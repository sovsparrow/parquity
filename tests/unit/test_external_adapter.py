from __future__ import annotations

from pathlib import Path

import pyarrow as pa
import pytest

from parquity.engines import resolve_engine
from parquity.engines.base import EngineReader, EngineWriter, ProviderOperationError
from parquity.engines.external.protocol import (
    CRASH_KIND,
    ExternalEngineProtocolError,
    ExternalEngineTimeout,
)
from parquity.profiles import WriterProfileIdentity
from parquity.profiles.contracts import ProfiledEngineWriter
from tests.support import external_engine as bridge

TABLE = pa.table({"value": pa.array([1, 2, 3], pa.int32()), "label": ["a", None, "c"]})


def _writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EngineWriter:
    bridge.configure(monkeypatch, tmp_path)
    writer = resolve_engine(bridge.NAME).writer
    return writer or pytest.fail("configured bridge resolved no writer")


def _reader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EngineReader:
    bridge.configure(monkeypatch, tmp_path)
    reader = resolve_engine(bridge.NAME).reader
    return reader or pytest.fail("configured bridge resolved no reader")


def test_a_table_survives_the_round_trip_through_the_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The controlled bridge copies its input to its output, so what returns is exactly what the
    # adapter serialized: this pins the Arrow IPC transport, not a Parquet implementation.
    bridge.configure(monkeypatch, tmp_path)
    resolution = resolve_engine(bridge.NAME)
    writer, reader = resolution.writer, resolution.reader
    assert writer is not None and reader is not None

    artifact = tmp_path / "artifact.parquet"
    writer.write(TABLE, artifact)
    observed = reader.read(artifact)

    assert observed.equals(TABLE)
    assert observed.schema == TABLE.schema
    assert writer.identity.version == "9.9.9"


def test_an_empty_table_keeps_its_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bridge.configure(monkeypatch, tmp_path)
    resolution = resolve_engine(bridge.NAME)
    writer, reader = resolution.writer, resolution.reader
    assert writer is not None and reader is not None
    empty = TABLE.schema.empty_table()

    artifact = tmp_path / "empty.parquet"
    writer.write(empty, artifact)
    observed = reader.read(artifact)

    assert observed.num_rows == 0
    assert observed.schema == TABLE.schema


def test_a_reported_provider_failure_becomes_evidence_under_its_own_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exit 1 means the implementation tried and failed, which is the observation Parquity exists to
    # record. The kind it reports is what groups the finding, so it has to survive.
    writer = _writer(tmp_path, monkeypatch)
    bridge.fault(monkeypatch, "provider")

    with pytest.raises(ProviderOperationError) as caught:
        writer.write(TABLE, tmp_path / "artifact.parquet")

    assert caught.value.engine == bridge.NAME
    assert caught.value.operation == "write"
    assert caught.value.provider_type == "ControlledProviderError"
    assert "controlled provider failure" in caught.value.detail


def test_a_rejected_request_stops_the_run_rather_than_becoming_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exit 2 means the bridge did not understand what Parquity asked for. Recording that as a
    # finding would file a defect against the implementation for an integration mistake.
    writer = _writer(tmp_path, monkeypatch)
    bridge.fault(monkeypatch, "reject")

    with pytest.raises(ExternalEngineProtocolError, match="rejected the write request"):
        writer.write(TABLE, tmp_path / "artifact.parquet")


@pytest.mark.parametrize(
    ("injected", "message"),
    (
        ("garbage", "not a JSON object"),
        ("silent", "without writing a Parquet file"),
    ),
)
def test_a_broken_contract_stops_the_run(
    injected: str, message: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer = _writer(tmp_path, monkeypatch)
    bridge.fault(monkeypatch, injected)

    with pytest.raises(ExternalEngineProtocolError, match=message):
        writer.write(TABLE, tmp_path / "artifact.parquet")


@pytest.mark.parametrize("injected", ("crash", "malformed-failure"))
def test_a_crash_is_evidence_because_the_implementation_still_failed(
    injected: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An exit without a usable response is the implementation dying on this input, which is a real
    # observation -- unlike a rejected request, which is Parquity's mistake.
    writer = _writer(tmp_path, monkeypatch)
    bridge.fault(monkeypatch, injected)

    with pytest.raises(ProviderOperationError) as caught:
        writer.write(TABLE, tmp_path / "artifact.parquet")

    assert caught.value.provider_type == CRASH_KIND


def test_an_operation_that_exceeds_its_timeout_is_not_a_provider_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exit 1 means the implementation answered and said it failed, which is worth recording. A
    # timeout means it never answered, so there is nothing to record -- and treating the two alike
    # would let a slow machine manufacture findings against an engine that did nothing wrong.
    bridge.configure(monkeypatch, tmp_path, bridge.declaration(timeout_seconds=1))
    writer = resolve_engine(bridge.NAME).writer
    assert writer is not None
    bridge.fault(monkeypatch, "slow")

    with pytest.raises(ExternalEngineTimeout) as caught:
        writer.write(TABLE, tmp_path / "artifact.parquet")

    assert not isinstance(caught.value, ProviderOperationError)
    assert "within 1 seconds" in str(caught.value)


def test_a_reading_bridge_that_cannot_be_read_from_stops_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = _reader(tmp_path, monkeypatch)
    artifact = tmp_path / "artifact.parquet"
    artifact.write_bytes(b"PAR1 not arrow ipc PAR1")

    with pytest.raises(ExternalEngineProtocolError, match="could not be read"):
        reader.read(artifact)


def test_declared_writer_profiles_carry_the_options_the_bridge_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer = _writer(tmp_path, monkeypatch)
    assert isinstance(writer, ProfiledEngineWriter)

    supported = writer.writer_profile("row-group-2")
    assert supported is not None
    assert supported == WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    assert writer.writer_profile("min-max-statistics-off") is None

    artifact = tmp_path / "profiled.parquet"
    writer.write_profiled(TABLE, artifact, supported)
    assert artifact.with_suffix(".profile").read_text(encoding="utf-8") == "row-group-2"


def test_a_profile_the_bridge_did_not_declare_is_refused_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer = _writer(tmp_path, monkeypatch)
    assert isinstance(writer, ProfiledEngineWriter)
    foreign = WriterProfileIdentity("row-group-2", {"row_group_size": 99})

    with pytest.raises(ValueError, match="does not match the bridge declaration"):
        writer.write_profiled(TABLE, tmp_path / "foreign.parquet", foreign)


@pytest.mark.parametrize(
    ("declared", "reader", "writer"),
    (("read", True, False), ("write", False, True), ("read,write", True, True)),
)
def test_only_the_declared_directions_resolve(
    declared: str,
    reader: bool,
    writer: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge.directions(monkeypatch, declared)
    bridge.configure(monkeypatch, tmp_path)
    resolution = resolve_engine(bridge.NAME)

    assert (resolution.reader is not None) is reader
    assert (resolution.writer is not None) is writer
    assert (resolution.availability.reader, resolution.availability.writer) == (reader, writer)
