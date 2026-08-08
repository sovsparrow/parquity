import copy
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock, PropertyMock

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity import writer_profile_contracts as contracts
from parquity.engines.base import EngineIdentity, EngineWriter, ProviderOperationError
from parquity.engines.duckdb import DuckDBEngine
from parquity.engines.fastparquet import FastparquetEngine
from parquity.engines.polars import PolarsEngine
from parquity.engines.pyarrow import PyArrowEngine
from parquity.findings.upstream_script import render_upstream_repro
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict
from parquity.writer_profiles import (
    PROFILE_REGISTRY,
    CapabilityStatus,
    WriterExecutionIdentity,
    WriterProfileCapability,
    WriterProfileError,
    WriterProfileIdentity,
    WriterProfilePlan,
    build_writer_profile_plan,
    parse_requested_profiles,
)

Profile = WriterProfileIdentity


def _writers() -> tuple[EngineWriter, ...]:
    return (
        PyArrowEngine(EngineIdentity("pyarrow", "1")),
        DuckDBEngine(EngineIdentity("duckdb", "2")),
        PolarsEngine(EngineIdentity("polars", "3")),
        FastparquetEngine(EngineIdentity("fastparquet", "4")),
    )


def _pass(writer: EngineVersion, reader: EngineVersion, profile: Profile | None) -> CellResult:
    engines = (writer.name, writer.version, reader.name, reader.version)
    return CellResult(*engines, "compare", Verdict.PASS, "$", "match", writer_profile=profile)


def test_registry_parsing_is_closed_set_deduplicated_and_canonical() -> None:
    assert parse_requested_profiles("min-max-statistics-off,row-group-2,compression-brotli") == (
        "compression-brotli",
        "row-group-2",
        "min-max-statistics-off",
    )
    assert PROFILE_REGISTRY == (
        "compression-gzip",
        "compression-brotli",
        "row-group-2",
        "min-max-statistics-off",
    )
    for invalid in ("", "default", "row-group-2,", "row-group-2,row-group-2", "unknown"):
        with pytest.raises(ValueError):
            parse_requested_profiles(invalid)
    assert parse_requested_profiles(None) is None
    assert parse_requested_profiles(["row-group-2", "compression-brotli"]) == (
        "compression-brotli",
        "row-group-2",
    )
    with pytest.raises(WriterProfileError, match="exceeds four"):
        parse_requested_profiles([*PROFILE_REGISTRY, "unknown"])


def test_complete_capability_grid_has_exact_support_and_effective_options() -> None:
    plan = build_writer_profile_plan(PROFILE_REGISTRY, _writers()) or pytest.fail("plan missing")
    supported = {
        ("pyarrow", "compression-gzip"): {"compression": "gzip"},
        ("pyarrow", "compression-brotli"): {"compression": "brotli"},
        ("pyarrow", "row-group-2"): {"row_group_size": 2},
        ("pyarrow", "min-max-statistics-off"): {"write_statistics": False},
        ("polars", "compression-gzip"): {"compression": "gzip"},
        ("polars", "compression-brotli"): {"compression": "brotli"},
        ("polars", "row-group-2"): {"row_group_size": 2},
        ("polars", "min-max-statistics-off"): {"statistics": False},
        ("fastparquet", "compression-gzip"): {"compression": "GZIP"},
        ("fastparquet", "compression-brotli"): {"compression": "BROTLI"},
        ("fastparquet", "row-group-2"): {"row_group_offsets": 2},
        ("fastparquet", "min-max-statistics-off"): {"stats": False},
        ("duckdb", "compression-gzip"): {"compression": "gzip"},
        ("duckdb", "compression-brotli"): {"compression": "brotli"},
    }
    for item in plan.capabilities:
        endpoint = (item.writer.name, item.profile_name)
        evidence = (item.status.value, item.effective_options, item.reason_code)
        options = supported.get(endpoint)
        if options is None:
            assert evidence == ("UNSUPPORTED", None, "OPTION_UNAVAILABLE")
        else:
            assert evidence == ("SUPPORTED", options, None)


def test_profile_plan_and_matrix_bind_complete_execution_identity(tmp_path: Path) -> None:
    adapters = _writers()[:2]
    plan = build_writer_profile_plan(("row-group-2",), adapters) or pytest.fail("plan missing")
    writers = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    reader = EngineVersion("pyarrow", "1")
    profile = WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    executions = plan.executions(writers)
    results = tuple(
        _pass(execution.writer, reader, execution.writer_profile) for execution in executions
    )
    files = tuple(
        (execution, tmp_path / f"{index}.parquet") for index, execution in enumerate(executions)
    )
    run = MatrixRun("0" * 64, results, files, writers, (reader,), plan)
    assert executions == (
        WriterExecutionIdentity(writers[0]),
        WriterExecutionIdentity(writers[0], profile),
        WriterExecutionIdentity(writers[1]),
    )
    assert run.file_for("pyarrow", profile) == tmp_path / "1.parquet"
    assert run.file_for("duckdb", profile) is None
    assert all(result.writer_profile is None for result in (results[0], results[2]))


def test_recorded_capabilities_decode_without_live_translation_equivalence() -> None:
    plan = build_writer_profile_plan(("row-group-2",), _writers()) or pytest.fail("plan missing")
    mutated = copy.deepcopy(plan.to_data())
    capabilities = cast(list[dict[str, object]], mutated["capabilities"])
    capabilities[0]["effective_options"] = {"historical_row_group_size": 3}
    historical = WriterProfilePlan.from_data(mutated)
    assert historical.capabilities[0].effective_options == {"historical_row_group_size": 3}
    assert not historical.replay_equivalent(plan)
    partial = copy.deepcopy(plan.to_data())
    cast(list[object], partial["capabilities"]).pop()
    parsed = WriterProfilePlan.from_data(partial)
    with pytest.raises(ValueError):
        parsed.validate_writers(plan.writers)


def test_profile_identity_and_capability_unions_reject_foreign_shapes() -> None:
    foreign_value = cast(tuple[tuple[str, bool | int | str], ...], (("x", object()),))
    invalid_identities = (
        lambda: WriterProfileIdentity("unknown", {"x": 1}),
        lambda: WriterProfileIdentity("row-group-2", {}),
        lambda: WriterProfileIdentity("row-group-2", {"": 2}),
        lambda: WriterProfileIdentity("row-group-2", foreign_value),
        lambda: WriterProfileIdentity("row-group-2", (("x", 1), ("x", 2))),
    )
    for construct in invalid_identities:
        with pytest.raises(ValueError):
            construct()
    writer = EngineVersion("pyarrow", "1")
    supported, unsupported = CapabilityStatus.SUPPORTED, CapabilityStatus.UNSUPPORTED
    for boolean_value, integer_value in ((False, 0), (True, 1)):
        boolean = WriterProfileIdentity("min-max-statistics-off", {"statistics": boolean_value})
        integer = WriterProfileIdentity("min-max-statistics-off", {"statistics": integer_value})
        same_boolean = copy.deepcopy(boolean)
        assert boolean == same_boolean and hash(boolean) == hash(same_boolean)
        assert boolean != integer and len({boolean, integer}) == 2
        boolean_capability = WriterProfileCapability(writer, boolean.name, supported, boolean)
        integer_capability = WriterProfileCapability(writer, integer.name, supported, integer)
        boolean_plan = WriterProfilePlan((boolean.name,), (boolean_capability,))
        integer_plan = WriterProfilePlan((integer.name,), (integer_capability,))
        assert boolean_plan != integer_plan and not boolean_plan.replay_equivalent(integer_plan)
    correct = WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    foreign = WriterProfileIdentity("row-group-2", {"row_group_size": 3})
    wrong_name = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    assert WriterProfileCapability(writer, "row-group-2", supported, foreign).effective_options == {
        "row_group_size": 3
    }
    unsupported_recorded = WriterProfileCapability(
        writer, "row-group-2", unsupported, reason_code="OPTION_UNAVAILABLE"
    )
    assert unsupported_recorded.status is CapabilityStatus.UNSUPPORTED
    bad_status = cast(CapabilityStatus, "BAD")
    invalid_capabilities = (
        lambda: WriterProfileCapability(writer, "row-group-2", bad_status),
        lambda: WriterProfileCapability(writer, "unknown", supported, correct),
        lambda: WriterProfileCapability(writer, "row-group-2", supported),
        lambda: WriterProfileCapability(writer, "row-group-2", supported, wrong_name),
        lambda: WriterProfileCapability(
            writer, "row-group-2", unsupported, correct, "OPTION_UNAVAILABLE"
        ),
        lambda: WriterProfileCapability(writer, "row-group-2", unsupported, reason_code="OTHER"),
    )
    for construct in invalid_capabilities:
        with pytest.raises(ValueError):
            construct()


def test_profile_plan_decoder_rejects_noncanonical_nested_shapes() -> None:
    plan = build_writer_profile_plan(("row-group-2",), _writers()[:2])
    assert plan is not None
    capability = cast(list[dict[str, object]], plan.to_data()["capabilities"])[0]
    malformed: tuple[dict[str, object], ...] = (
        {"requested": "row-group-2", "capabilities": []},
        {"requested": [1], "capabilities": []},
        {"requested": ["row-group-2"], "capabilities": [1]},
        {"requested": ["row-group-2"], "capabilities": []},
        {**plan.to_data(), "extra": True},
        {"requested": ["row-group-2", "row-group-2"], "capabilities": []},
        {"requested": ["row-group-2", "compression-gzip"], "capabilities": []},
        {"requested": ["row-group-2"], "capabilities": [{**capability, "status": "OTHER"}]},
        {"requested": ["row-group-2"], "capabilities": [{**capability, "writer": []}]},
        {
            "requested": ["row-group-2"],
            "capabilities": [{**capability, "writer": {"name": "pyarrow", "version": "1", "x": 1}}],
        },
        {"requested": ["row-group-2"], "capabilities": [{**capability, "effective_options": []}]},
        {
            "requested": ["row-group-2"],
            "capabilities": [{**capability, "effective_options": {"row_group_size": []}}],
        },
        {"requested": ["row-group-2"], "capabilities": [{**capability, "profile": ""}]},
    )
    for data in malformed:
        with pytest.raises(ValueError):
            WriterProfilePlan.from_data(data)
    with pytest.raises(ValueError):
        WriterProfilePlan.from_data(cast(dict[str, object], {1: "not-a-string-key"}))


def test_plan_builder_rejects_default_only_writers_and_universal_unavailability() -> None:
    assert build_writer_profile_plan(None, _writers()) is None
    write_default = Mock()
    default_only = cast(
        EngineWriter,
        SimpleNamespace(identity=EngineIdentity("default-only", "1"), write=write_default),
    )
    for writers in ((default_only,), (_writers()[1],)):
        with pytest.raises(WriterProfileError, match="no supporting endpoint"):
            build_writer_profile_plan(("row-group-2",), writers)
    malformed = Mock(side_effect=ValueError("adapter translation is malformed"))
    invalid_adapter = cast(
        EngineWriter,
        SimpleNamespace(
            identity=EngineIdentity("invalid", "1"),
            write=write_default,
            writer_profile=malformed,
            write_profiled=write_default,
        ),
    )
    with pytest.raises(ValueError, match="adapter translation"):
        build_writer_profile_plan(("row-group-2",), (invalid_adapter,))


def test_profiled_adapter_write_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    panic = pl.exceptions.PanicException("controlled panic")
    frame = SimpleNamespace(write_parquet=Mock(side_effect=panic))
    monkeypatch.setattr(pq, "write_table", Mock(side_effect=TypeError("option rejected")))
    monkeypatch.setattr(pl, "from_arrow", Mock(return_value=frame))
    adapters = (
        PyArrowEngine(EngineIdentity("pyarrow", "controlled")),
        PolarsEngine(EngineIdentity("polars", "controlled")),
    )
    profile = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    for adapter, provider_type in zip(adapters, ("TypeError", "PanicException"), strict=True):
        with pytest.raises(ProviderOperationError) as caught:
            adapter.write_profiled(pa.table({"value": [1]}), tmp_path / "rejected", profile)
        assert caught.value.engine == adapter.identity.name
        assert caught.value.operation == "write" and caught.value.provider_type == provider_type
        rejected = build_writer_profile_plan(("compression-gzip",), (adapter,))
        assert rejected is not None
        with pytest.raises(WriterProfileError) as unavailable:
            contracts.admit_writer_profile_plan(rejected, (adapter,))
        assert unavailable.value.kind == "WRITER_PROFILE_UNSUPPORTED"
        foreign = WriterProfileIdentity("compression-gzip", {"compression": "foreign"})
        with pytest.raises(ValueError, match="translation"):
            adapter.write_profiled(pa.table({"value": [1]}), tmp_path / "foreign", foreign)
    monkeypatch.setattr(pl, "from_arrow", Mock(side_effect=panic))
    with pytest.raises(ProviderOperationError):
        adapters[1].write_profiled(pa.table({"value": [1]}), tmp_path / "conversion", profile)
    monkeypatch.setattr(pl, "from_arrow", Mock(side_effect=KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        adapters[1].write(pa.table({"value": [1]}), tmp_path / "interrupt")


def test_artifact_verifier_distinguishes_invalid_artifacts_from_internal_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    malformed = tmp_path / "malformed.parquet"
    malformed.write_text("not a parquet artifact")
    for path in (tmp_path / "missing.parquet", malformed):
        with pytest.raises(contracts.WriterProfileContractViolation):
            contracts.verify_writer_profile_artifact(path, profile, 4)
    for failure in (OSError("resource failure"), TypeError("type failure")):
        monkeypatch.setattr(pq, "ParquetFile", Mock(side_effect=failure))
        with pytest.raises(type(failure)) as propagated:
            contracts.verify_writer_profile_artifact(malformed, profile, 4)
        assert propagated.value is failure
    metadata_failure = AttributeError("metadata access failure")
    artifact = type("Artifact", (), {"metadata": PropertyMock(side_effect=metadata_failure)})()
    monkeypatch.setattr(pq, "ParquetFile", Mock(return_value=artifact))
    with pytest.raises(AttributeError) as propagated:
        contracts.verify_writer_profile_artifact(malformed, profile, 4)
    assert propagated.value is metadata_failure


def test_upstream_reproduction_uses_every_recorded_provider_translation() -> None:
    plan = build_writer_profile_plan(PROFILE_REGISTRY, _writers()) or pytest.fail("plan missing")
    case = Case((Field("value", TypeSpec(Kind.INT32), False),), ((1,),))
    calls = {
        "pyarrow": "pq.write_table(TABLE, path, **options)",
        "duckdb": "connection.from_arrow(TABLE).write_parquet(str(path), **options)",
        "polars": "pl.from_arrow(TABLE).write_parquet(path, **options)",
        "fastparquet": "fastparquet.write(str(path), frame, write_index=False, **options)",
    }
    supported = tuple(i for i in plan.capabilities if i.status is CapabilityStatus.SUPPORTED)
    assert len(supported) == 14
    for capability in supported:
        profile = capability.profile_identity
        assert profile is not None
        result = _pass(capability.writer, EngineVersion("pyarrow", "1"), profile)
        script = render_upstream_repro(case, result).decode()
        assert f"options = {profile.effective_options!r}" in script
        assert calls[result.writer] in script
        assert script.count("options = ") == script.count("**options") == 1
        assert all(f"{key}=" not in script for key in profile.effective_options)
        compile(script, "upstream_repro.py", "exec")


def test_admission_controls_are_fixed_fresh_and_cleaned(monkeypatch: pytest.MonkeyPatch) -> None:
    assert contracts.admit_writer_profile_plan(None, ()) is None
    writer = PyArrowEngine(EngineIdentity("pyarrow", "1"))
    declared = build_writer_profile_plan(PROFILE_REGISTRY, (writer,)) or pytest.fail("plan missing")
    paths: list[Path] = []
    original = PyArrowEngine.write_profiled
    fields = (pa.field("value", pa.int32(), False), pa.field("label", pa.string(), False))
    control_schema = pa.schema(fields)

    def tracked(
        self: PyArrowEngine, table: pa.Table, path: Path, item: WriterProfileIdentity
    ) -> None:
        assert table.to_pydict() == {"value": [1, 2, 3, 4], "label": ["a", "b", "c", "d"]}
        assert table.schema == control_schema
        paths.append(path)
        original(self, table, path, item)

    monkeypatch.setattr(PyArrowEngine, "write_profiled", tracked)
    assert contracts.admit_writer_profile_plan(declared, (writer,)) == declared
    assert len(paths) == len(set(paths)) == len(PROFILE_REGISTRY)
    assert all(not path.exists() for path in paths)
