from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity.engines.base import EngineIdentity, ProviderOperationError
from parquity.matrix import run_matrix
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.profiles import WriterProfileIdentity
from parquity.profiles.contracts import (
    CONTRACT_VIOLATION,
    ArtifactContractObservation,
    WriterProfileContractViolation,
    verify_writer_profile_artifact,
)
from parquity.verdicts import Verdict

Write = Callable[[pa.Table, Path], None]
Read = Callable[[Path], pa.Table]


class _WriteTable(Protocol):
    def __call__(self, table: pa.Table, path: Path, **options: object) -> None: ...


class _ParquetModule(Protocol):
    write_table: _WriteTable


_PARQUET = cast(_ParquetModule, cast(object, pq))


@dataclass(frozen=True, slots=True)
class _Writer:
    identity: EngineIdentity
    write_call: Write

    def write(self, table: pa.Table, path: Path) -> None:
        self.write_call(table, path)


@dataclass(frozen=True, slots=True)
class _Reader:
    identity: EngineIdentity
    read_call: Read

    def read(self, path: Path) -> pa.Table:
        return self.read_call(path)


def test_asymmetric_matrix_accepts_one_shared_identity_in_each_direction(
    tmp_path: Path,
) -> None:
    stored: dict[Path, pa.Table] = {}

    def write(table: pa.Table, path: Path) -> None:
        stored[path] = table

    def read(path: Path) -> pa.Table:
        return stored[path]

    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))
    writer = _Writer(EngineIdentity("shared", "1"), write)
    readers = (
        _Reader(EngineIdentity("shared", "1"), read),
        _Reader(EngineIdentity("reader-only", "2"), read),
        _Reader(EngineIdentity("another-reader", "3"), read),
    )

    run = run_matrix(case, tmp_path / "asymmetric", (writer,), readers)

    assert len(run.results) == 3
    assert [result.reader for result in run.results] == [
        "shared",
        "reader-only",
        "another-reader",
    ]
    assert all(result.verdict is Verdict.PASS for result in run.results)


def test_writer_failure_is_one_owned_result_while_success_keeps_one_result_per_reader(
    tmp_path: Path,
) -> None:
    stored: dict[Path, pa.Table] = {}

    def failing_write(table: pa.Table, path: Path) -> None:
        del table, path
        raise ProviderOperationError("broken", "write", OSError("controlled writer failure"))

    def successful_write(table: pa.Table, path: Path) -> None:
        stored[path] = table

    def read(path: Path) -> pa.Table:
        return stored[path]

    writers = (
        _Writer(EngineIdentity("broken", "1"), failing_write),
        _Writer(EngineIdentity("stable", "2"), successful_write),
    )
    readers = (
        _Reader(EngineIdentity("first", "3"), read),
        _Reader(EngineIdentity("second", "4"), read),
    )
    case = Case(
        (
            Field("flag", TypeSpec(Kind.BOOL)),
            Field("small", TypeSpec(Kind.INT32)),
            Field("large", TypeSpec(Kind.INT64)),
            Field("label", TypeSpec(Kind.STRING)),
            Field("payload", TypeSpec(Kind.BINARY)),
            Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32))),
            Field("fixed", TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=2)),
            Field(
                "record",
                TypeSpec(Kind.STRUCT, fields=(Field("note", TypeSpec(Kind.STRING)),)),
            ),
        ),
        ((True, 1, 2**40, "value", b"bytes", [1, None], [True, False], {"note": None}),),
    )

    run = run_matrix(case, tmp_path / "matrix", writers, readers)

    broken = tuple(result for result in run.results if result.writer == "broken")
    stable = tuple(result for result in run.results if result.writer == "stable")
    assert len(run.results) == 3
    assert len(broken) == 1
    assert broken[0].verdict is Verdict.WRITE_ERROR
    assert broken[0].reader == "*"
    assert broken[0].reader_version == "*"
    assert broken[0].diagnostic_kind == "OSError"
    fingerprint = broken[0].fingerprint
    assert fingerprint is not None
    assert fingerprint.to_data()["reader"] == "*"
    assert [(result.reader, result.verdict) for result in stable] == [
        ("first", Verdict.PASS),
        ("second", Verdict.PASS),
    ]
    assert all(result.fingerprint is None for result in stable)
    assert run.file_for("broken") is None
    assert run.file_for("stable") == tmp_path / "matrix" / "stable.parquet"


def test_reader_failure_is_scoped_to_each_affected_cell(tmp_path: Path) -> None:
    stored: dict[Path, pa.Table] = {}

    def write(table: pa.Table, path: Path) -> None:
        stored[path] = table

    def stable_read(path: Path) -> pa.Table:
        return stored[path]

    def failing_read(path: Path) -> pa.Table:
        del path
        raise ProviderOperationError("unreadable", "read", OSError("controlled reader failure"))

    writers = (
        _Writer(EngineIdentity("first", "1"), write),
        _Writer(EngineIdentity("second", "2"), write),
    )
    readers = (
        _Reader(EngineIdentity("stable", "3"), stable_read),
        _Reader(EngineIdentity("unreadable", "4"), failing_read),
    )
    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))

    run = run_matrix(case, tmp_path / "reader-matrix", writers, readers)

    unreadable = tuple(result for result in run.results if result.reader == "unreadable")
    assert len(run.results) == 4
    assert len(unreadable) == 2
    assert all(result.verdict is Verdict.READ_ERROR for result in unreadable)
    assert all(result.reader_version == "4" for result in unreadable)
    assert {result.diagnostic_kind for result in unreadable} == {"OSError"}


def test_comparison_diagnostic_kind_is_the_typed_verdict(tmp_path: Path) -> None:
    def write(table: pa.Table, path: Path) -> None:
        del table
        path.write_bytes(b"written")

    def read(path: Path) -> pa.Table:
        del path
        return pa.table({"flag": [False]})

    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))
    writer = _Writer(EngineIdentity("writer", "1"), write)
    reader = _Reader(EngineIdentity("reader", "2"), read)

    result = run_matrix(case, tmp_path / "comparison", (writer,), (reader,)).results[0]

    assert result.verdict is Verdict.VALUE_MISMATCH
    assert result.diagnostic_kind == "VALUE_MISMATCH"
    assert result.fingerprint is not None
    assert result.fingerprint.diagnostic_kind == "VALUE_MISMATCH"


def test_unexpected_writer_runtime_error_propagates(tmp_path: Path) -> None:
    def failing_write(table: pa.Table, path: Path) -> None:
        del table, path
        raise RuntimeError("unexpected writer failure")

    def unused_read(path: Path) -> pa.Table:
        raise AssertionError(f"unexpected read from {path}")

    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))
    writer = _Writer(EngineIdentity("broken", "1"), failing_write)
    reader = _Reader(EngineIdentity("reader", "2"), unused_read)

    with pytest.raises(RuntimeError):
        run_matrix(case, tmp_path / "writer-runtime-error", (writer,), (reader,))


def test_unexpected_reader_runtime_error_propagates(tmp_path: Path) -> None:
    stored: dict[Path, pa.Table] = {}

    def write(table: pa.Table, path: Path) -> None:
        stored[path] = table

    def failing_read(path: Path) -> pa.Table:
        del path
        raise RuntimeError("unexpected reader failure")

    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))
    writer = _Writer(EngineIdentity("stable", "1"), write)
    reader = _Reader(EngineIdentity("broken", "2"), failing_read)

    with pytest.raises(RuntimeError):
        run_matrix(case, tmp_path / "reader-runtime-error", (writer,), (reader,))


def test_mismatched_provider_error_envelopes_propagate(tmp_path: Path) -> None:
    stored: dict[Path, pa.Table] = {}

    def mismatched_write(table: pa.Table, path: Path) -> None:
        del table, path
        raise ProviderOperationError("different", "write", OSError("wrong writer identity"))

    def write(table: pa.Table, path: Path) -> None:
        stored[path] = table

    def mismatched_read(path: Path) -> pa.Table:
        del path
        raise ProviderOperationError("reader", "write", OSError("wrong reader operation"))

    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ((True,),))
    reader = _Reader(EngineIdentity("reader", "2"), mismatched_read)

    with pytest.raises(ProviderOperationError):
        run_matrix(
            case,
            tmp_path / "mismatched-writer",
            (_Writer(EngineIdentity("writer", "1"), mismatched_write),),
            (reader,),
        )
    with pytest.raises(ProviderOperationError):
        run_matrix(
            case,
            tmp_path / "mismatched-reader",
            (_Writer(EngineIdentity("writer", "1"), write),),
            (reader,),
        )


def test_matrix_rejects_empty_and_duplicate_direction_sets(tmp_path: Path) -> None:
    def write(table: pa.Table, path: Path) -> None:
        del table, path

    def read(path: Path) -> pa.Table:
        raise AssertionError(f"unexpected read from {path}")

    writer = _Writer(EngineIdentity("same", "1"), write)
    reader = _Reader(EngineIdentity("same", "1"), read)
    case = Case((Field("flag", TypeSpec(Kind.BOOL)),), ())

    with pytest.raises(ValueError):
        run_matrix(case, tmp_path / "empty-writers", (), (reader,))
    with pytest.raises(ValueError):
        run_matrix(case, tmp_path / "empty-readers", (writer,), ())
    with pytest.raises(ValueError):
        run_matrix(case, tmp_path / "duplicate-writers", (writer, writer), (reader,))
    with pytest.raises(ValueError):
        run_matrix(case, tmp_path / "duplicate-readers", (writer,), (reader, reader))


def test_artifact_contract_verifier_marks_empty_rows_non_observable_and_rejects_bad_metadata(
    tmp_path: Path,
) -> None:
    table = pa.table({"value": [1, 2, 3, 4]})
    wrong_compression = tmp_path / "wrong-compression.parquet"
    wrong_groups = tmp_path / "wrong-groups.parquet"
    present_min_max = tmp_path / "present-min-max.parquet"
    empty = tmp_path / "empty.parquet"
    _PARQUET.write_table(table, wrong_compression)
    _PARQUET.write_table(table, wrong_groups, row_group_size=3)
    _PARQUET.write_table(table, present_min_max, write_statistics=True)
    _PARQUET.write_table(
        pa.table({"value": pa.array([], type=pa.int32())}), empty, row_group_size=2
    )

    invalid = (
        (
            wrong_compression,
            WriterProfileIdentity("compression-gzip", {"compression": "gzip"}),
        ),
        (wrong_groups, WriterProfileIdentity("row-group-2", {"row_group_size": 2})),
        (
            present_min_max,
            WriterProfileIdentity("min-max-statistics-off", {"write_statistics": False}),
        ),
        (tmp_path / "missing.parquet", WriterProfileIdentity("compression-gzip", {"x": 1})),
    )
    for path, profile in invalid:
        with pytest.raises(WriterProfileContractViolation) as captured:
            verify_writer_profile_artifact(path, profile, 4)
        assert captured.value.kind == CONTRACT_VIOLATION

    valid = (
        ("compression-gzip", {"compression": "gzip"}),
        ("compression-brotli", {"compression": "brotli"}),
        ("row-group-2", {"row_group_size": 2}),
        ("min-max-statistics-off", {"write_statistics": False}),
    )
    for name, options in valid:
        path = tmp_path / f"good-{name}.parquet"
        _PARQUET.write_table(table, path, **options)
        assert (
            verify_writer_profile_artifact(path, WriterProfileIdentity(name, options), 4)
            is ArtifactContractObservation.VERIFIED
        )
    empty_profiles = (
        WriterProfileIdentity("compression-gzip", {"compression": "gzip"}),
        WriterProfileIdentity("row-group-2", {"row_group_size": 2}),
        WriterProfileIdentity("min-max-statistics-off", {"write_statistics": False}),
    )
    for profile in empty_profiles:
        assert (
            verify_writer_profile_artifact(empty, profile, 0)
            is ArtifactContractObservation.NOT_OBSERVABLE_EMPTY
        )
    with pytest.raises(WriterProfileContractViolation):
        verify_writer_profile_artifact(
            tmp_path / "good-compression-gzip.parquet", empty_profiles[0], 0
        )
