from __future__ import annotations

import json
import runpy
from collections.abc import Callable
from decimal import Decimal
from importlib import import_module, metadata
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pyarrow as pa
import pytest

import parquity.cli as cli
from parquity.case.arrow import case_to_arrow
from parquity.comparison.table import compare_case
from parquity.engines import CORE_ENGINE_DESCRIPTORS, resolve_engine, resolve_engines
from parquity.engines.base import (
    EngineReader,
    EngineWriter,
    ProfiledEngineWriter,
    ProviderOperationError,
)
from parquity.engines.fastparquet import table_to_pandas
from parquity.findings.upstream_script import render_upstream_repro
from parquity.matrix import run_matrix
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, Verdict


def _scalar_case() -> Case:
    return Case(
        (
            Field("boolean_value", TypeSpec(Kind.BOOL)),
            Field("int32_value", TypeSpec(Kind.INT32)),
            Field("int64_value", TypeSpec(Kind.INT64)),
            Field("string_value", TypeSpec(Kind.STRING)),
            Field("binary_value", TypeSpec(Kind.BINARY)),
        ),
        (
            (True, 2**31 - 1, 2**63 - 1, "Parquity", b"\x00\xff"),
            (False, -(2**31), -(2**63), "", b""),
            (None, None, None, None, None),
        ),
    )


def _nullable_int32_case() -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32)),), ((1,), (None,)))


def _nested_list_case() -> Case:
    items = TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32))
    return Case((Field("items", items),), (([1, None],), (None,), ([],)))


def _temporal_boundary_case() -> Case:
    nested_item = TypeSpec(Kind.TIMESTAMP, unit="ms", timezone="UTC")
    nested = TypeSpec(
        Kind.STRUCT,
        fields=(Field("ticks", TypeSpec(Kind.LIST, item=nested_item)),),
    )
    return Case(
        (
            Field("day", TypeSpec(Kind.DATE32)),
            Field("tick_ms", TypeSpec(Kind.TIMESTAMP, unit="ms", timezone="UTC")),
            Field("tick_us", TypeSpec(Kind.TIMESTAMP, unit="us")),
            Field("tick_ns", TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC")),
            Field("nested", nested),
        ),
        (
            (-(2**31), -(10**15), -(10**18), -(2**63), {"ticks": [-(10**15)]}),
            (2**31 - 1, 10**15, 10**18, 2**63 - 1, {"ticks": [None, 10**15]}),
        ),
    )


def _fastparquet_cases() -> tuple[tuple[Case, tuple[str | None, ...]], ...]:
    nested = _nested_list_case()
    mapping = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.STRING),
        value=TypeSpec(Kind.INT32),
        value_nullable=False,
    )
    record = TypeSpec(
        Kind.STRUCT,
        fields=(Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)), False),),
    )
    extended = Case(
        (
            Field("f32", TypeSpec(Kind.FLOAT32), False),
            Field("f64", TypeSpec(Kind.FLOAT64), False),
            Field("amount", TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),
            Field("lookup", mapping, False),
            Field("record", record, False),
        ),
        ((1.5, -2.5, Decimal("1.20"), [["a", 1]], {"items": [1, None]}),),
    )
    return (
        (_nullable_int32_case(), ("Int32",)),
        (nested, (None,)),
        (extended, ("Float32", "Float64", None, None, None)),
        (_temporal_boundary_case(), (None, None, None, None, None)),
    )


def _comparison_target(writer: str) -> CellResult:
    identity = (writer, metadata.version(writer), "pyarrow", metadata.version("pyarrow"), "compare")
    return CellResult(*identity, Verdict.SCHEMA_MISMATCH, "$schema", "controlled target")


def _core_capabilities() -> tuple[tuple[EngineWriter, ...], tuple[EngineReader, ...]]:
    names = tuple(descriptor.name for descriptor in CORE_ENGINE_DESCRIPTORS)
    resolutions = resolve_engines(names)
    writers: list[EngineWriter] = []
    readers: list[EngineReader] = []
    for resolution in resolutions:
        assert resolution.availability.available
        assert resolution.writer is not None
        assert resolution.reader is not None
        writers.append(resolution.writer)
        readers.append(resolution.reader)
    return tuple(writers), tuple(readers)


def test_datafusion_reads_every_core_writer_without_a_writer_capability(tmp_path: Path) -> None:
    writers, _ = _core_capabilities()
    datafusion = resolve_engine("datafusion")
    assert datafusion.availability.available
    assert datafusion.reader is not None
    assert datafusion.writer is None
    run = run_matrix(
        _scalar_case(),
        tmp_path / "datafusion-reads-core",
        writers,
        (datafusion.reader,),
    )
    assert len(run.results) == 3
    assert {result.reader for result in run.results} == {"datafusion"}
    assert all(result.verdict is Verdict.PASS for result in run.results)


def test_datafusion_missing_file_is_an_owned_provider_read_failure(tmp_path: Path) -> None:
    datafusion = resolve_engine("datafusion")
    assert datafusion.availability.available
    assert datafusion.reader is not None
    with pytest.raises(ProviderOperationError) as captured:
        datafusion.reader.read(tmp_path / "does-not-exist.parquet")
    assert captured.value.engine == "datafusion"
    assert captured.value.operation == "read"


def test_datafusion_malformed_materialization_remains_internal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class MalformedContext:
        def read_parquet(self, path: str) -> object:
            del path
            return self

        def to_arrow_table(self) -> object:
            return object()

    adapter = import_module("parquity.engines.datafusion")
    monkeypatch.setattr(adapter, "_SESSION_CONTEXT", MalformedContext)
    datafusion = resolve_engine("datafusion")
    assert datafusion.reader is not None
    with pytest.raises(TypeError):
        datafusion.reader.read(tmp_path / "input.parquet")


def test_fastparquet_reads_every_core_writer(tmp_path: Path) -> None:
    writers, _ = _core_capabilities()
    fastparquet = resolve_engine("fastparquet")
    assert fastparquet.availability.available
    assert fastparquet.reader is not None
    run = run_matrix(
        _scalar_case(),
        tmp_path / "fastparquet-reads-core",
        writers,
        (fastparquet.reader,),
    )
    assert len(run.results) == 3
    assert {result.reader for result in run.results} == {"fastparquet"}
    assert all(result.verdict is Verdict.PASS for result in run.results)


def test_fastparquet_writer_preserves_nullable_scalars_for_all_core_and_self_readers(
    tmp_path: Path,
) -> None:
    _, core_readers = _core_capabilities()
    fastparquet = resolve_engine("fastparquet")
    assert fastparquet.availability.available
    assert fastparquet.writer is not None
    assert fastparquet.reader is not None
    run = run_matrix(
        _scalar_case(),
        tmp_path / "fastparquet-writes",
        (fastparquet.writer,),
        (*core_readers, fastparquet.reader),
    )
    assert len(run.results) == 4
    assert [result.reader for result in run.results] == [
        "pyarrow",
        "duckdb",
        "polars",
        "fastparquet",
    ]
    assert all(result.verdict is Verdict.PASS for result in run.results)


@pytest.mark.parametrize(("case", "pandas_dtypes"), _fastparquet_cases())
def test_fastparquet_direct_script_matches_adapter_schema_and_rows(
    case: Case,
    pandas_dtypes: tuple[str | None, ...],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    adapter = resolve_engine("fastparquet")
    pyarrow = resolve_engine("pyarrow")
    assert adapter.writer is not None and pyarrow.reader is not None
    table = case_to_arrow(case)
    from_pandas = cast(Callable[..., pa.Table], pa.Table.from_pandas)
    prepared = from_pandas(table_to_pandas(table), preserve_index=False)
    assert compare_case(case, prepared).passed
    names = tuple(field.name for field in case.fields)
    case_rows = [dict(zip(names, row, strict=True)) for row in case.rows]
    expected_rows = cast(object, json.loads(json.dumps(case_rows, default=repr)))
    completed = ["WRITE_COMPLETED", "READ_COMPLETED"]
    script = tmp_path / "upstream_repro.py"
    script.write_bytes(render_upstream_repro(case, _comparison_target("fastparquet")))
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(script), run_name="__main__")
    output = capsys.readouterr().out
    records = [cast(dict[str, object], json.loads(line)) for line in output.splitlines()]
    source = script.read_text(encoding="utf-8")
    temporal = 'record("observe", "ERROR"' in source
    for index, dtype in enumerate(pandas_dtypes):
        if dtype is None:
            marker = f"pd.Series(TABLE.column({index}), dtype=pd.ArrowDtype("
        else:
            marker = f"TABLE.column({index}).to_pylist(), dtype={dtype!r}"
        assert marker in source
    assert "TABLE.to_pandas()" not in source and "import parquity" not in source

    adapter_path = tmp_path / "adapter.parquet"
    try:
        adapter.writer.write(table, adapter_path)
    except ProviderOperationError as error:
        assert stopped.value.code == 1
        assert records[-1]["operation"] == "write"
        assert records[-1]["outcome"] == "ERROR"
        assert records[-1]["error_type"] == error.provider_type
        if temporal:
            control = _comparison_target("pyarrow")
            script.write_bytes(render_upstream_repro(case, control))
            with pytest.raises(SystemExit) as control_stopped:
                runpy.run_path(str(script), run_name="__main__")
            control_output = capsys.readouterr().out
            control_records = [
                cast(dict[str, object], json.loads(line)) for line in control_output.splitlines()
            ]
            assert control_stopped.value.code == 0
            assert [record["outcome"] for record in control_records] == completed
            assert pyarrow.writer is not None
            control_path = tmp_path / "control.parquet"
            pyarrow.writer.write(table, control_path)
            control_actual = pyarrow.reader.read(control_path)
            assert control_records[-1]["schema"] == str(control_actual.schema)
            assert control_records[-1]["rows"] == expected_rows
        return
    actual = pyarrow.reader.read(adapter_path)
    assert compare_case(case, actual).passed
    assert stopped.value.code == 0
    assert [record["outcome"] for record in records] == completed
    assert records[-1]["schema"] == str(actual.schema)
    assert records[-1]["rows"] == expected_rows


@pytest.mark.parametrize("case", (_nullable_int32_case(), _nested_list_case()))
def test_public_check_keeps_valid_fastparquet_cases_out_of_internal_error(
    case: Case,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case_path = tmp_path / "case.json"
    destination = tmp_path / "run"
    case_path.write_bytes(case.canonical_bytes())
    exit_code = cli.main(
        [
            "check",
            str(case_path),
            "--writers",
            "fastparquet",
            "--readers",
            "pyarrow",
            "--out",
            str(destination),
        ]
    )
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert exit_code in (0, 1) and exit_code != 3 and payload["status"] != "INTERNAL_ERROR"


def test_fastparquet_conversion_failures_are_owned_provider_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fastparquet = resolve_engine("fastparquet")
    assert fastparquet.writer is not None and fastparquet.reader is not None
    writer = cast(ProfiledEngineWriter, fastparquet.writer)
    foreign = pa.table({"unsupported": pa.array([1], type=pa.uint32())})
    profile = writer.writer_profile("compression-gzip") or pytest.fail("profile unavailable")
    operations = (
        lambda: writer.write(foreign, tmp_path / "unsupported.parquet"),
        lambda: writer.write_profiled(foreign, tmp_path / "profiled.parquet", profile),
        lambda: writer.write(
            case_to_arrow(_nullable_int32_case()), tmp_path / "missing" / "input.parquet"
        ),
    )
    for operation in operations:
        with pytest.raises(ProviderOperationError) as captured:
            operation()
        assert (captured.value.engine, captured.value.operation) == ("fastparquet", "write")
        assert 0 < len(captured.value.detail) <= 500
    valid = tmp_path / "valid.parquet"
    writer.write(case_to_arrow(_nullable_int32_case()), valid)
    adapter = import_module("parquity.engines.fastparquet")
    failure = ValueError("controlled materialization failure")
    factory = type("FailingArrowTable", (), {"from_pandas": Mock(side_effect=failure)})()
    monkeypatch.setattr(adapter, "_ARROW_TABLE", factory)
    with pytest.raises(ProviderOperationError) as read:
        fastparquet.reader.read(valid)
    error = read.value
    assert (error.engine, error.operation, error.__cause__) == ("fastparquet", "read", failure)
