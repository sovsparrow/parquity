from __future__ import annotations

import math
from decimal import Decimal
from typing import cast

from ..case.arrow import type_to_arrow
from ..engines.fastparquet import pandas_dtype_plan
from ..model import Case, Field, Kind, TypeSpec
from ..verdicts import CellResult


def render_upstream_repro(case: Case, result: CellResult) -> bytes:
    imports = _provider_imports(result.writer, result.reader)
    writer = _indent([*_writer_lines(result, case), "byte_count = path.stat().st_size"], 12)
    temporal = contains(case, Kind.DATE32) or contains(case, Kind.TIMESTAMP)
    providers = [("writer", result.writer)]
    if result.reader != "*":
        providers.append(("reader", result.reader))
    lines = [
        "import json",
        "import tempfile",
        *(["from decimal import Decimal"] if contains(case, Kind.DECIMAL128) else []),
        "from importlib import metadata",
        "from pathlib import Path",
        "",
        "import pyarrow as pa",
        *imports,
        "",
        f"CASE_ID = {case.case_id!r}",
        f"EXPECTED_CASE = {case.to_data()!r}",
        f"TARGET = {result.to_data()!r}",
        f"PROVIDERS = {providers!r}",
        (
            'VERSIONS = [{"role": role, "engine": engine, '
            '"version": metadata.version(engine)} for role, engine in PROVIDERS]'
        ),
        f"SCHEMA = pa.schema([{', '.join(field_expression(field) for field in case.fields)}])",
        f"ROWS = {rows_source(case)}",
        *table_lines(case),
        "",
        "def record(operation: str, outcome: str, **evidence: object) -> None:",
        "    payload = {",
        '        "case_id": CASE_ID,',
        '        "expected_case": EXPECTED_CASE,',
        '        "target": TARGET,',
        '        "provider_versions": VERSIONS,',
        '        "operation": operation,',
        '        "outcome": outcome,',
        "    }",
        "    payload.update(evidence)",
        "    print(json.dumps(payload, default=repr, ensure_ascii=False, sort_keys=True))",
        "",
        "def main() -> int:",
        '    with tempfile.TemporaryDirectory(prefix="parquity-upstream-") as raw_directory:',
        '        path = Path(raw_directory) / "input.parquet"',
        "        try:",
        *writer,
        "        except Exception as error:",
        (
            '            record("write", "ERROR", '
            "error_type=type(error).__name__, detail=str(error))"
        ),
        "            return 1",
        '        record("write", "WRITE_COMPLETED", byte_count=byte_count)',
        '        if TARGET["operation"] == "write":',
        "            return 0",
        *_read_block(result, temporal),
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(main())",
    ]
    return ("\n".join(lines) + "\n").encode()


def _read_block(result: CellResult, temporal: bool) -> list[str]:
    if result.operation == "write":
        return []
    reader = _indent(_reader_lines(result.reader), 12)
    provider_read = [
        "        try:",
        *reader,
        "        except Exception as error:",
        ('            record("read", "ERROR", error_type=type(error).__name__, detail=str(error))'),
        "            return 1",
    ]
    if not temporal:
        return [
            *provider_read,
            (
                '        record("read", "READ_COMPLETED", '
                "schema=str(actual.schema), rows=actual.to_pylist())"
            ),
            "        return 0",
        ]
    return [
        *provider_read,
        "        try:",
        "            observed_rows = actual.cast(STORAGE_SCHEMA).to_pylist()",
        "        except Exception as error:",
        (
            '            record("observe", "ERROR", '
            "error_type=type(error).__name__, detail=str(error))"
        ),
        "            return 1",
        ('        record("read", "READ_COMPLETED", schema=str(actual.schema), rows=observed_rows)'),
        "        return 0",
    ]


def _provider_imports(writer: str, reader: str) -> list[str]:
    imports = (
        ("pyarrow", "import pyarrow.parquet as pq"),
        ("duckdb", "import duckdb"),
        ("polars", "import polars as pl"),
        ("datafusion", "from datafusion import SessionContext"),
        ("fastparquet", "import fastparquet"),
    )
    selected = {writer, reader}
    selected_imports = [source for engine, source in imports if engine in selected]
    if writer == "fastparquet":
        selected_imports.append("import pandas as pd")
    return selected_imports


def _writer_lines(result: CellResult, case: Case) -> list[str]:
    writer = result.writer
    profile = result.writer_profile
    prefix = [] if profile is None else [f"options = {profile.effective_options!r}"]
    options = "" if profile is None else ", **options"
    if writer == "pyarrow":
        return [*prefix, f"pq.write_table(TABLE, path{options})"]
    if writer == "duckdb":
        return [
            *prefix,
            "connection = duckdb.connect()",
            "try:",
            f"    connection.from_arrow(TABLE).write_parquet(str(path){options})",
            "finally:",
            "    connection.close()",
        ]
    if writer == "polars":
        return [*prefix, f"pl.from_arrow(TABLE).write_parquet(path{options})"]
    if writer == "fastparquet":
        return [
            *prefix,
            *frame_source_lines(case),
            f"fastparquet.write(str(path), frame, write_index=False{options})",
        ]
    raise ValueError(f"unsupported writer: {writer}")


def _reader_lines(reader: str) -> list[str]:
    if reader == "pyarrow":
        return ["actual = pq.read_table(path)"]
    if reader == "duckdb":
        return [
            "connection = duckdb.connect()",
            "try:",
            "    actual = connection.execute(",
            '        "SELECT * FROM read_parquet(?)", [str(path)]',
            "    ).to_arrow_table()",
            "finally:",
            "    connection.close()",
        ]
    if reader == "polars":
        return ["actual = pl.read_parquet(path).to_arrow()"]
    if reader == "datafusion":
        return ["actual = SessionContext().read_parquet(str(path)).to_arrow_table()"]
    if reader == "fastparquet":
        return [
            "frame = fastparquet.ParquetFile(str(path), pandas_nulls=True).to_pandas()",
            "actual = pa.Table.from_pandas(frame, preserve_index=False)",
        ]
    raise ValueError(f"unsupported reader: {reader}")


def _indent(lines: list[str], spaces: int) -> list[str]:
    return [f"{' ' * spaces}{line}" for line in lines]


def frame_source_lines(case: Case) -> list[str]:
    return [
        "frame = pd.DataFrame({",
        *(
            _series_source(index, field.name, field.type_spec)
            for index, field in enumerate(case.fields)
        ),
        "})",
    ]


def _series_source(index: int, name: str, spec: TypeSpec) -> str:
    dtype, uses_arrow_dtype = pandas_dtype_plan(type_to_arrow(spec))
    if uses_arrow_dtype:
        return (
            f"    {name!r}: pd.Series(TABLE.column({index}), "
            f"dtype=pd.ArrowDtype(TABLE.schema.field({index}).type)),"
        )
    return f"    {name!r}: pd.Series(TABLE.column({index}).to_pylist(), dtype={dtype!r}),"


def field_expression(field: Field) -> str:
    return (
        f"pa.field({field.name!r}, {_type_expression(field.type_spec)}, "
        f"nullable={field.nullable!r})"
    )


def rows_source(case: Case) -> str:
    if not _has_extended_types(case):
        return repr(_row_dicts(case))
    rows = [
        "{"
        + ", ".join(
            f"{field.name!r}: {_value_expression(field.type_spec, value)}"
            for field, value in zip(case.fields, row, strict=True)
        )
        + "}"
        for row in case.rows
    ]
    return "[" + ", ".join(rows) + "]"


def table_lines(case: Case) -> list[str]:
    if not _has_temporal(case):
        return ["TABLE = pa.Table.from_pylist(ROWS, schema=SCHEMA)"]
    storage = ", ".join(_storage_field_expression(field) for field in case.fields)
    return [
        f"STORAGE_SCHEMA = pa.schema([{storage}])",
        "TABLE = pa.Table.from_pylist(ROWS, schema=STORAGE_SCHEMA).cast(SCHEMA)",
    ]


def contains(case: Case, kind: Kind) -> bool:
    return any(_contains_type(field.type_spec, {kind}) for field in case.fields)


def _type_expression(spec: TypeSpec) -> str:
    scalar = {
        Kind.BOOL: "pa.bool_()",
        Kind.INT32: "pa.int32()",
        Kind.INT64: "pa.int64()",
        Kind.STRING: "pa.string()",
        Kind.BINARY: "pa.binary()",
        Kind.FLOAT32: "pa.float32()",
        Kind.FLOAT64: "pa.float64()",
        Kind.DATE32: "pa.date32()",
    }
    if spec.kind in scalar:
        return scalar[spec.kind]
    if spec.kind is Kind.TIMESTAMP:
        return f"pa.timestamp({spec.unit!r}, tz={spec.timezone!r})"
    if spec.kind is Kind.DECIMAL128:
        return f"pa.decimal128({spec.precision}, {spec.scale})"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        field = f"pa.field('item', {_type_expression(item)}, nullable={spec.item_nullable!r})"
        return (
            f"pa.list_({field}, list_size={spec.size})"
            if spec.size is not None
            else f"pa.list_({field})"
        )
    if spec.kind is Kind.STRUCT:
        fields = ", ".join(field_expression(field) for field in spec.fields)
        return f"pa.struct([{fields}])"
    key = _type_expression(cast(TypeSpec, spec.key))
    value = _type_expression(cast(TypeSpec, spec.value))
    return (
        f"pa.map_(pa.field('key', {key}, nullable=False), "
        f"pa.field('value', {value}, nullable={spec.value_nullable!r}))"
    )


def _value_expression(spec: TypeSpec, value: object) -> str:
    if value is None:
        return "None"
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        number = cast(float, value)
        if math.isnan(number):
            return "float('nan')"
        if math.isinf(number):
            return "float('inf')" if number > 0 else "float('-inf')"
    if spec.kind is Kind.DECIMAL128:
        return f"Decimal({str(cast(Decimal, value))!r})"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return (
            "["
            + ", ".join(_value_expression(item, child) for child in cast(list[object], value))
            + "]"
        )
    if spec.kind is Kind.STRUCT:
        data = cast(dict[str, object], value)
        return (
            "{"
            + ", ".join(
                f"{field.name!r}: {_value_expression(field.type_spec, data[field.name])}"
                for field in spec.fields
            )
            + "}"
        )
    if spec.kind is Kind.MAP:
        key = cast(TypeSpec, spec.key)
        item = cast(TypeSpec, spec.value)
        return (
            "["
            + ", ".join(
                f"({_value_expression(key, pair[0])}, {_value_expression(item, pair[1])})"
                for pair in cast(list[list[object]], value)
            )
            + "]"
        )
    return repr(value)


def _row_dicts(case: Case) -> list[dict[str, object]]:
    return [
        {field.name: value for field, value in zip(case.fields, row, strict=True)}
        for row in case.rows
    ]


def _storage_field_expression(field: Field) -> str:
    return (
        f"pa.field({field.name!r}, {_storage_type_expression(field.type_spec)}, "
        f"nullable={field.nullable!r})"
    )


def _storage_type_expression(spec: TypeSpec) -> str:
    if spec.kind is Kind.DATE32:
        return "pa.int32()"
    if spec.kind is Kind.TIMESTAMP:
        return "pa.int64()"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        field = (
            f"pa.field('item', {_storage_type_expression(item)}, nullable={spec.item_nullable!r})"
        )
        return f"pa.list_({field}, list_size={spec.size})" if spec.size else f"pa.list_({field})"
    if spec.kind is Kind.STRUCT:
        return (
            f"pa.struct([{', '.join(_storage_field_expression(field) for field in spec.fields)}])"
        )
    if spec.kind is Kind.MAP:
        key = _storage_type_expression(cast(TypeSpec, spec.key))
        value = _storage_type_expression(cast(TypeSpec, spec.value))
        return (
            f"pa.map_(pa.field('key', {key}, nullable=False), "
            f"pa.field('value', {value}, nullable={spec.value_nullable!r}))"
        )
    return _type_expression(spec)


def _has_extended_types(case: Case) -> bool:
    return any(_contains_type(field.type_spec, None) for field in case.fields)


def _has_temporal(case: Case) -> bool:
    return any(
        _contains_type(field.type_spec, {Kind.DATE32, Kind.TIMESTAMP}) for field in case.fields
    )


def _contains_type(spec: TypeSpec, selected: set[Kind] | None) -> bool:
    extended = {
        Kind.FLOAT32,
        Kind.FLOAT64,
        Kind.DATE32,
        Kind.TIMESTAMP,
        Kind.DECIMAL128,
        Kind.MAP,
    }
    if spec.kind in (extended if selected is None else selected):
        return True
    if spec.item is not None and _contains_type(spec.item, selected):
        return True
    if any(_contains_type(field.type_spec, selected) for field in spec.fields):
        return True
    return (spec.key is not None and _contains_type(spec.key, selected)) or (
        spec.value is not None and _contains_type(spec.value, selected)
    )


__all__ = ["render_upstream_repro"]
