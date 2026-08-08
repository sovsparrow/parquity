from __future__ import annotations

from ..engines.fastparquet_pandas import frame_source_lines
from ..model import Case, Kind
from ..verdicts import CellResult
from .upstream_case import contains, field_expression, rows_source, table_lines


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


__all__ = ["render_upstream_repro"]
