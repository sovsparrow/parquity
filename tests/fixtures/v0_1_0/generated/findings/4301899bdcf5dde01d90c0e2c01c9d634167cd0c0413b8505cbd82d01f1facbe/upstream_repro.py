import json
import tempfile
from importlib import metadata
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import duckdb

CASE_ID = 'fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3'
EXPECTED_CASE = {'format': 'parquity.case.v1', 'schema': [{'name': 'value', 'nullable': False, 'type': {'kind': 'int32'}}], 'rows': [[1]]}
TARGET = {'writer': 'pyarrow', 'writer_version': '25.0.0', 'reader': 'duckdb', 'reader_version': '1.5.5', 'operation': 'compare', 'verdict': 'VALUE_MISMATCH', 'schema_path': '$rows[0].value', 'detail': 'expected 1, got 2', 'diagnostic_kind': 'VALUE_MISMATCH'}
PROVIDERS = [('writer', 'pyarrow'), ('reader', 'duckdb')]
VERSIONS = [{"role": role, "engine": engine, "version": metadata.version(engine)} for role, engine in PROVIDERS]
SCHEMA = pa.schema([pa.field('value', pa.int32(), nullable=False)])
ROWS = [{'value': 1}]
TABLE = pa.Table.from_pylist(ROWS, schema=SCHEMA)

def record(operation: str, outcome: str, **evidence: object) -> None:
    payload = {
        "case_id": CASE_ID,
        "expected_case": EXPECTED_CASE,
        "target": TARGET,
        "provider_versions": VERSIONS,
        "operation": operation,
        "outcome": outcome,
    }
    payload.update(evidence)
    print(json.dumps(payload, default=repr, ensure_ascii=False, sort_keys=True))

def main() -> int:
    with tempfile.TemporaryDirectory(prefix="parquity-upstream-") as raw_directory:
        path = Path(raw_directory) / "input.parquet"
        try:
            pq.write_table(TABLE, path)
            byte_count = path.stat().st_size
        except Exception as error:
            record("write", "ERROR", error_type=type(error).__name__, detail=str(error))
            return 1
        record("write", "WRITE_COMPLETED", byte_count=byte_count)
        if TARGET["operation"] == "write":
            return 0
        try:
            connection = duckdb.connect()
            try:
                actual = connection.execute(
                    "SELECT * FROM read_parquet(?)", [str(path)]
                ).to_arrow_table()
            finally:
                connection.close()
        except Exception as error:
            record("read", "ERROR", error_type=type(error).__name__, detail=str(error))
            return 1
        record("read", "READ_COMPLETED", schema=str(actual.schema), rows=actual.to_pylist())
        return 0

if __name__ == "__main__":
    raise SystemExit(main())
