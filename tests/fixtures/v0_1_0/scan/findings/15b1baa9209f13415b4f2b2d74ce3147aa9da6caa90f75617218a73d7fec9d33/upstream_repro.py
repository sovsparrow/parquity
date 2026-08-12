import json
import sys
from importlib import import_module, metadata
from pathlib import Path

ENGINES = ('pyarrow', 'duckdb')


def read(engine, path):
    if engine == "pyarrow":
        return import_module("pyarrow.parquet").read_table(path)
    if engine == "duckdb":
        connection = import_module("duckdb").connect()
        try:
            query = connection.execute("SELECT * FROM read_parquet(?)", [str(path)])
            return query.to_arrow_table()
        finally:
            connection.close()
    if engine == "polars":
        return import_module("polars").read_parquet(path).to_arrow()
    if engine == "datafusion":
        context = import_module("datafusion").SessionContext()
        return context.read_parquet(str(path)).to_arrow_table()
    parquet = import_module("fastparquet").ParquetFile(str(path), pandas_nulls=True)
    frame = parquet.to_pandas()
    return import_module("pyarrow").Table.from_pandas(frame, preserve_index=False)


def main():
    engine = sys.argv[1] if len(sys.argv) == 2 else ""
    if engine not in ENGINES:
        return 2
    path = Path(__file__).resolve().parent / "input.parquet"
    try:
        table = read(engine, path)
    except Exception as error:
        evidence = {
            "engine": engine,
            "version": metadata.version(engine),
            "outcome": "ERROR",
            "error_type": type(error).__name__,
            "detail": str(error),
        }
        print(json.dumps(evidence, sort_keys=True))
        return 1
    evidence = {
        "engine": engine,
        "version": metadata.version(engine),
        "outcome": "SUCCESS",
        "schema": str(table.schema),
        "rows": table.to_pylist(),
    }
    print(json.dumps(evidence, default=repr, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
