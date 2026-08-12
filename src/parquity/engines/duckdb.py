from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

import duckdb
import pyarrow as pa

from ..profiles import WriterProfileIdentity
from .base import EngineIdentity, EngineReaderWriter, ProviderOperationError


@dataclass(frozen=True, slots=True)
class DuckDBEngine:
    identity: EngineIdentity

    def write(self, table: pa.Table, path: Path) -> None:
        try:
            connection = duckdb.connect()
            try:
                connection.from_arrow(table).write_parquet(str(path))
            finally:
                connection.close()
        except duckdb.Error as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = {
            "compression-gzip": {"compression": "gzip"},
            "compression-brotli": {"compression": "brotli"},
        }
        selected = options.get(name)
        return None if selected is None else WriterProfileIdentity(name, selected)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the DuckDB translation")
        compression = cast(Literal["gzip", "brotli"], profile.effective_options["compression"])
        try:
            connection = duckdb.connect()
            try:
                connection.from_arrow(table).write_parquet(str(path), compression=compression)
            finally:
                connection.close()
        except duckdb.Error as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def read(self, path: Path) -> pa.Table:
        try:
            connection = duckdb.connect()
            try:
                return connection.execute(
                    "SELECT * FROM read_parquet(?)", [str(path)]
                ).to_arrow_table()
            finally:
                connection.close()
        except duckdb.Error as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error


def create_engine(version: str) -> EngineReaderWriter:
    return DuckDBEngine(EngineIdentity("duckdb", version))
