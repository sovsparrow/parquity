from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa
import pyarrow.parquet as pq

from ..profiles import WriterProfileIdentity
from .base import EngineIdentity, EngineReaderWriter, ProviderOperationError


class _WriteTable(Protocol):
    def __call__(self, table: pa.Table, path: Path, **options: object) -> None: ...


class _ReadTable(Protocol):
    def __call__(self, path: Path) -> pa.Table: ...


class _ParquetModule(Protocol):
    write_table: _WriteTable
    read_table: _ReadTable


_PARQUET = cast(_ParquetModule, cast(object, pq))


@dataclass(frozen=True, slots=True)
class PyArrowEngine:
    identity: EngineIdentity

    def write(self, table: pa.Table, path: Path) -> None:
        try:
            _PARQUET.write_table(table, path)
        except pa.ArrowException as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = {
            "compression-gzip": {"compression": "gzip"},
            "compression-brotli": {"compression": "brotli"},
            "row-group-2": {"row_group_size": 2},
            "min-max-statistics-off": {"write_statistics": False},
        }
        selected = options.get(name)
        return None if selected is None else WriterProfileIdentity(name, selected)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the PyArrow translation")
        try:
            _PARQUET.write_table(table, path, **profile.effective_options)
        except (pa.ArrowException, TypeError, ValueError) as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def read(self, path: Path) -> pa.Table:
        try:
            return _PARQUET.read_table(path)
        except pa.ArrowException as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error


def create_engine(version: str) -> EngineReaderWriter:
    return PyArrowEngine(EngineIdentity("pyarrow", version))
