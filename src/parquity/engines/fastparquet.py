from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa

from ..writer_profiles import WriterProfileIdentity
from .base import EngineIdentity, EngineReaderWriter, ProviderOperationError
from .fastparquet_pandas import table_to_pandas


class _Write(Protocol):
    def __call__(
        self, path: str, frame: object, *, write_index: bool, **options: object
    ) -> None: ...


class _ParquetFile(Protocol):
    def to_pandas(self) -> object: ...


class _ParquetFileFactory(Protocol):
    def __call__(self, path: str, *, pandas_nulls: bool) -> _ParquetFile: ...


class _FastparquetModule(Protocol):
    write: _Write
    ParquetFile: _ParquetFileFactory


class _ArrowTableFactory(Protocol):
    def from_pandas(self, frame: object, *, preserve_index: bool) -> pa.Table: ...


_FASTPARQUET = cast(_FastparquetModule, cast(object, import_module("fastparquet")))
_ARROW_TABLE = cast(_ArrowTableFactory, cast(object, pa.Table))


@dataclass(frozen=True, slots=True)
class FastparquetEngine:
    identity: EngineIdentity

    def write(self, table: pa.Table, path: Path) -> None:
        try:
            frame = table_to_pandas(table)
            _FASTPARQUET.write(str(path), frame, write_index=False)
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = {
            "compression-gzip": {"compression": "GZIP"},
            "compression-brotli": {"compression": "BROTLI"},
            "row-group-2": {"row_group_offsets": 2},
            "min-max-statistics-off": {"stats": False},
        }
        selected = options.get(name)
        return None if selected is None else WriterProfileIdentity(name, selected)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the fastparquet translation")
        try:
            frame = table_to_pandas(table)
            _FASTPARQUET.write(str(path), frame, write_index=False, **profile.effective_options)
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def read(self, path: Path) -> pa.Table:
        try:
            frame = _FASTPARQUET.ParquetFile(str(path), pandas_nulls=True).to_pandas()
            return _ARROW_TABLE.from_pandas(frame, preserve_index=False)
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error


def create_engine(version: str) -> EngineReaderWriter:
    return FastparquetEngine(EngineIdentity("fastparquet", version))
