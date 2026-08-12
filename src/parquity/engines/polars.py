from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import polars as pl
import pyarrow as pa

from ..profiles import WriterProfileIdentity
from .base import EngineIdentity, EngineReaderWriter, ProviderOperationError


class _FromArrow(Protocol):
    def __call__(self, table: pa.Table) -> pl.DataFrame: ...


class _PolarsModule(Protocol):
    from_arrow: _FromArrow


class _WriteParquet(Protocol):
    def __call__(self, file: str | Path, **options: object) -> None: ...


_POLARS = cast(_PolarsModule, cast(object, pl))


@dataclass(frozen=True, slots=True)
class PolarsEngine:
    identity: EngineIdentity

    def write(self, table: pa.Table, path: Path) -> None:
        try:
            frame = _POLARS.from_arrow(table)
            frame.write_parquet(path)
        except (pl.exceptions.PolarsError, pl.exceptions.PanicException) as error:
            cause = cast(Exception, error)
            raise ProviderOperationError(self.identity.name, "write", cause) from error

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = {
            "compression-gzip": {"compression": "gzip"},
            "compression-brotli": {"compression": "brotli"},
            "row-group-2": {"row_group_size": 2},
            "min-max-statistics-off": {"statistics": False},
        }
        selected = options.get(name)
        return None if selected is None else WriterProfileIdentity(name, selected)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the Polars translation")
        try:
            frame = _POLARS.from_arrow(table)
        except (pl.exceptions.PolarsError, pl.exceptions.PanicException) as error:
            cause = cast(Exception, error)
            raise ProviderOperationError(self.identity.name, "write", cause) from error
        try:
            write_parquet = cast(_WriteParquet, frame.write_parquet)
            write_parquet(path, **profile.effective_options)
        except (
            pl.exceptions.PolarsError,
            pl.exceptions.PanicException,
            TypeError,
            ValueError,
        ) as error:
            cause = cast(Exception, error)
            raise ProviderOperationError(self.identity.name, "write", cause) from error

    def read(self, path: Path) -> pa.Table:
        try:
            return pl.read_parquet(path).to_arrow()
        except (pl.exceptions.PolarsError, pl.exceptions.PanicException) as error:
            cause = cast(Exception, error)
            raise ProviderOperationError(self.identity.name, "read", cause) from error


def create_engine(version: str) -> EngineReaderWriter:
    return PolarsEngine(EngineIdentity("polars", version))
