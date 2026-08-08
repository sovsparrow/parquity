from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa
from datafusion import SessionContext

from .base import EngineIdentity, EngineReader, ProviderOperationError


class _DataFrame(Protocol):
    def __call__(self) -> object: ...


class _Context(Protocol):
    def __call__(self, path: str) -> object: ...


class _SessionContextFactory(Protocol):
    def __call__(self) -> object: ...


_SESSION_CONTEXT = cast(_SessionContextFactory, cast(object, SessionContext))


@dataclass(frozen=True, slots=True)
class DataFusionEngine:
    identity: EngineIdentity

    def read(self, path: Path) -> pa.Table:
        try:
            context = _SESSION_CONTEXT()
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error
        read_parquet = _read_method(context)
        try:
            frame = read_parquet(str(path))
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error
        to_arrow_table = _arrow_method(frame)
        try:
            table = to_arrow_table()
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error
        if not isinstance(table, pa.Table):
            raise TypeError("datafusion materialization did not return a PyArrow table")
        return table


def _read_method(value: object) -> _Context:
    member = getattr(value, "read_parquet", None)
    if not callable(member):
        raise TypeError("datafusion context has no callable read_parquet")
    return cast(_Context, member)


def _arrow_method(value: object) -> _DataFrame:
    member = getattr(value, "to_arrow_table", None)
    if not callable(member):
        raise TypeError("datafusion frame has no callable to_arrow_table")
    return cast(_DataFrame, member)


def create_engine(version: str) -> EngineReader:
    return DataFusionEngine(EngineIdentity("datafusion", version))
