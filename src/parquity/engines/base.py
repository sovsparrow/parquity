from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import pyarrow as pa

    from ..writer_profiles import WriterProfileIdentity


@dataclass(frozen=True, slots=True)
class EngineDescriptor:
    name: str
    distribution: str
    import_name: str
    adapter_module: str
    installation_hint: str
    tier: str
    reader: bool
    writer: bool

    def __post_init__(self) -> None:
        if self.tier not in ("core", "extended"):
            raise ValueError("engine tier must be core or extended")
        if not self.reader and not self.writer:
            raise ValueError("an engine must declare at least one direction")


@dataclass(frozen=True, slots=True)
class EngineIdentity:
    name: str
    version: str


class ProviderOperationError(Exception):
    def __init__(self, engine: str, operation: str, cause: Exception) -> None:
        self.engine = engine
        self.operation = operation
        self.provider_type = type(cause).__name__
        message = " ".join(str(cause).split())
        self.detail = message[:500]
        super().__init__(f"{engine} {operation} failed: {self.provider_type}: {self.detail}")


@runtime_checkable
class EngineReader(Protocol):
    @property
    def identity(self) -> EngineIdentity: ...

    def read(self, path: Path) -> pa.Table: ...


@runtime_checkable
class EngineWriter(Protocol):
    @property
    def identity(self) -> EngineIdentity: ...

    def write(self, table: pa.Table, path: Path) -> None: ...


@runtime_checkable
class ProfiledEngineWriter(EngineWriter, Protocol):
    def writer_profile(self, name: str) -> WriterProfileIdentity | None: ...

    def write_profiled(
        self, table: pa.Table, path: Path, profile: WriterProfileIdentity
    ) -> None: ...


@runtime_checkable
class EngineReaderWriter(EngineReader, EngineWriter, Protocol):
    pass
