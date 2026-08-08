from __future__ import annotations

import tempfile
from collections.abc import Sequence
from enum import StrEnum
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from .engines.base import EngineWriter, ProfiledEngineWriter, ProviderOperationError
from .verdicts import EngineVersion
from .writer_profiles import (
    OPTION_UNAVAILABLE,
    CapabilityStatus,
    WriterProfileCapability,
    WriterProfileError,
    WriterProfileIdentity,
    WriterProfilePlan,
)

if TYPE_CHECKING:
    import pyarrow as pa

CONTRACT_VIOLATION = "WRITER_PROFILE_CONTRACT_VIOLATION"


class _Statistics(Protocol):
    has_min_max: bool


class _ColumnChunk(Protocol):
    compression: str
    num_values: int
    statistics: _Statistics | None


class _RowGroup(Protocol):
    num_columns: int
    num_rows: int

    def column(self, index: int) -> _ColumnChunk: ...


class _FileMetadata(Protocol):
    num_row_groups: int
    num_rows: int

    def row_group(self, index: int) -> _RowGroup: ...


class _ParquetFile(Protocol):
    metadata: _FileMetadata


class _ParquetFileFactory(Protocol):
    def __call__(self, path: Path) -> _ParquetFile: ...


class _ParquetModule(Protocol):
    ParquetFile: _ParquetFileFactory


class _TableFactory(Protocol):
    def from_arrays(self, arrays: Sequence[object], *, schema: object) -> object: ...


class _ArrowModule(Protocol):
    ArrowInvalid: type[Exception]
    Table: _TableFactory

    def array(self, values: Sequence[object], data_type: object) -> object: ...

    def field(self, name: str, data_type: object, *, nullable: bool) -> object: ...

    def int32(self) -> object: ...

    def schema(self, fields: Sequence[object]) -> object: ...

    def string(self) -> object: ...


class WriterProfileContractViolation(RuntimeError):
    kind = CONTRACT_VIOLATION

    def __init__(self, profile_name: str, detail: str) -> None:
        self.profile_name = profile_name
        self.detail = detail
        super().__init__(f"{profile_name}: {detail}")


class ArtifactContractObservation(StrEnum):
    VERIFIED = "VERIFIED"
    NOT_OBSERVABLE_EMPTY = "NOT_OBSERVABLE_EMPTY"


def verify_writer_profile_artifact(
    path: Path,
    profile: WriterProfileIdentity,
    expected_rows: int,
) -> ArtifactContractObservation:
    parquet = cast(_ParquetModule, cast(object, import_module("pyarrow.parquet")))
    arrow = cast(_ArrowModule, cast(object, import_module("pyarrow")))
    try:
        artifact = parquet.ParquetFile(path)
    except (FileNotFoundError, arrow.ArrowInvalid) as error:
        raise WriterProfileContractViolation(
            profile.name, "artifact footer could not be verified"
        ) from error
    return _verify_metadata(artifact.metadata, profile, expected_rows)


def admit_writer_profile_plan(
    declared: WriterProfilePlan | None,
    writers: Sequence[EngineWriter],
) -> WriterProfilePlan | None:
    if declared is None:
        return None
    writer_versions = tuple(
        EngineVersion(writer.identity.name, writer.identity.version) for writer in writers
    )
    declared.validate_writers(writer_versions)
    installed: list[WriterProfileCapability] = []
    table = _fixed_control_table()
    with tempfile.TemporaryDirectory(prefix="parquity-profile-control-") as raw_directory:
        directory = Path(raw_directory)
        for index, capability in enumerate(declared.capabilities):
            if capability.status is CapabilityStatus.UNSUPPORTED:
                installed.append(capability)
                continue
            writer = writers[writer_versions.index(capability.writer)]
            profile = capability.profile_identity
            if profile is None:
                raise TypeError("supported writer profile capability has no identity")
            try:
                _write_control(writer, table, directory / f"endpoint-{index}.parquet", profile)
            except ProviderOperationError as error:
                if error.engine != writer.identity.name or error.operation != "write":
                    raise
                installed.append(_unavailable(capability))
            except WriterProfileContractViolation:
                installed.append(_unavailable(capability))
            else:
                installed.append(capability)
    _require_installed_support(declared.requested_profiles, installed)
    return WriterProfilePlan(declared.requested_profiles, tuple(installed))


def _verify_metadata(
    metadata: _FileMetadata,
    profile: WriterProfileIdentity,
    expected_rows: int,
) -> ArtifactContractObservation:
    observation = _artifact_observation(metadata, profile.name, expected_rows)
    if observation is ArtifactContractObservation.NOT_OBSERVABLE_EMPTY:
        return observation
    if profile.name == "compression-gzip":
        _verify_compression(metadata, profile.name, "GZIP")
    elif profile.name == "compression-brotli":
        _verify_compression(metadata, profile.name, "BROTLI")
    elif profile.name == "row-group-2":
        _verify_row_groups(metadata, profile.name, expected_rows)
    elif profile.name == "min-max-statistics-off":
        _verify_min_max_statistics(metadata, profile.name)
    else:
        raise WriterProfileContractViolation(profile.name, "artifact contract is not recognized")
    return ArtifactContractObservation.VERIFIED


def _artifact_observation(
    metadata: _FileMetadata,
    profile_name: str,
    expected_rows: int,
) -> ArtifactContractObservation:
    groups = tuple(metadata.row_group(index) for index in range(metadata.num_row_groups))
    chunks = _column_chunks(metadata)
    if expected_rows == 0:
        empty = (
            metadata.num_rows == 0
            and all(group.num_rows == 0 for group in groups)
            and all(chunk.num_values == 0 for chunk in chunks)
        )
        if not empty:
            raise WriterProfileContractViolation(
                profile_name, "empty artifact contains non-empty physical evidence"
            )
        return ArtifactContractObservation.NOT_OBSERVABLE_EMPTY
    if expected_rows < 0 or metadata.num_rows != expected_rows or not chunks:
        raise WriterProfileContractViolation(
            profile_name, "non-empty artifact has no complete observable evidence"
        )
    return ArtifactContractObservation.VERIFIED


def _verify_compression(metadata: _FileMetadata, profile_name: str, expected: str) -> None:
    if any(column.compression != expected for column in _column_chunks(metadata)):
        raise WriterProfileContractViolation(
            profile_name, f"a column chunk does not use {expected} compression"
        )


def _verify_row_groups(
    metadata: _FileMetadata,
    profile_name: str,
    expected_rows: int,
) -> None:
    sizes = tuple(metadata.row_group(index).num_rows for index in range(metadata.num_row_groups))
    if expected_rows == 0:
        valid = metadata.num_rows == 0 and all(size == 0 for size in sizes)
    else:
        pair_count, remainder = divmod(expected_rows, 2)
        expected_sizes = (2,) * pair_count + ((1,) if remainder else ())
        valid = metadata.num_rows == expected_rows and sizes == expected_sizes
    if not valid:
        raise WriterProfileContractViolation(profile_name, "row-group sizes violate the contract")


def _verify_min_max_statistics(metadata: _FileMetadata, profile_name: str) -> None:
    if any(
        column.statistics is not None and column.statistics.has_min_max
        for column in _column_chunks(metadata)
    ):
        raise WriterProfileContractViolation(
            profile_name, "a column chunk contains min/max statistics"
        )


def _column_chunks(metadata: _FileMetadata) -> tuple[_ColumnChunk, ...]:
    return tuple(
        metadata.row_group(group).column(column)
        for group in range(metadata.num_row_groups)
        for column in range(metadata.row_group(group).num_columns)
    )


def _fixed_control_table() -> pa.Table:
    arrow = cast(_ArrowModule, cast(object, import_module("pyarrow")))
    schema = arrow.schema(
        (
            arrow.field("value", arrow.int32(), nullable=False),
            arrow.field("label", arrow.string(), nullable=False),
        )
    )
    table = arrow.Table.from_arrays(
        (
            arrow.array((1, 2, 3, 4), arrow.int32()),
            arrow.array(("a", "b", "c", "d"), arrow.string()),
        ),
        schema=schema,
    )
    return cast("pa.Table", table)


def _write_control(
    writer: EngineWriter,
    table: pa.Table,
    path: Path,
    profile: WriterProfileIdentity,
) -> None:
    if not isinstance(writer, ProfiledEngineWriter):
        raise TypeError("declared writer profile endpoint is not executable")
    result = writer.write_profiled(table, path, profile)
    if result is not None:
        raise TypeError("writer profile endpoint returned a foreign result")
    observation = verify_writer_profile_artifact(path, profile, table.num_rows)
    if observation is not ArtifactContractObservation.VERIFIED:
        raise TypeError("non-empty writer profile control is not observable")


def _unavailable(capability: WriterProfileCapability) -> WriterProfileCapability:
    return WriterProfileCapability(
        capability.writer,
        capability.profile_name,
        CapabilityStatus.UNSUPPORTED,
        reason_code=OPTION_UNAVAILABLE,
    )


def _require_installed_support(
    requested: tuple[str, ...],
    capabilities: Sequence[WriterProfileCapability],
) -> None:
    missing = tuple(
        name
        for name in requested
        if not any(
            item.profile_name == name and item.status is CapabilityStatus.SUPPORTED
            for item in capabilities
        )
    )
    if missing:
        names = ", ".join(missing)
        raise WriterProfileError(
            "WRITER_PROFILE_UNSUPPORTED",
            f"requested writer profile is unavailable in installed providers: {names}",
        )


__all__ = [
    "CONTRACT_VIOLATION",
    "ArtifactContractObservation",
    "WriterProfileContractViolation",
    "admit_writer_profile_plan",
    "verify_writer_profile_artifact",
]
