from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pyarrow as pa

from .arrow_bridge import case_to_arrow
from .compare import compare_case
from .engines.base import (
    EngineReader,
    EngineWriter,
    ProfiledEngineWriter,
    ProviderOperationError,
)
from .model import Case
from .verdicts import CellResult, ComparisonResult, EngineVersion, MatrixRun, Verdict
from .writer_profile_contracts import (
    WriterProfileContractViolation,
    verify_writer_profile_artifact,
)
from .writer_profiles import WriterExecutionIdentity, WriterProfileIdentity, WriterProfilePlan


def run_matrix(
    case: Case,
    directory: Path,
    writer_set: Sequence[EngineWriter],
    reader_set: Sequence[EngineReader],
    writer_profiles: WriterProfilePlan | None = None,
) -> MatrixRun:
    writers = tuple(writer_set)
    readers = tuple(reader_set)
    _validate_writers(writers)
    _validate_readers(readers)
    directory.mkdir(parents=True, exist_ok=True)
    table = case_to_arrow(case)
    results: list[CellResult] = []
    files: list[tuple[str | WriterExecutionIdentity, Path]] = []
    attempts: list[
        tuple[EngineWriter, WriterExecutionIdentity, Path, ProviderOperationError | None]
    ] = []
    versions = tuple(
        EngineVersion(writer.identity.name, writer.identity.version) for writer in writers
    )
    executions = _executions(versions, writer_profiles)
    for writer in writers:
        selected = tuple(item for item in executions if item.writer.name == writer.identity.name)
        for execution in selected:
            profile = execution.writer_profile
            path = directory / _filename(writer.identity.name, profile)
            try:
                _write(writer, table, path, profile)
            except ProviderOperationError as error:
                if error.engine != writer.identity.name or error.operation != "write":
                    raise
                attempts.append((writer, execution, path, error))
                continue
            except WriterProfileContractViolation as error:
                _discard_outputs((*[item[2] for item in attempts], path), error)
                raise
            key: str | WriterExecutionIdentity = (
                writer.identity.name if profile is None else execution
            )
            files.append((key, path))
            attempts.append((writer, execution, path, None))
    for writer, execution, path, error in attempts:
        if error is not None:
            results.append(_write_error(writer, error, execution.writer_profile))
            continue
        results.extend(
            _read_and_compare(case, writer, reader, path, execution.writer_profile)
            for reader in readers
        )
    return MatrixRun(
        case.case_id,
        tuple(results),
        tuple(files),
        versions,
        tuple(EngineVersion(reader.identity.name, reader.identity.version) for reader in readers),
        writer_profiles,
    ).normalized((directory,))


def _read_and_compare(
    case: Case,
    writer: EngineWriter,
    reader: EngineReader,
    path: Path,
    writer_profile: WriterProfileIdentity | None = None,
) -> CellResult:
    try:
        actual = reader.read(path)
    except ProviderOperationError as error:
        if error.engine != reader.identity.name or error.operation != "read":
            raise
        return CellResult(
            writer=writer.identity.name,
            writer_version=writer.identity.version,
            reader=reader.identity.name,
            reader_version=reader.identity.version,
            operation="read",
            verdict=Verdict.READ_ERROR,
            schema_path="$",
            detail=error.detail,
            diagnostic_kind=error.provider_type,
            writer_profile=writer_profile,
        )
    return _comparison_result(writer, reader, compare_case(case, actual), writer_profile)


def _comparison_result(
    writer: EngineWriter,
    reader: EngineReader,
    comparison: ComparisonResult,
    writer_profile: WriterProfileIdentity | None = None,
) -> CellResult:
    return CellResult(
        writer=writer.identity.name,
        writer_version=writer.identity.version,
        reader=reader.identity.name,
        reader_version=reader.identity.version,
        operation="compare",
        verdict=comparison.verdict,
        schema_path=comparison.path,
        detail=comparison.detail,
        diagnostic_kind=comparison.verdict.value,
        writer_profile=writer_profile,
        difference=comparison.difference,
    )


def _executions(
    writers: tuple[EngineVersion, ...], plan: WriterProfilePlan | None
) -> tuple[WriterExecutionIdentity, ...]:
    if plan is None:
        return tuple(WriterExecutionIdentity(writer) for writer in writers)
    return plan.executions(writers)


def _write(
    writer: EngineWriter,
    table: pa.Table,
    path: Path,
    profile: WriterProfileIdentity | None,
) -> None:
    if profile is None:
        writer.write(table, path)
        return
    if not isinstance(writer, ProfiledEngineWriter):
        raise ValueError("writer cannot execute the recorded profile")
    writer.write_profiled(table, path, profile)
    verify_writer_profile_artifact(path, profile, table.num_rows)


def _discard_outputs(paths: Sequence[Path], violation: WriterProfileContractViolation) -> None:
    try:
        for path in dict.fromkeys(paths):
            path.unlink(missing_ok=True)
    except OSError as error:
        raise WriterProfileContractViolation(
            violation.profile_name,
            f"{violation.detail}; produced artifact removal failed",
        ) from error


def _write_error(
    writer: EngineWriter,
    error: ProviderOperationError,
    profile: WriterProfileIdentity | None,
) -> CellResult:
    return CellResult(
        writer=writer.identity.name,
        writer_version=writer.identity.version,
        reader="*",
        reader_version="*",
        operation="write",
        verdict=Verdict.WRITE_ERROR,
        schema_path="$",
        detail=error.detail,
        diagnostic_kind=error.provider_type,
        writer_profile=profile,
    )


def _filename(writer: str, profile: WriterProfileIdentity | None) -> str:
    return f"{writer}.parquet" if profile is None else f"{writer}--{profile.name}.parquet"


def _validate_writers(writers: tuple[EngineWriter, ...]) -> None:
    if not writers:
        raise ValueError("matrix requires at least one writer")
    names = [writer.identity.name for writer in writers]
    if len(names) != len(set(names)):
        raise ValueError("matrix writer names must be unique")


def _validate_readers(readers: tuple[EngineReader, ...]) -> None:
    if not readers:
        raise ValueError("matrix requires at least one reader")
    names = [reader.identity.name for reader in readers]
    if len(names) != len(set(names)):
        raise ValueError("matrix reader names must be unique")
