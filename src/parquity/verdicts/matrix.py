from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .. import evidence
from ..evidence import EngineVersion
from .model import CellResult, FailureFingerprint, Verdict

if TYPE_CHECKING:
    from .. import profiles
    from ..model import Case


class CaseEvaluator(Protocol):
    def __call__(self, case: Case, directory: Path, /) -> MatrixRun: ...


@dataclass(frozen=True, slots=True)
class MatrixRun:
    case_id: str
    results: tuple[CellResult, ...]
    files: tuple[tuple[str | profiles.WriterExecutionIdentity, Path], ...] = ()
    writers: tuple[EngineVersion, ...] = ()
    readers: tuple[EngineVersion, ...] = ()
    writer_profiles: profiles.WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        _validate_matrix_structure(self.writers, self.readers, self.results, self.writer_profiles)

    @property
    def failures(self) -> tuple[CellResult, ...]:
        return tuple(result for result in self.results if not result.passed)

    @property
    def distinct_failures(self) -> tuple[CellResult, ...]:
        by_fingerprint = {
            fingerprint: result
            for result in self.results
            if (fingerprint := result.fingerprint) is not None
        }
        return tuple(
            by_fingerprint[fingerprint]
            for fingerprint in sorted(by_fingerprint, key=FailureFingerprint.canonical_bytes)
        )

    @property
    def status(self) -> str:
        return "PASS" if not self.failures else "FAIL"

    def file_for(
        self, writer: str, writer_profile: profiles.WriterProfileIdentity | None = None
    ) -> Path | None:
        for identity, path in self.files:
            if isinstance(identity, str):
                if identity == writer and writer_profile is None:
                    return path
            elif identity.writer.name == writer and identity.writer_profile == writer_profile:
                return path
        return None

    def normalized(self, transient_roots: tuple[Path, ...]) -> MatrixRun:
        return MatrixRun(
            self.case_id,
            tuple(result.normalized(transient_roots) for result in self.results),
            self.files,
            self.writers,
            self.readers,
            self.writer_profiles,
        )


def _validate_matrix_structure(
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    results: tuple[CellResult, ...],
    writer_profiles: profiles.WriterProfilePlan | None,
) -> None:
    for label, engines in (("writer", writers), ("reader", readers)):
        if not evidence.engine_selection_is_valid(engines):
            raise ValueError(f"matrix {label} selection must be non-empty and unique")
    position = 0
    if writer_profiles is None:
        executions = tuple((writer, None) for writer in writers)
    else:
        executions = tuple(
            (item.writer, item.writer_profile) for item in writer_profiles.executions(writers)
        )
    for writer, profile in executions:
        if position >= len(results):
            raise ValueError("matrix results are incomplete")
        first = results[position]
        if first.verdict is Verdict.WRITE_ERROR:
            _validate_write_error(first, writer, profile)
            position += 1
            continue
        for reader in readers:
            if position >= len(results):
                raise ValueError("matrix results are incomplete")
            _validate_reader_cell(results[position], writer, reader, profile)
            position += 1
    if position != len(results):
        raise ValueError("matrix results contain extra cells")


def _validate_write_error(
    result: CellResult,
    writer: EngineVersion,
    writer_profile: profiles.WriterProfileIdentity | None,
) -> None:
    valid = (
        result.writer == writer.name
        and result.writer_version == writer.version
        and result.writer_profile == writer_profile
    )
    if not valid:
        raise ValueError("matrix writer error conflicts with the declared selection")


def _validate_reader_cell(
    result: CellResult,
    writer: EngineVersion,
    reader: EngineVersion,
    writer_profile: profiles.WriterProfileIdentity | None,
) -> None:
    engines_match = (
        result.writer == writer.name
        and result.writer_version == writer.version
        and result.reader == reader.name
        and result.reader_version == reader.version
        and result.writer_profile == writer_profile
    )
    if not engines_match:
        raise ValueError("matrix reader cell conflicts with the declared selection")


__all__ = ["CaseEvaluator", "MatrixRun"]
