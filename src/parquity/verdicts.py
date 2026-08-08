from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Self

from .result_evidence import DifferenceEvidence, EngineVersion, normalize_detail

if TYPE_CHECKING:
    from . import writer_profiles as profiles


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 - public verdict label, not a password.
    WRITE_ERROR = "WRITE_ERROR"
    READ_ERROR = "READ_ERROR"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    ROW_COUNT_MISMATCH = "ROW_COUNT_MISMATCH"
    VALUE_MISMATCH = "VALUE_MISMATCH"


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    verdict: Verdict
    path: str
    detail: str
    difference: DifferenceEvidence | None = None

    @property
    def passed(self) -> bool:
        return self.verdict is Verdict.PASS

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "verdict": self.verdict.value,
            "path": self.path,
            "detail": self.detail,
        }
        if self.difference is not None:
            data["difference"] = self.difference.to_data()
        return data


@dataclass(frozen=True, slots=True)
class EngineAvailability:
    name: str
    distribution: str
    tier: str
    reader: bool
    writer: bool
    available: bool
    version: str | None
    installation_hint: str | None
    detail: str

    def __post_init__(self) -> None:
        if self.available and self.version is None:
            raise ValueError("an available engine requires a version")
        if not self.available and not self.installation_hint:
            raise ValueError("an unavailable engine requires an installation hint")

    def to_data(self) -> dict[str, object]:
        return {
            "name": self.name,
            "distribution": self.distribution,
            "tier": self.tier,
            "reader": self.reader,
            "writer": self.writer,
            "available": self.available,
            "version": self.version,
            "installation_hint": self.installation_hint,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class FailureFingerprint:
    writer: str
    writer_version: str
    reader: str
    reader_version: str
    operation: str
    verdict: Verdict
    schema_path: str
    diagnostic_kind: str
    normalized_detail_sha256: str
    writer_profile: profiles.WriterProfileIdentity | None = None

    def __post_init__(self) -> None:
        values = (
            self.writer,
            self.writer_version,
            self.reader,
            self.reader_version,
            self.operation,
            self.schema_path,
            self.diagnostic_kind,
        )
        if any(not value for value in values):
            raise ValueError("fingerprint fields must not be empty")
        malformed_hash = len(self.normalized_detail_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.normalized_detail_sha256
        )
        if malformed_hash:
            raise ValueError("normalized detail SHA-256 is malformed")

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "writer": self.writer,
            "writer_version": self.writer_version,
            "reader": self.reader,
            "reader_version": self.reader_version,
            "operation": self.operation,
            "verdict": self.verdict.value,
            "schema_path": self.schema_path,
            "diagnostic_kind": self.diagnostic_kind,
            "normalized_detail_sha256": self.normalized_detail_sha256,
        }
        if self.writer_profile is not None:
            data["writer_profile"] = self.writer_profile.to_data()
        return data

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_data(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CellResult:
    writer: str
    writer_version: str
    reader: str
    reader_version: str
    operation: str
    verdict: Verdict
    schema_path: str
    detail: str
    diagnostic_kind: str = ""
    writer_profile: profiles.WriterProfileIdentity | None = None
    difference: DifferenceEvidence | None = None

    def __post_init__(self) -> None:
        if not self.diagnostic_kind:
            object.__setattr__(self, "diagnostic_kind", self.verdict.value)
        object.__setattr__(self, "detail", normalize_detail(self.detail))
        semantic = self.operation == "compare" and self.verdict not in (
            Verdict.PASS,
            Verdict.WRITE_ERROR,
            Verdict.READ_ERROR,
        )
        if self.difference is not None and not semantic:
            raise ValueError("difference evidence requires a semantic disagreement")

    @property
    def passed(self) -> bool:
        return self.verdict is Verdict.PASS

    @property
    def fingerprint(self) -> FailureFingerprint | None:
        if self.passed:
            return None
        return FailureFingerprint(
            writer=self.writer,
            writer_version=self.writer_version,
            reader=self.reader,
            reader_version=self.reader_version,
            operation=self.operation,
            verdict=self.verdict,
            schema_path=self.schema_path,
            diagnostic_kind=self.diagnostic_kind,
            normalized_detail_sha256=hashlib.sha256(self.detail.encode("utf-8")).hexdigest(),
            writer_profile=self.writer_profile,
        )

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "writer": self.writer,
            "writer_version": self.writer_version,
            "reader": self.reader,
            "reader_version": self.reader_version,
            "operation": self.operation,
            "verdict": self.verdict.value,
            "schema_path": self.schema_path,
            "detail": self.detail,
            "diagnostic_kind": self.diagnostic_kind,
        }
        if self.writer_profile is not None:
            data["writer_profile"] = self.writer_profile.to_data()
        if self.difference is not None:
            data["difference"] = self.difference.to_data()
        return data

    def normalized(self, transient_roots: tuple[Path, ...]) -> Self:
        detail = normalize_detail(self.detail, transient_roots)
        if detail == self.detail:
            return self
        return type(self)(
            writer=self.writer,
            writer_version=self.writer_version,
            reader=self.reader,
            reader_version=self.reader_version,
            operation=self.operation,
            verdict=self.verdict,
            schema_path=self.schema_path,
            detail=detail,
            diagnostic_kind=self.diagnostic_kind,
            writer_profile=self.writer_profile,
            difference=self.difference,
        )


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

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "case_id": self.case_id,
            "status": self.status,
            "writers": [engine.to_data() for engine in self.writers],
            "readers": [engine.to_data() for engine in self.readers],
            "results": [result.to_data() for result in self.results],
        }
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        return data

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
    _validate_selection("writer", writers)
    _validate_selection("reader", readers)
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
        if first.operation == "write" or first.verdict is Verdict.WRITE_ERROR:
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


def _validate_selection(label: str, engines: tuple[EngineVersion, ...]) -> None:
    names = [engine.name for engine in engines]
    if not names or len(names) != len(set(names)):
        raise ValueError(f"matrix {label} selection must be non-empty and unique")


def _validate_write_error(
    result: CellResult,
    writer: EngineVersion,
    writer_profile: profiles.WriterProfileIdentity | None,
) -> None:
    valid = (
        result.writer == writer.name
        and result.writer_version == writer.version
        and result.reader == "*"
        and result.reader_version == "*"
        and result.operation == "write"
        and result.verdict is Verdict.WRITE_ERROR
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
    read_error = result.operation == "read" and result.verdict is Verdict.READ_ERROR
    comparisons = (
        Verdict.PASS,
        Verdict.SCHEMA_MISMATCH,
        Verdict.ROW_COUNT_MISMATCH,
        Verdict.VALUE_MISMATCH,
    )
    compared = result.operation == "compare" and result.verdict in comparisons
    if not engines_match or not (read_error or compared):
        raise ValueError("matrix reader cell conflicts with the declared selection")
