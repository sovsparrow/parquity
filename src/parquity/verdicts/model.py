from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Self, cast

from .. import evidence
from ..evidence import DifferenceEvidence, json_codec
from ..profiles import WriterProfileIdentity

if TYPE_CHECKING:
    from .. import profiles


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 - public verdict label, not a password.
    WRITE_ERROR = "WRITE_ERROR"
    READ_ERROR = "READ_ERROR"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    ROW_COUNT_MISMATCH = "ROW_COUNT_MISMATCH"
    VALUE_MISMATCH = "VALUE_MISMATCH"


class _FingerprintShapeError(ValueError):
    pass


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
        verdict = cast(object, self.verdict)
        profile = cast(object, self.writer_profile)
        values = (self.writer, self.writer_version, self.reader, self.reader_version)
        values += (self.operation, self.schema_path, self.diagnostic_kind)
        if any(not _canonical_text(value, "fingerprint field") for value in values):
            raise ValueError("fingerprint fields must not be empty")
        if not isinstance(verdict, Verdict):
            raise ValueError("fingerprint verdict must be a Verdict")
        if profile is not None and not isinstance(profile, WriterProfileIdentity):
            raise ValueError("fingerprint writer profile is malformed")
        if not evidence.is_sha256(self.normalized_detail_sha256):
            raise ValueError("normalized detail SHA-256 is malformed")
        if not _outcome_shape_is_valid(
            self.operation,
            self.verdict,
            self.reader,
            self.reader_version,
            allow_pass=False,
        ):
            raise _FingerprintShapeError("fingerprint fields conflict")

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
        return json_codec.canonical_bytes(self.to_data())

    @classmethod
    def from_data(
        cls, data: Mapping[str, object], *, allow_profile: bool = False
    ) -> FailureFingerprint:
        keys = {
            "writer",
            "writer_version",
            "reader",
            "reader_version",
            "operation",
            "verdict",
            "schema_path",
            "diagnostic_kind",
            "normalized_detail_sha256",
        }
        profile = _profile_from_data(data, keys, allow_profile, "failure fingerprint")
        try:
            return cls(
                writer=json_codec.string(json_codec.required(data, "writer"), "writer"),
                writer_version=json_codec.string(
                    json_codec.required(data, "writer_version"), "writer_version"
                ),
                reader=json_codec.string(json_codec.required(data, "reader"), "reader"),
                reader_version=json_codec.string(
                    json_codec.required(data, "reader_version"), "reader_version"
                ),
                operation=json_codec.string(json_codec.required(data, "operation"), "operation"),
                verdict=_verdict(json_codec.required(data, "verdict")),
                schema_path=json_codec.string(
                    json_codec.required(data, "schema_path"), "schema_path"
                ),
                diagnostic_kind=json_codec.string(
                    json_codec.required(data, "diagnostic_kind"), "diagnostic_kind"
                ),
                normalized_detail_sha256=json_codec.string(
                    json_codec.required(data, "normalized_detail_sha256"),
                    "normalized detail SHA-256",
                ),
                writer_profile=profile,
            )
        except _FingerprintShapeError as error:
            raise json_codec.FindingValidationError(
                "failure fingerprint fields conflict"
            ) from error
        except ValueError as error:
            raise json_codec.FindingValidationError("failure fingerprint is malformed") from error


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
        verdict = cast(object, self.verdict)
        profile = cast(object, self.writer_profile)
        difference = cast(object, self.difference)
        values = (self.writer, self.writer_version, self.reader, self.reader_version)
        values += (self.operation, self.schema_path)
        if any(not _canonical_text(value, "result field") for value in values):
            raise ValueError("result fields must not be empty")
        if not isinstance(verdict, Verdict):
            raise ValueError("result verdict must be a Verdict")
        if profile is not None and not isinstance(profile, WriterProfileIdentity):
            raise ValueError("result writer profile is malformed")
        if difference is not None and not isinstance(difference, DifferenceEvidence):
            raise ValueError("result difference evidence is malformed")
        _canonical_text(self.detail, "result detail")
        _canonical_text(self.diagnostic_kind, "result diagnostic kind")
        if not self.diagnostic_kind:
            object.__setattr__(self, "diagnostic_kind", self.verdict.value)
        object.__setattr__(self, "detail", evidence.normalize_detail(self.detail))
        if not _outcome_shape_is_valid(
            self.operation,
            self.verdict,
            self.reader,
            self.reader_version,
            allow_pass=True,
        ):
            raise ValueError("result fields conflict")
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
            normalized_detail_sha256=evidence.sha256_hex(self.detail.encode("utf-8")),
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
        detail = evidence.normalize_detail(self.detail, transient_roots)
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

    @classmethod
    def from_data(cls, data: Mapping[str, object], *, allow_profile: bool = False) -> CellResult:
        keys = {
            "writer",
            "writer_version",
            "reader",
            "reader_version",
            "operation",
            "verdict",
            "schema_path",
            "detail",
            "diagnostic_kind",
        }
        difference = None
        if "difference" in data:
            keys.add("difference")
            try:
                difference = DifferenceEvidence.from_data(
                    json_codec.mapping(json_codec.required(data, "difference"), "difference")
                )
            except ValueError as error:
                raise json_codec.FindingValidationError(
                    "difference evidence is malformed"
                ) from error
        profile = _profile_from_data(data, keys, allow_profile, "matrix result")
        try:
            return cls(
                writer=json_codec.string(json_codec.required(data, "writer"), "writer"),
                writer_version=json_codec.string(
                    json_codec.required(data, "writer_version"), "writer_version"
                ),
                reader=json_codec.string(json_codec.required(data, "reader"), "reader"),
                reader_version=json_codec.string(
                    json_codec.required(data, "reader_version"), "reader_version"
                ),
                operation=json_codec.string(json_codec.required(data, "operation"), "operation"),
                verdict=_verdict(json_codec.required(data, "verdict")),
                schema_path=json_codec.string(
                    json_codec.required(data, "schema_path"), "schema_path"
                ),
                detail=json_codec.string(json_codec.required(data, "detail"), "detail"),
                diagnostic_kind=json_codec.string(
                    json_codec.required(data, "diagnostic_kind"), "diagnostic_kind"
                ),
                writer_profile=profile,
                difference=difference,
            )
        except ValueError as error:
            raise json_codec.FindingValidationError("matrix result is malformed") from error


def _outcome_shape_is_valid(
    operation: str,
    verdict: Verdict,
    reader: str,
    reader_version: str,
    *,
    allow_pass: bool,
) -> bool:
    if operation == "write":
        return verdict is Verdict.WRITE_ERROR and (reader, reader_version) == ("*", "*")
    if reader == "*" or reader_version == "*":
        return False
    if operation == "read":
        return verdict is Verdict.READ_ERROR
    comparisons = {
        Verdict.SCHEMA_MISMATCH,
        Verdict.ROW_COUNT_MISMATCH,
        Verdict.VALUE_MISMATCH,
    }
    if allow_pass:
        comparisons.add(Verdict.PASS)
    return operation == "compare" and verdict in comparisons


def _profile_from_data(
    data: Mapping[str, object],
    base_keys: set[str],
    allow_profile: bool,
    label: str,
) -> WriterProfileIdentity | None:
    has_profile = "writer_profile" in data
    if has_profile and not allow_profile:
        json_codec.require_exact_keys(data, base_keys, label)
    expected = set(base_keys)
    if has_profile:
        expected.add("writer_profile")
    json_codec.require_exact_keys(data, expected, label)
    if not has_profile:
        return None
    return WriterProfileIdentity.from_data(
        json_codec.mapping(json_codec.required(data, "writer_profile"), "writer_profile")
    )


def _verdict(value: object) -> Verdict:
    try:
        return Verdict(json_codec.string(value, "verdict"))
    except ValueError as error:
        raise json_codec.FindingValidationError("verdict is not recognized") from error


def _canonical_text(value: object, label: str) -> str:
    try:
        return json_codec.string(value, label)
    except json_codec.EvidenceValidationError as error:
        raise ValueError(str(error)) from error


__all__ = [
    "CellResult",
    "FailureFingerprint",
    "Verdict",
]
