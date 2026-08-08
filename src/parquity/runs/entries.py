from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..findings import json_codec as codec
from ..findings.evidence import DISCOVERY_OVERFLOW, FINDING_CAP_REACHED, MINIMIZATION_OVERFLOW
from ..findings.model import finding_id_for
from ..findings.observation import cell_result_from_data, fingerprint_from_data
from ..model import Case
from ..verdicts import CellResult, FailureFingerprint


class RunEntryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RunDigest:
    path: str
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if self.path != "REPORT.md":
            raise RunEntryError("run artifact path is not recognized")
        _validate_sha256(self.sha256, "run artifact SHA-256")
        if self.byte_count < 0:
            raise RunEntryError("run artifact byte count must not be negative")

    def to_data(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "bytes": self.byte_count}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> RunDigest:
        codec.require_exact_keys(data, {"path", "sha256", "bytes"}, "run artifact")
        return cls(
            codec.string(codec.required(data, "path"), "artifact path"),
            codec.string(codec.required(data, "sha256"), "artifact SHA-256"),
            codec.integer(codec.required(data, "bytes"), "artifact byte count"),
        )


@dataclass(frozen=True, slots=True)
class RunFindingIndex:
    finding_id: str
    case_id: str
    fingerprint: FailureFingerprint
    manifest_path: str
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if self.finding_id != finding_id_for(self.case_id, self.fingerprint):
            raise RunEntryError("indexed finding identity does not match its target")
        if self.manifest_path != f"findings/{self.finding_id}/finding.json":
            raise RunEntryError("indexed finding path is not canonical")
        _validate_sha256(self.sha256, "child manifest SHA-256")
        if self.byte_count < 0:
            raise RunEntryError("child manifest byte count must not be negative")

    def to_data(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "fingerprint": self.fingerprint.to_data(),
            "manifest_path": self.manifest_path,
            "sha256": self.sha256,
            "bytes": self.byte_count,
        }

    @classmethod
    def from_data(
        cls, data: Mapping[str, object], *, allow_profile: bool = False
    ) -> RunFindingIndex:
        keys = {"finding_id", "case_id", "fingerprint", "manifest_path", "sha256", "bytes"}
        codec.require_exact_keys(data, keys, "finding index")
        return cls(
            finding_id=codec.string(codec.required(data, "finding_id"), "finding_id"),
            case_id=codec.string(codec.required(data, "case_id"), "case_id"),
            fingerprint=fingerprint_from_data(
                codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
                allow_profile=allow_profile,
            ),
            manifest_path=codec.string(codec.required(data, "manifest_path"), "manifest_path"),
            sha256=codec.string(codec.required(data, "sha256"), "manifest SHA-256"),
            byte_count=codec.integer(codec.required(data, "bytes"), "manifest byte count"),
        )


@dataclass(frozen=True, slots=True)
class OverflowEvidence:
    case: Case
    result: CellResult
    stop_reason: str
    origin: str = DISCOVERY_OVERFLOW

    def __post_init__(self) -> None:
        if self.stop_reason != FINDING_CAP_REACHED:
            raise RunEntryError("overflow stop reason must be FINDING_CAP_REACHED")
        if self.origin not in (DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW):
            raise RunEntryError("overflow origin is not recognized")
        if self.result.fingerprint is None:
            raise RunEntryError("overflow result must be non-passing")

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def fingerprint(self) -> FailureFingerprint:
        value = self.result.fingerprint
        if value is None:
            raise RunEntryError("overflow result must be non-passing")
        return value

    @classmethod
    def from_parts(
        cls,
        case_id: str,
        fingerprint: FailureFingerprint,
        case: Case,
        result: CellResult,
        stop_reason: str,
        origin: str = DISCOVERY_OVERFLOW,
    ) -> OverflowEvidence:
        value = cls(case, result, stop_reason, origin)
        if value.case_id != case_id or value.fingerprint != fingerprint:
            raise RunEntryError("overflow summary conflicts with its typed evidence")
        return value

    def to_data(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "fingerprint": self.fingerprint.to_data(),
            "case": self.case.to_data(),
            "result": self.result.to_data(),
            "stop_reason": self.stop_reason,
            "origin": self.origin,
        }

    @classmethod
    def from_data(
        cls, data: Mapping[str, object], *, allow_profile: bool = False
    ) -> OverflowEvidence:
        codec.require_exact_keys(
            data,
            {"case_id", "fingerprint", "case", "result", "stop_reason", "origin"},
            "overflow evidence",
        )
        case_id = codec.string(codec.required(data, "case_id"), "case_id")
        fingerprint = fingerprint_from_data(
            codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
            allow_profile=allow_profile,
        )
        case = Case.from_data(codec.mapping(codec.required(data, "case"), "overflow Case"))
        result = cell_result_from_data(
            codec.mapping(codec.required(data, "result"), "overflow result"),
            allow_profile=allow_profile,
        )
        return cls.from_parts(
            case_id,
            fingerprint,
            case,
            result,
            codec.string(codec.required(data, "stop_reason"), "stop_reason"),
            codec.string(codec.required(data, "origin"), "overflow origin"),
        )


def _validate_sha256(value: str, label: str) -> None:
    malformed = len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    if malformed:
        raise RunEntryError(f"{label} must be a lowercase SHA-256 value")


__all__ = ["OverflowEvidence", "RunDigest", "RunEntryError", "RunFindingIndex"]
