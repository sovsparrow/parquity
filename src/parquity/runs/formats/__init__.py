from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ...evidence import is_sha256
from ...evidence import json_codec as codec
from ...findings.model import finding_id_for
from ...verdicts import FailureFingerprint

RUN_FORMAT_V1 = "parquity.run.v1"
RUN_FORMAT_V2 = "parquity.run.v2"


class RunValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RunDigest:
    path: str
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        if self.path != "REPORT.md":
            raise RunValidationError("run artifact path is not recognized")
        _validate_sha256(self.sha256, "run artifact SHA-256")
        if self.byte_count < 0:
            raise RunValidationError("run artifact byte count must not be negative")

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
            raise RunValidationError("indexed finding identity does not match its target")
        if self.manifest_path != f"findings/{self.finding_id}/finding.json":
            raise RunValidationError("indexed finding path is not canonical")
        _validate_sha256(self.sha256, "child manifest SHA-256")
        if self.byte_count < 0:
            raise RunValidationError("child manifest byte count must not be negative")

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
        cls,
        data: Mapping[str, object],
        *,
        allow_profile: bool = False,
    ) -> RunFindingIndex:
        keys = {"finding_id", "case_id", "fingerprint", "manifest_path", "sha256", "bytes"}
        codec.require_exact_keys(data, keys, "finding index")
        return cls(
            finding_id=codec.string(codec.required(data, "finding_id"), "finding_id"),
            case_id=codec.string(codec.required(data, "case_id"), "case_id"),
            fingerprint=FailureFingerprint.from_data(
                codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
                allow_profile=allow_profile,
            ),
            manifest_path=codec.string(
                codec.required(data, "manifest_path"),
                "manifest_path",
            ),
            sha256=codec.string(codec.required(data, "sha256"), "manifest SHA-256"),
            byte_count=codec.integer(codec.required(data, "bytes"), "manifest byte count"),
        )


def parse_run_record(payload: str | bytes) -> v1.RunRecord | v2.RunRecord:
    try:
        data = codec.mapping(codec.decode(payload), "run")
        format_name = codec.string(codec.required(data, "format"), "format")
        if format_name == RUN_FORMAT_V1:
            return v1.RunRecord.from_data(data)
        if format_name == RUN_FORMAT_V2:
            return v2.RunRecord.from_data(data)
        raise RunValidationError("run format is not recognized")
    except (codec.FindingValidationError, RunValidationError):
        raise
    except (TypeError, ValueError) as error:
        raise RunValidationError("run.json is malformed") from error


def _validate_sha256(value: str, label: str) -> None:
    if not is_sha256(value):
        raise RunValidationError(f"{label} must be a lowercase SHA-256 value")


from . import v1, v2  # noqa: E402 - shared primitives must exist before version imports.

RunRecord = v1.RunRecord | v2.RunRecord

__all__ = [
    "RUN_FORMAT_V1",
    "RUN_FORMAT_V2",
    "RunDigest",
    "RunFindingIndex",
    "RunRecord",
    "RunValidationError",
    "parse_run_record",
    "v1",
    "v2",
]
