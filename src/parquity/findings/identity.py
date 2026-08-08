from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from ..verdicts import CellResult, FailureFingerprint, Verdict
from ..writer_profiles import WriterProfileIdentity
from . import OPTIONAL_DISCOVERED_CASE, OPTIONAL_INPUT, REQUIRED_ARTIFACTS
from . import json_codec as codec
from .observation import fingerprint_from_data


@dataclass(frozen=True, slots=True)
class ReplaySignature:
    writer: str
    reader: str
    operation: str
    verdict: Verdict
    schema_path: str
    diagnostic_kind: str
    normalized_detail_sha256: str
    writer_profile: WriterProfileIdentity | None = None

    @classmethod
    def from_fingerprint(cls, fingerprint: FailureFingerprint) -> ReplaySignature:
        return cls(
            fingerprint.writer,
            fingerprint.reader,
            fingerprint.operation,
            fingerprint.verdict,
            fingerprint.schema_path,
            fingerprint.diagnostic_kind,
            fingerprint.normalized_detail_sha256,
            fingerprint.writer_profile,
        )

    @classmethod
    def from_result(cls, result: CellResult) -> ReplaySignature:
        fingerprint = result.fingerprint
        if fingerprint is None:
            raise codec.FindingValidationError("a passing result has no replay signature")
        return cls.from_fingerprint(fingerprint)

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "writer": self.writer,
            "reader": self.reader,
            "operation": self.operation,
            "verdict": self.verdict.value,
            "schema_path": self.schema_path,
            "diagnostic_kind": self.diagnostic_kind,
            "normalized_detail_sha256": self.normalized_detail_sha256,
        }
        if self.writer_profile is not None:
            data["writer_profile"] = self.writer_profile.to_data()
        return data

    def related_shape(self) -> tuple[object, ...]:
        shape: tuple[object, ...] = (
            self.writer,
            self.reader,
            self.operation,
            self.verdict,
            self.schema_path,
            self.diagnostic_kind,
        )
        return shape if self.writer_profile is None else (*shape, self.writer_profile)

    @classmethod
    def from_data(
        cls, data: Mapping[str, object], *, allow_profile: bool = False
    ) -> ReplaySignature:
        keys = {
            "writer",
            "reader",
            "operation",
            "verdict",
            "schema_path",
            "diagnostic_kind",
            "normalized_detail_sha256",
        }
        if allow_profile and "writer_profile" in data:
            keys.add("writer_profile")
        codec.require_exact_keys(data, keys, "replay signature")
        reader = codec.string(codec.required(data, "reader"), "reader")
        fingerprint = fingerprint_from_data(
            {
                **data,
                "writer_version": "ignored",
                "reader": reader,
                "reader_version": "*" if reader == "*" else "ignored",
            },
            allow_profile=allow_profile,
        )
        return cls.from_fingerprint(fingerprint)


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    name: str
    sha256: str
    byte_count: int

    def __post_init__(self) -> None:
        allowed = (*REQUIRED_ARTIFACTS, OPTIONAL_DISCOVERED_CASE, OPTIONAL_INPUT)
        if self.name not in allowed:
            raise codec.FindingValidationError("artifact name is not part of the finding format")
        _validate_sha256(self.sha256, "artifact SHA-256")
        if self.byte_count < 0:
            raise codec.FindingValidationError("artifact byte count must not be negative")

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "sha256": self.sha256, "bytes": self.byte_count}

    def matches(self, payload: bytes) -> bool:
        return (
            len(payload) == self.byte_count and hashlib.sha256(payload).hexdigest() == self.sha256
        )

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> ArtifactDigest:
        codec.require_exact_keys(data, {"name", "sha256", "bytes"}, "artifact evidence")
        return cls(
            codec.string(codec.required(data, "name"), "artifact name"),
            codec.string(codec.required(data, "sha256"), "artifact SHA-256"),
            codec.integer(codec.required(data, "bytes"), "artifact byte count"),
        )


def _validate_sha256(value: str, label: str) -> None:
    malformed = len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    if malformed:
        raise codec.FindingValidationError(f"{label} must be a lowercase SHA-256 value")


__all__ = ["ArtifactDigest", "ReplaySignature"]
