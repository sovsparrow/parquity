from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ..findings import json_codec as codec
from ..findings.evidence import (
    CHECK_COMPLETE,
    FINDING_CAP_REACHED,
    DiscoveryEvidence,
    EnvironmentEvidence,
    engine_version_from_data,
    provider_inventory_matches,
)
from ..findings.observation import fingerprint_shape_is_valid
from ..verdicts import EngineVersion, FailureFingerprint, Verdict
from ..writer_profiles import WriterProfilePlan
from . import RUN_FORMAT, RUN_STATUS_CAP, RUN_STATUS_FINDINGS
from .entries import OverflowEvidence, RunDigest, RunEntryError, RunFindingIndex

RunValidationError = RunEntryError


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    command: str
    status: str
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    environment: EnvironmentEvidence
    findings: tuple[RunFindingIndex, ...]
    overflow: tuple[OverflowEvidence, ...]
    report: RunDigest
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        _validate_command(self.command, self.discovery)
        if self.writer_profiles is not None:
            self.writer_profiles.validate_writers(self.writers)
        if not provider_inventory_matches(self.writers, self.readers, self.environment.providers):
            raise RunValidationError("environment providers conflict with engine selections")
        if not self.findings:
            raise RunValidationError("a published run requires at least one finding")
        finding_ids = [finding.finding_id for finding in self.findings]
        finding_fingerprints = tuple(finding.fingerprint for finding in self.findings)
        ordered_findings = tuple(
            sorted(finding_fingerprints, key=FailureFingerprint.canonical_bytes)
        )
        if (
            finding_fingerprints != ordered_findings
            or len(finding_ids) != len(set(finding_ids))
            or len(finding_fingerprints) != len(set(finding_fingerprints))
        ):
            raise RunValidationError("run findings must be unique and canonically ordered")
        overflow_fingerprints = tuple(item.fingerprint for item in self.overflow)
        ordered_overflow = tuple(
            sorted(overflow_fingerprints, key=FailureFingerprint.canonical_bytes)
        )
        if overflow_fingerprints != ordered_overflow or len(overflow_fingerprints) != len(
            set(overflow_fingerprints)
        ):
            raise RunValidationError("run overflow must be unique and canonically ordered")
        if set(finding_fingerprints) & set(overflow_fingerprints):
            raise RunValidationError("run findings and overflow must be disjoint")
        fingerprints = (*finding_fingerprints, *overflow_fingerprints)
        if any(
            not _fingerprint_matches_selection(
                item, self.writers, self.readers, self.writer_profiles
            )
            for item in fingerprints
        ):
            raise RunValidationError("run fingerprint conflicts with engine selections")
        expected_status = RUN_STATUS_CAP if self.overflow else RUN_STATUS_FINDINGS
        if self.status != expected_status or (
            bool(self.overflow) != (self.discovery.stop_reason == FINDING_CAP_REACHED)
        ):
            raise RunValidationError("run status conflicts with discovery evidence")
        if self.run_id != calculate_run_id(
            self.command,
            self.status,
            self.writers,
            self.readers,
            self.discovery,
            self.environment,
            self.findings,
            self.overflow,
            self.writer_profiles,
        ):
            raise RunValidationError("run identity does not match its evidence")

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "format": RUN_FORMAT,
            "run_id": self.run_id,
            "command": self.command,
            "status": self.status,
            "writers": [engine.to_data() for engine in self.writers],
            "readers": [engine.to_data() for engine in self.readers],
            "discovery": self.discovery.to_data(),
            "environment": self.environment.to_data(),
            "findings": [finding.to_data() for finding in self.findings],
            "overflow": [item.to_data() for item in self.overflow],
            "report": self.report.to_data(),
        }
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        return data

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.to_data())

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> RunRecord:
        plan = _profile_plan(data)
        keys = {
            "format",
            "run_id",
            "command",
            "status",
            "writers",
            "readers",
            "discovery",
            "environment",
            "findings",
            "overflow",
            "report",
        }
        if plan is not None:
            keys.add("writer_profiles")
        codec.require_exact_keys(
            data,
            keys,
            "run manifest",
        )
        if codec.required(data, "format") != RUN_FORMAT:
            raise RunValidationError(f"run format must be {RUN_FORMAT!r}")
        return cls(
            run_id=codec.string(codec.required(data, "run_id"), "run_id"),
            command=codec.string(codec.required(data, "command"), "command"),
            status=codec.string(codec.required(data, "status"), "status"),
            writers=_engines(data, "writers"),
            readers=_engines(data, "readers"),
            discovery=DiscoveryEvidence.from_data(
                codec.mapping(codec.required(data, "discovery"), "discovery")
            ),
            environment=EnvironmentEvidence.from_data(
                codec.mapping(codec.required(data, "environment"), "environment")
            ),
            findings=tuple(
                RunFindingIndex.from_data(
                    codec.mapping(value, "finding index"), allow_profile=plan is not None
                )
                for value in codec.sequence(codec.required(data, "findings"), "findings")
            ),
            overflow=tuple(
                OverflowEvidence.from_data(
                    codec.mapping(value, "overflow"), allow_profile=plan is not None
                )
                for value in codec.sequence(codec.required(data, "overflow"), "overflow")
            ),
            report=RunDigest.from_data(codec.mapping(codec.required(data, "report"), "report")),
            writer_profiles=plan,
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> RunRecord:
        try:
            decoded = cast(object, json.loads(payload, object_pairs_hook=codec.unique_object))
            return cls.from_data(codec.mapping(decoded, "run"))
        except (codec.FindingValidationError, RunValidationError):
            raise
        except (TypeError, ValueError) as error:
            raise RunValidationError("run.json is malformed") from error


def calculate_run_id(
    command: str,
    status: str,
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    discovery: DiscoveryEvidence,
    environment: EnvironmentEvidence,
    findings: tuple[RunFindingIndex, ...],
    overflow: tuple[OverflowEvidence, ...],
    writer_profiles: WriterProfilePlan | None = None,
) -> str:
    identity = {
        "command": command,
        "status": status,
        "writers": [engine.to_data() for engine in writers],
        "readers": [engine.to_data() for engine in readers],
        "discovery": discovery.to_data(),
        "environment": environment.to_data(),
        "findings": [finding.to_data() for finding in findings],
        "overflow": [item.to_data() for item in overflow],
    }
    if writer_profiles is not None:
        identity["writer_profiles"] = writer_profiles.to_data()
    return hashlib.sha256(_canonical_bytes(identity)).hexdigest()


def _engines(data: Mapping[str, object], key: str) -> tuple[EngineVersion, ...]:
    return tuple(
        engine_version_from_data(codec.mapping(value, key))
        for value in codec.sequence(codec.required(data, key), key)
    )


def _validate_command(command: str, discovery: DiscoveryEvidence) -> None:
    if command not in ("check", "fuzz"):
        raise RunValidationError("run command must be check or fuzz")
    if (command == "check") != (discovery.stop_reason == CHECK_COMPLETE):
        raise RunValidationError("run command conflicts with discovery evidence")


def _fingerprint_matches_selection(
    fingerprint: FailureFingerprint,
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    writer_profiles: WriterProfilePlan | None,
) -> bool:
    if not fingerprint_shape_is_valid(fingerprint):
        return False
    writer_versions = {engine.name: engine.version for engine in writers}
    if writer_versions.get(fingerprint.writer) != fingerprint.writer_version:
        return False
    if writer_profiles is None:
        if fingerprint.writer_profile is not None:
            return False
    elif not any(
        item.writer.name == fingerprint.writer and item.writer_profile == fingerprint.writer_profile
        for item in writer_profiles.executions(writers)
    ):
        return False
    if fingerprint.reader == "*":
        return (
            fingerprint.reader_version == "*"
            and fingerprint.operation == "write"
            and fingerprint.verdict is Verdict.WRITE_ERROR
        )
    reader_versions = {engine.name: engine.version for engine in readers}
    return reader_versions.get(fingerprint.reader) == fingerprint.reader_version


def _profile_plan(data: Mapping[str, object]) -> WriterProfilePlan | None:
    if "writer_profiles" not in data:
        return None
    return WriterProfilePlan.from_data(
        codec.mapping(codec.required(data, "writer_profiles"), "writer_profiles")
    )


def _canonical_bytes(data: Mapping[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


__all__ = [
    "OverflowEvidence",
    "RunDigest",
    "RunFindingIndex",
    "RunRecord",
    "RunValidationError",
    "calculate_run_id",
]
