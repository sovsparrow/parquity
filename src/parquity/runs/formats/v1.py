from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ...evidence import (
    EngineVersion,
    EnvironmentEvidence,
    engine_versions_from_data,
    fingerprint_selection_issue,
    provider_inventory_matches,
    sha256_hex,
)
from ...evidence import json_codec as codec
from ...generation.evidence import (
    CHECK_COMPLETE,
    DISCOVERY_OVERFLOW,
    MINIMIZATION_OVERFLOW,
    SAVED_EVIDENCE_LIMIT_REACHED,
    DiscoveryEvidence,
    stop_reason_from_v1,
    stop_reason_to_v1,
)
from ...model import Case
from ...profiles import WriterProfilePlan, optional_writer_profile_plan_from_data
from ...verdicts import CellResult, FailureFingerprint
from ..source import RunSource
from . import RunDigest, RunFindingIndex, RunValidationError

FORMAT_NAME = "parquity.run.v1"
RUN_STATUS_FINDINGS = "FINDINGS_FOUND"
RUN_STATUS_SAVED_LIMIT = SAVED_EVIDENCE_LIMIT_REACHED


@dataclass(frozen=True, slots=True)
class OverflowEvidence:
    case: Case
    result: CellResult
    stop_reason: str
    origin: str = DISCOVERY_OVERFLOW

    def __post_init__(self) -> None:
        if self.stop_reason != SAVED_EVIDENCE_LIMIT_REACHED:
            raise RunValidationError("overflow stop reason must be SAVED_EVIDENCE_LIMIT_REACHED")
        _validate_exact_evidence(self.result, self.origin, "overflow")

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def fingerprint(self) -> FailureFingerprint:
        return _result_fingerprint(self.result, "overflow")

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
        _validate_exact_summary(value.case_id, value.fingerprint, case_id, fingerprint, "overflow")
        return value

    def to_data(self) -> dict[str, object]:
        data = _exact_evidence_data(self.case, self.result, "overflow")
        data["stop_reason"] = stop_reason_to_v1(self.stop_reason)
        data["origin"] = self.origin
        return data

    @classmethod
    def from_data(
        cls, data: Mapping[str, object], *, allow_profile: bool = False
    ) -> OverflowEvidence:
        codec.require_exact_keys(
            data,
            {"case_id", "fingerprint", "case", "result", "stop_reason", "origin"},
            "overflow evidence",
        )
        case_id, fingerprint, case, result = _exact_evidence_from_data(
            data,
            case_label="overflow Case",
            result_label="overflow result",
            allow_profile=allow_profile,
        )
        return cls.from_parts(
            case_id,
            fingerprint,
            case,
            result,
            stop_reason_from_v1(codec.string(codec.required(data, "stop_reason"), "stop_reason")),
            codec.string(codec.required(data, "origin"), "overflow origin"),
        )


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
            fingerprint_selection_issue(item, self.writers, self.readers, self.writer_profiles)
            is not None
            for item in fingerprints
        ):
            raise RunValidationError("run fingerprint conflicts with engine selections")
        expected_status = status_for_overflow(self.overflow)
        if self.status != expected_status or (
            bool(self.overflow) != (self.discovery.stop_reason == SAVED_EVIDENCE_LIMIT_REACHED)
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
            "format": FORMAT_NAME,
            "run_id": self.run_id,
            "command": self.command,
            "status": stop_reason_to_v1(self.status),
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
        return codec.canonical_bytes(self.to_data())

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> RunRecord:
        plan = optional_writer_profile_plan_from_data(data)
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
        if codec.required(data, "format") != FORMAT_NAME:
            raise RunValidationError(f"run format must be {FORMAT_NAME!r}")
        return cls(
            run_id=codec.string(codec.required(data, "run_id"), "run_id"),
            command=codec.string(codec.required(data, "command"), "command"),
            status=stop_reason_from_v1(codec.string(codec.required(data, "status"), "status")),
            writers=engine_versions_from_data(codec.required(data, "writers"), "writers"),
            readers=engine_versions_from_data(codec.required(data, "readers"), "readers"),
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
            return cls.from_data(codec.mapping(codec.decode(payload), "run"))
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
        "status": stop_reason_to_v1(status),
        "writers": [engine.to_data() for engine in writers],
        "readers": [engine.to_data() for engine in readers],
        "discovery": discovery.to_data(),
        "environment": environment.to_data(),
        "findings": [finding.to_data() for finding in findings],
        "overflow": [item.to_data() for item in overflow],
    }
    if writer_profiles is not None:
        identity["writer_profiles"] = writer_profiles.to_data()
    return sha256_hex(codec.canonical_bytes(identity))


def build_run_record(
    source: RunSource,
    findings: tuple[RunFindingIndex, ...],
    report: RunDigest,
) -> RunRecord:
    overflow = tuple(
        OverflowEvidence(item.case, item.result, SAVED_EVIDENCE_LIMIT_REACHED, item.origin)
        for item in sorted(source.overflow, key=lambda item: item.fingerprint.canonical_bytes())
    )
    status = status_for_overflow(overflow)
    run_id = calculate_run_id(
        source.command,
        status,
        source.writers,
        source.readers,
        source.discovery,
        source.environment,
        findings,
        overflow,
        source.writer_profiles,
    )
    return RunRecord(
        run_id,
        source.command,
        status,
        source.writers,
        source.readers,
        source.discovery,
        source.environment,
        findings,
        overflow,
        report,
        source.writer_profiles,
    )


def status_for_overflow(overflow: tuple[OverflowEvidence, ...]) -> str:
    return RUN_STATUS_SAVED_LIMIT if overflow else RUN_STATUS_FINDINGS


def _validate_command(command: str, discovery: DiscoveryEvidence) -> None:
    if command not in ("check", "fuzz"):
        raise RunValidationError("run command must be check or fuzz")
    if (command == "check") != (discovery.stop_reason == CHECK_COMPLETE):
        raise RunValidationError("run command conflicts with discovery evidence")


def _validate_exact_evidence(result: CellResult, origin: str, label: str) -> None:
    if origin not in (DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW):
        raise RunValidationError(f"{label} origin is not recognized")
    _result_fingerprint(result, label)


def _result_fingerprint(result: CellResult, label: str) -> FailureFingerprint:
    fingerprint = result.fingerprint
    if fingerprint is None:
        raise RunValidationError(f"{label} result must be non-passing")
    return fingerprint


def _validate_exact_summary(
    actual_case_id: str,
    actual_fingerprint: FailureFingerprint,
    case_id: str,
    fingerprint: FailureFingerprint,
    label: str,
) -> None:
    if actual_case_id != case_id or actual_fingerprint != fingerprint:
        raise RunValidationError(f"{label} summary conflicts with its typed evidence")


def _exact_evidence_data(case: Case, result: CellResult, label: str) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "fingerprint": _result_fingerprint(result, label).to_data(),
        "case": case.to_data(),
        "result": result.to_data(),
    }


def _exact_evidence_from_data(
    data: Mapping[str, object],
    *,
    case_label: str,
    result_label: str,
    allow_profile: bool,
) -> tuple[str, FailureFingerprint, Case, CellResult]:
    return (
        codec.string(codec.required(data, "case_id"), "case_id"),
        FailureFingerprint.from_data(
            codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
            allow_profile=allow_profile,
        ),
        Case.from_data(codec.mapping(codec.required(data, "case"), case_label)),
        CellResult.from_data(
            codec.mapping(codec.required(data, "result"), result_label),
            allow_profile=allow_profile,
        ),
    )


__all__ = [
    "FORMAT_NAME",
    "OverflowEvidence",
    "RunDigest",
    "RunFindingIndex",
    "RunRecord",
    "RunValidationError",
    "build_run_record",
    "calculate_run_id",
    "status_for_overflow",
]
