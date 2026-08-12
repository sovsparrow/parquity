from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ...evidence import (
    EngineVersion,
    EnvironmentEvidence,
    engine_versions_from_data,
    fingerprint_selection_issue,
    is_sha256,
    provider_inventory_matches,
    sha256_hex,
)
from ...evidence import json_codec as codec
from ...generation.evidence import (
    CHECK_COMPLETE,
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    MINIMIZATION_OVERFLOW,
    SAVED_EVIDENCE_LIMIT_REACHED,
    STRATEGY_EXHAUSTED,
    DiscoveryEvidence,
)
from ...generation.search.identity import FindingKey, finding_key
from ...model import Case
from ...profiles import WriterProfilePlan, optional_writer_profile_plan_from_data
from ...verdicts import CellResult, FailureFingerprint
from ..source import RunV2Source
from . import RunDigest, RunFindingIndex, RunValidationError

FORMAT_NAME = "parquity.run.v2"
FINDING_KEY_FORMAT = "parquity.finding-key.v1"
OCCURRENCE_FORMAT = "parquity.generated-occurrence.v1"
RUN_STATUS_FINDINGS = "FINDINGS_FOUND"


@dataclass(frozen=True, slots=True)
class OccurrenceRecord:
    occurrence_id: str
    case_id: str
    fingerprint: FailureFingerprint
    origin: str

    def __post_init__(self) -> None:
        if not is_sha256(self.case_id):
            raise RunValidationError("occurrence case ID must be a lowercase SHA-256 value")
        if self.origin not in (DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW):
            raise RunValidationError("occurrence origin is not recognized")
        if self.occurrence_id != occurrence_id_for(self.case_id, self.fingerprint):
            raise RunValidationError("occurrence identity does not match its exact target")

    @property
    def key(self) -> FindingKey:
        return finding_key(self.fingerprint)

    @property
    def target(self) -> tuple[str, FailureFingerprint]:
        return self.case_id, self.fingerprint

    def to_data(self) -> dict[str, object]:
        return {
            "occurrence_format": OCCURRENCE_FORMAT,
            "occurrence_id": self.occurrence_id,
            "case_id": self.case_id,
            "fingerprint": self.fingerprint.to_data(),
            "origin": self.origin,
        }

    @classmethod
    def from_data(
        cls,
        data: Mapping[str, object],
        *,
        allow_profile: bool = False,
    ) -> OccurrenceRecord:
        codec.require_exact_keys(
            data,
            {"occurrence_format", "occurrence_id", "case_id", "fingerprint", "origin"},
            "generated occurrence",
        )
        if codec.required(data, "occurrence_format") != OCCURRENCE_FORMAT:
            raise RunValidationError(f"occurrence format must be {OCCURRENCE_FORMAT!r}")
        return cls(
            codec.string(codec.required(data, "occurrence_id"), "occurrence_id"),
            codec.string(codec.required(data, "case_id"), "occurrence case_id"),
            FailureFingerprint.from_data(
                codec.mapping(codec.required(data, "fingerprint"), "occurrence fingerprint"),
                allow_profile=allow_profile,
            ),
            codec.string(codec.required(data, "origin"), "occurrence origin"),
        )


@dataclass(frozen=True, slots=True)
class ManifestOnlyEvidence:
    case: Case
    result: CellResult
    stop_reason: str
    origin: str = DISCOVERY_OVERFLOW

    def __post_init__(self) -> None:
        if self.stop_reason != SAVED_EVIDENCE_LIMIT_REACHED:
            raise RunValidationError(
                "manifest-only stop reason must be SAVED_EVIDENCE_LIMIT_REACHED"
            )
        if self.origin not in (DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW):
            raise RunValidationError("manifest-only origin is not recognized")
        _result_fingerprint(self.result, "manifest-only")

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def fingerprint(self) -> FailureFingerprint:
        return _result_fingerprint(self.result, "manifest-only")

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
        cls,
        data: Mapping[str, object],
        *,
        allow_profile: bool = False,
    ) -> ManifestOnlyEvidence:
        codec.require_exact_keys(
            data,
            {"case_id", "fingerprint", "case", "result", "stop_reason", "origin"},
            "manifest-only evidence",
        )
        case_id = codec.string(codec.required(data, "case_id"), "manifest-only case_id")
        fingerprint = FailureFingerprint.from_data(
            codec.mapping(
                codec.required(data, "fingerprint"),
                "manifest-only fingerprint",
            ),
            allow_profile=allow_profile,
        )
        case = Case.from_data(codec.mapping(codec.required(data, "case"), "manifest-only Case"))
        result = CellResult.from_data(
            codec.mapping(codec.required(data, "result"), "manifest-only result"),
            allow_profile=allow_profile,
        )
        value = cls(
            case,
            result,
            codec.string(
                codec.required(data, "stop_reason"),
                "manifest-only stop_reason",
            ),
            codec.string(codec.required(data, "origin"), "manifest-only origin"),
        )
        if value.case_id != case_id or value.fingerprint != fingerprint:
            raise RunValidationError(
                "manifest-only summary conflicts with its exact representative"
            )
        return value


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    command: str
    status: str
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    evaluated_inputs: int
    executed_checks: int
    environment: EnvironmentEvidence
    saved_evidence: tuple[RunFindingIndex, ...]
    manifest_only_evidence: tuple[ManifestOnlyEvidence, ...]
    occurrences: tuple[OccurrenceRecord, ...]
    report: RunDigest
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        _validate_command(self.command, self.discovery)
        _validate_execution_counts(
            self.command,
            self.discovery,
            self.evaluated_inputs,
            self.executed_checks,
        )
        if self.writer_profiles is not None:
            self.writer_profiles.validate_writers(self.writers)
        if not provider_inventory_matches(self.writers, self.readers, self.environment.providers):
            raise RunValidationError("environment providers conflict with engine selections")
        if not self.findings:
            raise RunValidationError("a published run requires at least one saved finding")
        saved_keys = self._validate_findings()
        overflow_keys = self._validate_overflow()
        if set(saved_keys) & set(overflow_keys):
            raise RunValidationError(
                "saved and manifest-only representative finding keys must be disjoint"
            )
        representative_keys = set(saved_keys) | set(overflow_keys)
        self._validate_occurrences(representative_keys)
        fingerprints = tuple(item.fingerprint for item in self.findings)
        fingerprints += tuple(item.fingerprint for item in self.overflow)
        fingerprints += tuple(item.fingerprint for item in self.occurrences)
        if any(
            fingerprint_selection_issue(
                item,
                self.writers,
                self.readers,
                self.writer_profiles,
            )
            is not None
            for item in fingerprints
        ):
            raise RunValidationError("run fingerprint conflicts with engine selections")
        expected_status = SAVED_EVIDENCE_LIMIT_REACHED if self.overflow else RUN_STATUS_FINDINGS
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
            self.evaluated_inputs,
            self.executed_checks,
            self.environment,
            self.findings,
            self.overflow,
            self.occurrences,
            self.writer_profiles,
        ):
            raise RunValidationError("run identity does not match its evidence")

    @property
    def findings(self) -> tuple[RunFindingIndex, ...]:
        return self.saved_evidence

    @property
    def overflow(self) -> tuple[ManifestOnlyEvidence, ...]:
        return self.manifest_only_evidence

    def _validate_findings(self) -> tuple[FindingKey, ...]:
        finding_ids = tuple(item.finding_id for item in self.findings)
        keys = tuple(finding_key(item.fingerprint) for item in self.findings)
        if (
            keys != tuple(sorted(keys))
            or len(keys) != len(set(keys))
            or len(finding_ids) != len(set(finding_ids))
        ):
            raise RunValidationError(
                "saved representative finding keys must be unique and canonically ordered"
            )
        return keys

    def _validate_overflow(self) -> tuple[FindingKey, ...]:
        keys = tuple(finding_key(item.fingerprint) for item in self.overflow)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise RunValidationError(
                "manifest-only representative finding keys must be unique and canonically ordered"
            )
        return keys

    def _validate_occurrences(self, representative_keys: set[FindingKey]) -> None:
        if not self.occurrences:
            raise RunValidationError("run.v2 requires generated occurrence evidence")
        occurrence_ids = tuple(item.occurrence_id for item in self.occurrences)
        targets = tuple(item.target for item in self.occurrences)
        if occurrence_ids != tuple(sorted(occurrence_ids)) or len(occurrence_ids) != len(
            set(occurrence_ids)
        ):
            raise RunValidationError("occurrences must have unique canonically ordered IDs")
        if len(targets) != len(set(targets)):
            raise RunValidationError("occurrence exact targets must be unique")
        manifest_targets = {
            (item.case_id, item.fingerprint) for item in self.manifest_only_evidence
        }
        if not manifest_targets <= set(targets):
            raise RunValidationError(
                "manifest-only representative exact targets must be occurrences"
            )
        if {item.key for item in self.occurrences} != representative_keys:
            raise RunValidationError(
                "saved and manifest-only representatives must partition occurrences"
            )
        discovery_keys = {
            item.key for item in self.occurrences if item.origin == DISCOVERY_OVERFLOW
        }
        minimized_keys = tuple(
            item.key for item in self.occurrences if item.origin == MINIMIZATION_OVERFLOW
        )
        if len(minimized_keys) != len(set(minimized_keys)) or discovery_keys & set(minimized_keys):
            raise RunValidationError(
                "minimization occurrences must introduce unique sibling finding keys"
            )

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "format": FORMAT_NAME,
            "finding_key_format": FINDING_KEY_FORMAT,
            "run_id": self.run_id,
            "command": self.command,
            "status": self.status,
            "writers": [engine.to_data() for engine in self.writers],
            "readers": [engine.to_data() for engine in self.readers],
            "discovery": _discovery_data(self.discovery),
            "evaluated_inputs": self.evaluated_inputs,
            "executed_checks": self.executed_checks,
            "environment": self.environment.to_data(),
            "saved_evidence": [finding.to_data() for finding in self.saved_evidence],
            "manifest_only_evidence": [item.to_data() for item in self.manifest_only_evidence],
            "occurrences": [item.to_data() for item in self.occurrences],
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
            "finding_key_format",
            "run_id",
            "command",
            "status",
            "writers",
            "readers",
            "discovery",
            "evaluated_inputs",
            "executed_checks",
            "environment",
            "saved_evidence",
            "manifest_only_evidence",
            "occurrences",
            "report",
        }
        if plan is not None:
            keys.add("writer_profiles")
        codec.require_exact_keys(data, keys, "run.v2 manifest")
        if codec.required(data, "format") != FORMAT_NAME:
            raise RunValidationError(f"run format must be {FORMAT_NAME!r}")
        if codec.required(data, "finding_key_format") != FINDING_KEY_FORMAT:
            raise RunValidationError(f"finding key format must be {FINDING_KEY_FORMAT!r}")
        evaluated_inputs = codec.integer(
            codec.required(data, "evaluated_inputs"),
            "evaluated_inputs",
        )
        executed_checks = codec.integer(
            codec.required(data, "executed_checks"),
            "executed_checks",
        )
        return cls(
            run_id=codec.string(codec.required(data, "run_id"), "run_id"),
            command=codec.string(codec.required(data, "command"), "command"),
            status=codec.string(codec.required(data, "status"), "status"),
            writers=engine_versions_from_data(codec.required(data, "writers"), "writers"),
            readers=engine_versions_from_data(codec.required(data, "readers"), "readers"),
            discovery=_discovery_from_data(
                codec.mapping(codec.required(data, "discovery"), "discovery"),
                evaluated_inputs,
                executed_checks,
            ),
            evaluated_inputs=evaluated_inputs,
            executed_checks=executed_checks,
            environment=EnvironmentEvidence.from_data(
                codec.mapping(codec.required(data, "environment"), "environment")
            ),
            saved_evidence=tuple(
                RunFindingIndex.from_data(
                    codec.mapping(value, "finding index"),
                    allow_profile=plan is not None,
                )
                for value in codec.sequence(
                    codec.required(data, "saved_evidence"),
                    "saved_evidence",
                )
            ),
            manifest_only_evidence=tuple(
                ManifestOnlyEvidence.from_data(
                    codec.mapping(value, "manifest-only evidence"),
                    allow_profile=plan is not None,
                )
                for value in codec.sequence(
                    codec.required(data, "manifest_only_evidence"),
                    "manifest_only_evidence",
                )
            ),
            occurrences=tuple(
                OccurrenceRecord.from_data(
                    codec.mapping(value, "generated occurrence"),
                    allow_profile=plan is not None,
                )
                for value in codec.sequence(codec.required(data, "occurrences"), "occurrences")
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


def occurrence_id_for(case_id: str, fingerprint: FailureFingerprint) -> str:
    if not is_sha256(case_id):
        raise RunValidationError("occurrence case ID must be a lowercase SHA-256 value")
    identity = {
        "occurrence_format": OCCURRENCE_FORMAT,
        "case_id": case_id,
        "fingerprint": fingerprint.to_data(),
    }
    return sha256_hex(codec.canonical_bytes(identity))


def calculate_run_id(
    command: str,
    status: str,
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    discovery: DiscoveryEvidence,
    evaluated_inputs: int,
    executed_checks: int,
    environment: EnvironmentEvidence,
    saved_evidence: tuple[RunFindingIndex, ...],
    manifest_only_evidence: tuple[ManifestOnlyEvidence, ...],
    occurrences: tuple[OccurrenceRecord, ...],
    writer_profiles: WriterProfilePlan | None = None,
) -> str:
    identity: dict[str, object] = {
        "format": FORMAT_NAME,
        "finding_key_format": FINDING_KEY_FORMAT,
        "command": command,
        "status": status,
        "writers": [engine.to_data() for engine in writers],
        "readers": [engine.to_data() for engine in readers],
        "discovery": _discovery_data(discovery),
        "evaluated_inputs": evaluated_inputs,
        "executed_checks": executed_checks,
        "environment": environment.to_data(),
        "saved_evidence": [finding.to_data() for finding in saved_evidence],
        "manifest_only_evidence": [item.to_data() for item in manifest_only_evidence],
        "occurrences": [item.to_data() for item in occurrences],
    }
    if writer_profiles is not None:
        identity["writer_profiles"] = writer_profiles.to_data()
    return sha256_hex(codec.canonical_bytes(identity))


def build_run_record(
    source: RunV2Source,
    findings: tuple[RunFindingIndex, ...],
    report: RunDigest,
) -> RunRecord:
    evaluated_inputs = source.evaluated_inputs
    executed_checks = source.executed_checks
    saved_evidence = tuple(sorted(findings, key=lambda item: finding_key(item.fingerprint)))
    manifest_only_evidence = tuple(
        ManifestOnlyEvidence(
            item.case,
            item.result,
            SAVED_EVIDENCE_LIMIT_REACHED,
            item.origin,
        )
        for item in sorted(source.overflow, key=lambda item: finding_key(item.fingerprint))
    )
    occurrences = tuple(
        sorted(
            (
                OccurrenceRecord(
                    occurrence_id_for(item.case_id, item.fingerprint),
                    item.case_id,
                    item.fingerprint,
                    item.origin,
                )
                for item in source.occurrences
            ),
            key=lambda item: item.occurrence_id,
        )
    )
    status = SAVED_EVIDENCE_LIMIT_REACHED if manifest_only_evidence else RUN_STATUS_FINDINGS
    run_id = calculate_run_id(
        source.command,
        status,
        source.writers,
        source.readers,
        source.discovery,
        evaluated_inputs,
        executed_checks,
        source.environment,
        saved_evidence,
        manifest_only_evidence,
        occurrences,
        source.writer_profiles,
    )
    return RunRecord(
        run_id,
        source.command,
        status,
        source.writers,
        source.readers,
        source.discovery,
        evaluated_inputs,
        executed_checks,
        source.environment,
        saved_evidence,
        manifest_only_evidence,
        occurrences,
        report,
        source.writer_profiles,
    )


def _discovery_data(value: DiscoveryEvidence) -> dict[str, object]:
    return {
        "examples": value.examples,
        "seed": value.seed,
        "max_saved": value.max_saved,
        "stop_reason": value.stop_reason,
    }


def _discovery_from_data(
    data: Mapping[str, object],
    evaluated_inputs: int,
    executed_checks: int,
) -> DiscoveryEvidence:
    keys = {"examples", "seed", "max_saved", "stop_reason"}
    codec.require_exact_keys(data, keys, "run.v2 discovery evidence")
    stop_reason = codec.string(codec.required(data, "stop_reason"), "stop_reason")
    return DiscoveryEvidence(
        codec.optional_integer(codec.required(data, "examples"), "examples"),
        codec.optional_integer(codec.required(data, "seed"), "seed"),
        codec.optional_integer(codec.required(data, "max_saved"), "max_saved"),
        stop_reason,
        None if stop_reason == CHECK_COMPLETE else evaluated_inputs,
        None if stop_reason == CHECK_COMPLETE else executed_checks,
    )


def _validate_execution_counts(
    command: str,
    discovery: DiscoveryEvidence,
    evaluated_inputs: int,
    executed_checks: int,
) -> None:
    if isinstance(evaluated_inputs, bool) or isinstance(executed_checks, bool):
        raise RunValidationError("run execution counts must be integers")
    if evaluated_inputs < 1 or executed_checks < evaluated_inputs:
        raise RunValidationError("run execution counts are invalid")
    if command == "check":
        if evaluated_inputs != 1:
            raise RunValidationError("check run must bind one evaluated input")
        return
    discovery_counts = discovery.evaluated_cases, discovery.evaluated_cells
    if discovery_counts != (evaluated_inputs, executed_checks):
        raise RunValidationError("fuzz execution counts conflict with discovery evidence")
    bound = discovery.examples
    if discovery.stop_reason == EXAMPLE_BOUND_REACHED and evaluated_inputs != bound:
        raise RunValidationError("example-bound stop requires the full requested bound")
    if discovery.stop_reason == STRATEGY_EXHAUSTED and (bound is None or evaluated_inputs >= bound):
        raise RunValidationError("strategy exhaustion requires fewer evaluated inputs")


def _result_fingerprint(result: CellResult, label: str) -> FailureFingerprint:
    fingerprint = result.fingerprint
    if fingerprint is None:
        raise RunValidationError(f"{label} result must be non-passing")
    return fingerprint


def _validate_command(command: str, discovery: DiscoveryEvidence) -> None:
    if command not in ("check", "fuzz"):
        raise RunValidationError("run command must be check or fuzz")
    if (command == "check") != (discovery.stop_reason == CHECK_COMPLETE):
        raise RunValidationError("run command conflicts with discovery evidence")
