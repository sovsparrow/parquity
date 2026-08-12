from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..evidence import (
    EngineVersion,
    EnvironmentEvidence,
    FingerprintSelectionIssue,
    digest_matches,
    engine_selection_is_valid,
    engine_versions_from_data,
    fingerprint_selection_issue,
    is_sha256,
    provider_inventory_matches,
    sha256_hex,
)
from ..evidence import json_codec as codec
from ..generation.evidence import (
    CHECK_COMPLETE,
    DiscoveryEvidence,
    GenerationEvidence,
)
from ..profiles import (
    WriterProfileIdentity,
    WriterProfilePlan,
    optional_writer_profile_plan_from_data,
)
from ..verdicts import CellResult, FailureFingerprint, Verdict
from . import FINDING_FORMAT, OPTIONAL_DISCOVERED_CASE, OPTIONAL_INPUT, REQUIRED_ARTIFACTS

FindingValidationError = codec.FindingValidationError


@dataclass(frozen=True, slots=True)
class ReplaySignature:
    """Compatibility view stored by the immutable finding-v1 schema."""

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
            raise FindingValidationError("a passing result has no replay signature")
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
        fingerprint = FailureFingerprint.from_data(
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
            raise FindingValidationError("artifact name is not part of the finding format")
        _validate_sha256(self.sha256, "artifact SHA-256")
        if self.byte_count < 0:
            raise FindingValidationError("artifact byte count must not be negative")

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "sha256": self.sha256, "bytes": self.byte_count}

    def matches(self, payload: bytes) -> bool:
        return digest_matches(payload, self.sha256, self.byte_count)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> ArtifactDigest:
        codec.require_exact_keys(data, {"name", "sha256", "bytes"}, "artifact evidence")
        return cls(
            codec.string(codec.required(data, "name"), "artifact name"),
            codec.string(codec.required(data, "sha256"), "artifact SHA-256"),
            codec.integer(codec.required(data, "bytes"), "artifact byte count"),
        )


@dataclass(frozen=True, slots=True)
class ReductionEvidence:
    discovered_case_id: str
    minimized_case_id: str
    hypothesis_reduced: bool
    fields: int
    rows: int
    nullability: int
    containers: int
    scalars: int

    def __post_init__(self) -> None:
        _validate_sha256(self.discovered_case_id, "discovered Case identity")
        _validate_sha256(self.minimized_case_id, "minimized Case identity")
        counts = (self.fields, self.rows, self.nullability, self.containers, self.scalars)
        if any(isinstance(value, bool) or value < 0 for value in counts):
            raise FindingValidationError("reduction counts must not be negative")

    @property
    def total(self) -> int:
        return self.fields + self.rows + self.nullability + self.containers + self.scalars

    def to_data(self) -> dict[str, object]:
        return {
            "discovered_case_id": self.discovered_case_id,
            "minimized_case_id": self.minimized_case_id,
            "hypothesis_reduced": self.hypothesis_reduced,
            "successful_reductions": {
                "fields": self.fields,
                "rows": self.rows,
                "nullability": self.nullability,
                "containers": self.containers,
                "scalars": self.scalars,
                "total": self.total,
            },
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> ReductionEvidence:
        keys = {
            "discovered_case_id",
            "minimized_case_id",
            "hypothesis_reduced",
            "successful_reductions",
        }
        codec.require_exact_keys(data, keys, "reduction evidence")
        counts = codec.mapping(codec.required(data, "successful_reductions"), "reductions")
        codec.require_exact_keys(
            counts,
            {"fields", "rows", "nullability", "containers", "scalars", "total"},
            "counts",
        )
        result = cls(
            codec.string(codec.required(data, "discovered_case_id"), "discovered_case_id"),
            codec.string(codec.required(data, "minimized_case_id"), "minimized_case_id"),
            codec.boolean(codec.required(data, "hypothesis_reduced"), "hypothesis_reduced"),
            codec.integer(codec.required(counts, "fields"), "fields"),
            codec.integer(codec.required(counts, "rows"), "rows"),
            codec.integer(codec.required(counts, "nullability"), "nullability"),
            codec.integer(codec.required(counts, "containers"), "containers"),
            codec.integer(codec.required(counts, "scalars"), "scalars"),
        )
        if codec.integer(codec.required(counts, "total"), "total") != result.total:
            raise FindingValidationError("reduction total does not match its categories")
        return result


@dataclass(frozen=True, slots=True)
class FindingRecord:
    finding_id: str
    case_id: str
    command: str
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    environment: EnvironmentEvidence
    reduction: ReductionEvidence
    fingerprint: FailureFingerprint
    replay_signature: ReplaySignature
    result: CellResult
    input_parquet: bool
    artifacts: tuple[ArtifactDigest, ...]
    generation: GenerationEvidence | None = None
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        _validate_sha256(self.case_id, "case_id")
        if self.finding_id != finding_id_for(self.case_id, self.fingerprint):
            raise FindingValidationError("finding identifier does not match its target")
        if self.command not in ("check", "fuzz"):
            raise FindingValidationError("finding command must be check or fuzz")
        if (self.command == "check") != (self.discovery.stop_reason == CHECK_COMPLETE):
            raise FindingValidationError("finding command conflicts with discovery evidence")
        _validate_generation(self)
        _validate_engine_sets(self.writers, self.readers)
        if self.writer_profiles is not None:
            self.writer_profiles.validate_writers(self.writers)
        if not provider_inventory_matches(self.writers, self.readers, self.environment.providers):
            raise FindingValidationError("environment providers conflict with engine selections")
        if self.replay_signature != ReplaySignature.from_fingerprint(self.fingerprint):
            raise FindingValidationError("replay signature conflicts with the fingerprint")
        if self.result.fingerprint != self.fingerprint:
            raise FindingValidationError("selected result conflicts with the fingerprint")
        if self.reduction.minimized_case_id != self.case_id:
            raise FindingValidationError("reduction evidence conflicts with the final Case")
        _validate_target_selection(self)
        expected_input = self.fingerprint.operation != "write"
        if self.input_parquet != expected_input:
            raise FindingValidationError("input.parquet presence conflicts with the operation")
        _validate_artifact_inventory(self)

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "format": FINDING_FORMAT,
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "command": self.command,
            "writers": [engine.to_data() for engine in self.writers],
            "readers": [engine.to_data() for engine in self.readers],
            "discovery": self.discovery.to_data(),
            "environment": self.environment.to_data(),
            "reduction": self.reduction.to_data(),
            "fingerprint": self.fingerprint.to_data(),
            "replay_signature": self.replay_signature.to_data(),
            "result": self.result.to_data(),
            "input_parquet": self.input_parquet,
            "artifacts": [artifact.to_data() for artifact in self.artifacts],
        }
        if self.generation is not None:
            data["generation"] = self.generation.to_data()
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        return data

    def canonical_bytes(self) -> bytes:
        return codec.canonical_bytes(self.to_data())

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> FindingRecord:
        plan = optional_writer_profile_plan_from_data(data)
        if codec.required(data, "format") != FINDING_FORMAT:
            raise FindingValidationError(f"finding format must be {FINDING_FORMAT!r}")
        return cls(
            finding_id=codec.string(codec.required(data, "finding_id"), "finding_id"),
            case_id=codec.string(codec.required(data, "case_id"), "case_id"),
            command=codec.string(codec.required(data, "command"), "command"),
            writers=engine_versions_from_data(codec.required(data, "writers"), "writers"),
            readers=engine_versions_from_data(codec.required(data, "readers"), "readers"),
            discovery=DiscoveryEvidence.from_data(
                codec.mapping(codec.required(data, "discovery"), "discovery")
            ),
            environment=EnvironmentEvidence.from_data(
                codec.mapping(codec.required(data, "environment"), "environment")
            ),
            reduction=ReductionEvidence.from_data(
                codec.mapping(codec.required(data, "reduction"), "reduction")
            ),
            fingerprint=FailureFingerprint.from_data(
                codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
                allow_profile=plan is not None,
            ),
            replay_signature=ReplaySignature.from_data(
                codec.mapping(codec.required(data, "replay_signature"), "replay signature"),
                allow_profile=plan is not None,
            ),
            result=CellResult.from_data(
                codec.mapping(codec.required(data, "result"), "result"),
                allow_profile=plan is not None,
            ),
            input_parquet=codec.boolean(codec.required(data, "input_parquet"), "input_parquet"),
            artifacts=tuple(
                ArtifactDigest.from_data(codec.mapping(value, "artifact"))
                for value in codec.sequence(codec.required(data, "artifacts"), "artifacts")
            ),
            generation=_generation_from_data(data),
            writer_profiles=plan,
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> FindingRecord:
        try:
            return cls.from_data(codec.mapping(codec.decode(payload), "finding"))
        except FindingValidationError:
            raise
        except (TypeError, ValueError) as error:
            raise FindingValidationError("finding.json is malformed") from error


def finding_id_for(case_id: str, fingerprint: FailureFingerprint) -> str:
    _validate_sha256(case_id, "case_id")
    identity = codec.canonical_bytes({"case_id": case_id, "fingerprint": fingerprint.to_data()})
    return sha256_hex(identity)


def _generation_from_data(data: Mapping[str, object]) -> GenerationEvidence | None:
    if "generation" not in data:
        return None
    return GenerationEvidence.from_data(
        codec.mapping(codec.required(data, "generation"), "generation")
    )


def _validate_generation(finding: FindingRecord) -> None:
    if finding.command == "check" and finding.generation is not None:
        raise FindingValidationError("check findings cannot declare generation evidence")
    reductions = finding.reduction
    if finding.generation is not None and (reductions.fields or reductions.nullability):
        raise FindingValidationError("schema generation cannot declare schema reductions")


def _validate_target_selection(finding: FindingRecord) -> None:
    issue = fingerprint_selection_issue(
        finding.fingerprint,
        finding.writers,
        finding.readers,
        finding.writer_profiles,
    )
    messages = {
        FingerprintSelectionIssue.WRITER: "target writer is absent from the selected writer set",
        FingerprintSelectionIssue.READER: "target reader is absent from the selected reader set",
        FingerprintSelectionIssue.PROFILE_PLAN: "target profile requires a writer profile plan",
        FingerprintSelectionIssue.PROFILE: "target profile is absent from the writer profile plan",
    }
    if issue is not None:
        raise FindingValidationError(messages[issue])


def _validate_engine_sets(
    writers: tuple[EngineVersion, ...], readers: tuple[EngineVersion, ...]
) -> None:
    for label, engines in (("writer", writers), ("reader", readers)):
        if not engine_selection_is_valid(engines):
            raise FindingValidationError(f"{label} engine evidence must be non-empty and unique")


def _validate_artifact_inventory(finding: FindingRecord) -> None:
    expected: set[str] = set(REQUIRED_ARTIFACTS)
    if finding.input_parquet:
        expected.add(OPTIONAL_INPUT)
    if finding.reduction.discovered_case_id != finding.case_id:
        expected.add(OPTIONAL_DISCOVERED_CASE)
    names = [artifact.name for artifact in finding.artifacts]
    if names != sorted(names) or len(names) != len(set(names)) or set(names) != expected:
        raise FindingValidationError("artifact evidence does not declare the exact inventory")


def _validate_sha256(value: str, label: str) -> None:
    if not is_sha256(value):
        raise FindingValidationError(f"{label} must be a lowercase SHA-256 value")


__all__ = [
    "ArtifactDigest",
    "FindingRecord",
    "FindingValidationError",
    "ReplaySignature",
    "finding_id_for",
]
