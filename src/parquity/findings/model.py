from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from ..verdicts import CellResult, EngineVersion, FailureFingerprint
from ..writer_profiles import WriterProfilePlan
from . import FINDING_FORMAT, OPTIONAL_DISCOVERED_CASE, OPTIONAL_INPUT, REQUIRED_ARTIFACTS
from . import json_codec as codec
from .evidence import (
    CHECK_COMPLETE,
    DiscoveryEvidence,
    EnvironmentEvidence,
    GenerationEvidence,
    ReductionEvidence,
    engine_version_from_data,
    provider_inventory_matches,
)
from .identity import ArtifactDigest, ReplaySignature
from .observation import cell_result_from_data, fingerprint_from_data

FindingValidationError = codec.FindingValidationError


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
        return _canonical_bytes(self.to_data())

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> FindingRecord:
        plan = _writer_profiles_from_data(data)
        if codec.required(data, "format") != FINDING_FORMAT:
            raise FindingValidationError(f"finding format must be {FINDING_FORMAT!r}")
        return cls(
            finding_id=codec.string(codec.required(data, "finding_id"), "finding_id"),
            case_id=codec.string(codec.required(data, "case_id"), "case_id"),
            command=codec.string(codec.required(data, "command"), "command"),
            writers=_engine_versions(data, "writers"),
            readers=_engine_versions(data, "readers"),
            discovery=DiscoveryEvidence.from_data(
                codec.mapping(codec.required(data, "discovery"), "discovery")
            ),
            environment=EnvironmentEvidence.from_data(
                codec.mapping(codec.required(data, "environment"), "environment")
            ),
            reduction=ReductionEvidence.from_data(
                codec.mapping(codec.required(data, "reduction"), "reduction")
            ),
            fingerprint=fingerprint_from_data(
                codec.mapping(codec.required(data, "fingerprint"), "fingerprint"),
                allow_profile=plan is not None,
            ),
            replay_signature=ReplaySignature.from_data(
                codec.mapping(codec.required(data, "replay_signature"), "replay signature"),
                allow_profile=plan is not None,
            ),
            result=cell_result_from_data(
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
            decoded = cast(object, json.loads(payload, object_pairs_hook=codec.unique_object))
            return cls.from_data(codec.mapping(decoded, "finding"))
        except FindingValidationError:
            raise
        except (TypeError, ValueError) as error:
            raise FindingValidationError("finding.json is malformed") from error


def finding_id_for(case_id: str, fingerprint: FailureFingerprint) -> str:
    _validate_sha256(case_id, "case_id")
    identity = _canonical_bytes({"case_id": case_id, "fingerprint": fingerprint.to_data()})
    return hashlib.sha256(identity).hexdigest()


def _generation_from_data(data: Mapping[str, object]) -> GenerationEvidence | None:
    if "generation" not in data:
        return None
    return GenerationEvidence.from_data(
        codec.mapping(codec.required(data, "generation"), "generation")
    )


def _writer_profiles_from_data(data: Mapping[str, object]) -> WriterProfilePlan | None:
    if "writer_profiles" not in data:
        return None
    return WriterProfilePlan.from_data(
        codec.mapping(codec.required(data, "writer_profiles"), "writer_profiles")
    )


def _validate_generation(finding: FindingRecord) -> None:
    if finding.command == "check" and finding.generation is not None:
        raise FindingValidationError("check findings cannot declare generation evidence")
    reductions = finding.reduction
    if finding.generation is not None and (reductions.fields or reductions.nullability):
        raise FindingValidationError("schema generation cannot declare schema reductions")


def _validate_target_selection(finding: FindingRecord) -> None:
    writers = {engine.name: engine.version for engine in finding.writers}
    readers = {engine.name: engine.version for engine in finding.readers}
    fingerprint = finding.fingerprint
    if writers.get(fingerprint.writer) != fingerprint.writer_version:
        raise FindingValidationError("target writer is absent from the selected writer set")
    if fingerprint.reader != "*" and readers.get(fingerprint.reader) != fingerprint.reader_version:
        raise FindingValidationError("target reader is absent from the selected reader set")
    if finding.writer_profiles is None:
        if fingerprint.writer_profile is not None:
            raise FindingValidationError("target profile requires a writer profile plan")
        return
    executions = finding.writer_profiles.executions(finding.writers)
    if not any(
        item.writer.name == fingerprint.writer
        and item.writer.version == fingerprint.writer_version
        and item.writer_profile == fingerprint.writer_profile
        for item in executions
    ):
        raise FindingValidationError("target profile is absent from the writer profile plan")


def _validate_engine_sets(
    writers: tuple[EngineVersion, ...], readers: tuple[EngineVersion, ...]
) -> None:
    for label, engines in (("writer", writers), ("reader", readers)):
        names = [engine.name for engine in engines]
        if not names or len(names) != len(set(names)):
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


def _engine_versions(data: Mapping[str, object], key: str) -> tuple[EngineVersion, ...]:
    return tuple(
        engine_version_from_data(codec.mapping(value, key))
        for value in codec.sequence(codec.required(data, key), key)
    )


def _validate_sha256(value: str, label: str) -> None:
    malformed = len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    if malformed:
        raise FindingValidationError(f"{label} must be a lowercase SHA-256 value")


def _canonical_bytes(data: Mapping[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


__all__ = [
    "ArtifactDigest",
    "FindingRecord",
    "FindingValidationError",
    "ReplaySignature",
    "cell_result_from_data",
    "finding_id_for",
    "fingerprint_from_data",
]
