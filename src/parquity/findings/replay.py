from __future__ import annotations

import tempfile
from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata
from pathlib import Path

from ..generation import CaseEvaluator
from ..verdicts import CellResult, EngineVersion, MatrixRun
from ..writer_profiles import WriterProfilePlan
from .bundle import ValidatedBundle, validate_bundle
from .evidence import DependencyVersion
from .model import FindingRecord, ReplaySignature


class ReplayClassification(StrEnum):
    REPRODUCED = "REPRODUCED"
    RELATED_FAILURE = "RELATED_FAILURE"
    NOT_REPRODUCED = "NOT_REPRODUCED"


@dataclass(frozen=True, slots=True)
class VersionDrift:
    role: str
    engine: str
    original: str
    current: str

    def to_data(self) -> dict[str, object]:
        return {
            "role": self.role,
            "engine": self.engine,
            "original": self.original,
            "current": self.current,
        }


@dataclass(frozen=True, slots=True)
class VersionEvidence:
    role: str
    engine: str
    original: str
    current: str | None
    available: bool

    def to_data(self) -> dict[str, object]:
        return {
            "role": self.role,
            "engine": self.engine,
            "original": self.original,
            "current": self.current,
            "available": self.available,
        }


@dataclass(frozen=True, slots=True)
class DependencyEvidence:
    package: str
    original: str
    current: str | None
    available: bool

    def to_data(self) -> dict[str, object]:
        return {
            "package": self.package,
            "original": self.original,
            "current": self.current,
            "available": self.available,
        }


@dataclass(frozen=True, slots=True)
class DependencyDrift:
    package: str
    original: str
    current: str

    def to_data(self) -> dict[str, object]:
        return {
            "package": self.package,
            "original": self.original,
            "current": self.current,
        }


@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    finding: FindingRecord
    run: MatrixRun
    classification: ReplayClassification
    matched: CellResult | None
    version_evidence: tuple[VersionEvidence, ...]
    version_drift: tuple[VersionDrift, ...]
    dependency_evidence: tuple[DependencyEvidence, ...]
    dependency_drift: tuple[DependencyDrift, ...]

    @property
    def reproduced(self) -> bool:
        return self.classification is ReplayClassification.REPRODUCED


def replay_bundle(directory: Path, evaluator: CaseEvaluator) -> ReplayOutcome:
    return replay_validated_bundle(validate_bundle(directory), evaluator)


def replay_validated_bundle(
    validated: ValidatedBundle,
    evaluator: CaseEvaluator,
) -> ReplayOutcome:
    with tempfile.TemporaryDirectory(prefix="parquity-replay-") as raw_directory:
        root = Path(raw_directory)
        run = evaluator(validated.case, root / "evaluation").normalized((root,))
    if run.case_id != validated.case.case_id:
        raise RuntimeError("replay evaluation returned a conflicting Case identity")
    require_replay_profile_plan(validated.finding.writer_profiles, run.writer_profiles)
    classification, matched = _classify(validated.finding.replay_signature, run)
    evidence = _version_evidence(validated.finding, run)
    drift = tuple(
        VersionDrift(item.role, item.engine, item.original, item.current)
        for item in evidence
        if item.current is not None and item.current != item.original
    )
    dependencies = _dependency_evidence(validated.finding.environment.dependencies)
    dependency_drift = tuple(
        DependencyDrift(item.package, item.original, item.current)
        for item in dependencies
        if item.current is not None and item.current != item.original
    )
    return ReplayOutcome(
        validated.finding,
        run,
        classification,
        matched,
        evidence,
        drift,
        dependencies,
        dependency_drift,
    )


def require_replay_profile_plan(
    recorded: WriterProfilePlan | None,
    current: WriterProfilePlan | None,
) -> None:
    if recorded is None:
        if current is not None:
            raise RuntimeError("unprofiled replay returned a writer profile plan")
        return
    if current is None or not recorded.replay_equivalent(current):
        raise RuntimeError("replay returned a conflicting writer profile plan")


def _classify(
    target: ReplaySignature,
    run: MatrixRun,
) -> tuple[ReplayClassification, CellResult | None]:
    failures = tuple(result for result in run.failures if result.fingerprint is not None)
    exact = next(
        (result for result in failures if ReplaySignature.from_result(result) == target),
        None,
    )
    if exact is not None:
        return ReplayClassification.REPRODUCED, exact
    related = next(
        (
            result
            for result in failures
            if ReplaySignature.from_result(result).related_shape() == target.related_shape()
        ),
        None,
    )
    if related is not None:
        return ReplayClassification.RELATED_FAILURE, related
    return ReplayClassification.NOT_REPRODUCED, None


def _version_evidence(finding: FindingRecord, run: MatrixRun) -> tuple[VersionEvidence, ...]:
    current_writers = _versions(run.writers, run, "writer")
    current_readers = _versions(run.readers, run, "reader")
    fingerprint = finding.fingerprint
    evidence = [
        VersionEvidence(
            "writer",
            fingerprint.writer,
            fingerprint.writer_version,
            current_writers.get(fingerprint.writer),
            fingerprint.writer in current_writers,
        )
    ]
    if fingerprint.reader != "*":
        evidence.append(
            VersionEvidence(
                "reader",
                fingerprint.reader,
                fingerprint.reader_version,
                current_readers.get(fingerprint.reader),
                fingerprint.reader in current_readers,
            )
        )
    return tuple(evidence)


def _versions(
    engines: tuple[EngineVersion, ...],
    run: MatrixRun,
    role: str,
) -> dict[str, str]:
    if engines:
        return {engine.name: engine.version for engine in engines}
    pairs = (
        (result.writer, result.writer_version)
        if role == "writer"
        else (result.reader, result.reader_version)
        for result in run.results
        if (result.writer if role == "writer" else result.reader) != "*"
    )
    versions: dict[str, str] = {}
    for name, version in pairs:
        if name in versions and versions[name] != version:
            raise RuntimeError(f"replay observed conflicting {role} versions for {name}")
        versions[name] = version
    return versions


def _dependency_evidence(
    recorded: tuple[DependencyVersion, ...],
) -> tuple[DependencyEvidence, ...]:
    values: list[DependencyEvidence] = []
    for item in recorded:
        try:
            current = metadata.version(item.package)
        except metadata.PackageNotFoundError:
            current = None
        values.append(DependencyEvidence(item.package, item.version, current, current is not None))
    return tuple(values)


__all__ = [
    "DependencyDrift",
    "DependencyEvidence",
    "ReplayClassification",
    "ReplayOutcome",
    "VersionDrift",
    "VersionEvidence",
    "replay_bundle",
    "replay_validated_bundle",
    "require_replay_profile_plan",
]
