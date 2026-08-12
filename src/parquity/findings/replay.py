from __future__ import annotations

import tempfile
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from ..evidence import DependencyVersion, EngineVersion, ReplayClassification
from ..model import Case
from ..profiles import WriterProfilePlan
from ..verdicts import CaseEvaluator, FailureFingerprint, MatrixRun
from .bundle import ValidatedBundle
from .model import FindingRecord, ReplaySignature


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
    classification: ReplayClassification
    version_evidence: tuple[VersionEvidence, ...]
    version_drift: tuple[VersionDrift, ...]
    dependency_evidence: tuple[DependencyEvidence, ...]
    dependency_drift: tuple[DependencyDrift, ...]

    @property
    def reproduced(self) -> bool:
        return self.classification is ReplayClassification.REPRODUCED


def replay_validated_bundle(
    validated: ValidatedBundle,
    evaluator: CaseEvaluator,
) -> ReplayOutcome:
    run = _evaluate_case(validated.case, evaluator)
    require_replay_profile_plan(validated.finding.writer_profiles, run.writer_profiles)
    fingerprint = validated.finding.fingerprint
    classification = _classify(ReplaySignature.from_fingerprint(fingerprint), run)
    version_evidence = _version_evidence(fingerprint, run)
    version_drift = tuple(
        VersionDrift(item.role, item.engine, item.original, item.current)
        for item in version_evidence
        if item.current is not None and item.current != item.original
    )
    dependency_evidence = _dependency_evidence(validated.finding.environment.dependencies)
    dependency_drift = tuple(
        DependencyDrift(item.package, item.original, item.current)
        for item in dependency_evidence
        if item.current is not None and item.current != item.original
    )
    return ReplayOutcome(
        validated.finding,
        classification,
        version_evidence,
        version_drift,
        dependency_evidence,
        dependency_drift,
    )


def _evaluate_case(case: Case, evaluator: CaseEvaluator) -> MatrixRun:
    with tempfile.TemporaryDirectory(prefix="parquity-replay-") as raw_directory:
        root = Path(raw_directory)
        run = evaluator(case, root / "evaluation").normalized((root,))
    if run.case_id != case.case_id:
        raise RuntimeError("replay evaluation returned a conflicting Case identity")
    return run


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
) -> ReplayClassification:
    failures = tuple(result for result in run.failures if result.fingerprint is not None)
    exact = next(
        (result for result in failures if ReplaySignature.from_result(result) == target),
        None,
    )
    if exact is not None:
        return ReplayClassification.REPRODUCED
    related = next(
        (
            result
            for result in failures
            if ReplaySignature.from_result(result).related_shape() == target.related_shape()
        ),
        None,
    )
    if related is not None:
        return ReplayClassification.RELATED_FAILURE
    return ReplayClassification.NOT_REPRODUCED


def _version_evidence(
    fingerprint: FailureFingerprint,
    run: MatrixRun,
) -> tuple[VersionEvidence, ...]:
    current_writers = _versions(run.writers, run, "writer")
    current_readers = _versions(run.readers, run, "reader")
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
    "replay_validated_bundle",
    "require_replay_profile_plan",
]
