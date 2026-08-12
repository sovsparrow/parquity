from __future__ import annotations

from dataclasses import dataclass

from ...evidence import is_sha256
from ...model import Case
from ...verdicts import CellResult, FailureFingerprint, MatrixRun
from ..evidence import DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW
from ..reduce import ReductionCounts
from .identity import FindingKey, finding_key


@dataclass(frozen=True, slots=True)
class SearchFinding:
    discovered_case: Case
    case: Case
    fingerprint: FailureFingerprint
    result: CellResult
    run: MatrixRun
    discovery_bound: int
    hypothesis_reduced: bool
    reductions: ReductionCounts

    @property
    def key(self) -> FindingKey:
        return finding_key(self.fingerprint)


@dataclass(frozen=True, slots=True)
class OverflowObservation:
    case: Case
    result: CellResult
    origin: str

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def fingerprint(self) -> FailureFingerprint:
        fingerprint = self.result.fingerprint
        if fingerprint is None:
            raise ValueError("overflow observation must be non-passing")
        return fingerprint


@dataclass(frozen=True, slots=True)
class GeneratedOccurrence:
    case_id: str
    fingerprint: FailureFingerprint
    origin: str

    def __post_init__(self) -> None:
        if not is_sha256(self.case_id):
            raise ValueError("generated occurrence case ID must be a lowercase SHA-256 value")
        if self.origin not in (DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW):
            raise ValueError("generated occurrence origin is not recognized")

    @property
    def key(self) -> FindingKey:
        return finding_key(self.fingerprint)

    @property
    def target(self) -> tuple[str, FailureFingerprint]:
        return self.case_id, self.fingerprint


@dataclass(frozen=True, slots=True)
class SearchCampaign:
    findings: tuple[SearchFinding, ...]
    overflow: tuple[OverflowObservation, ...]
    discovery_bound: int
    seed: int
    max_saved: int
    stop_reason: str
    evaluated_cases: int
    evaluated_cells: int
    occurrences: tuple[GeneratedOccurrence, ...] = ()

    def __post_init__(self) -> None:
        saved = tuple(item.key for item in self.findings)
        overflow = tuple(finding_key(item.fingerprint) for item in self.overflow)
        if saved != tuple(sorted(saved)) or len(saved) != len(set(saved)):
            raise ValueError("saved finding keys must be unique and canonically ordered")
        if overflow != tuple(sorted(overflow)) or len(overflow) != len(set(overflow)):
            raise ValueError("overflow finding keys must be unique and canonically ordered")
        if set(saved) & set(overflow):
            raise ValueError("saved and overflow finding keys must be disjoint")
        _validate_occurrence_partition(saved, overflow, self.occurrences)


@dataclass(frozen=True, slots=True)
class DiscoveredObservation:
    case: Case
    result: CellResult
    run: MatrixRun


@dataclass(frozen=True, slots=True)
class CaseSearch:
    findings: tuple[SearchFinding, ...]
    occurrences: tuple[GeneratedOccurrence, ...]
    evaluated_cases: int
    evaluated_cells: int

    def __post_init__(self) -> None:
        saved = tuple(item.key for item in self.findings)
        if saved != tuple(sorted(saved)) or len(saved) != len(set(saved)):
            raise ValueError("check finding keys must be unique and canonically ordered")
        if self.evaluated_cases != 1 or self.evaluated_cells < 1:
            raise ValueError("check search counts must describe one executed input")
        _validate_occurrence_partition(saved, (), self.occurrences)


def occurrence_sort_key(value: GeneratedOccurrence) -> tuple[str, bytes]:
    return value.case_id, value.fingerprint.canonical_bytes()


def _validate_occurrence_partition(
    saved: tuple[FindingKey, ...],
    overflow: tuple[FindingKey, ...],
    occurrences: tuple[GeneratedOccurrence, ...],
) -> None:
    targets = tuple(item.target for item in occurrences)
    if occurrences != tuple(sorted(occurrences, key=occurrence_sort_key)):
        raise ValueError("generated occurrences must be canonically ordered")
    if len(targets) != len(set(targets)):
        raise ValueError("generated occurrence targets must be unique")
    representative_keys = set(saved) | set(overflow)
    occurrence_keys = {item.key for item in occurrences}
    if representative_keys != occurrence_keys:
        raise ValueError("generated occurrences must partition the represented finding keys")
    discovery_keys = {item.key for item in occurrences if item.origin == DISCOVERY_OVERFLOW}
    minimized_keys = tuple(item.key for item in occurrences if item.origin == MINIMIZATION_OVERFLOW)
    if len(minimized_keys) != len(set(minimized_keys)) or discovery_keys & set(minimized_keys):
        raise ValueError("minimization occurrences must introduce unique sibling finding keys")


__all__ = [
    "CaseSearch",
    "DiscoveredObservation",
    "GeneratedOccurrence",
    "OverflowObservation",
    "SearchCampaign",
    "SearchFinding",
    "occurrence_sort_key",
]
