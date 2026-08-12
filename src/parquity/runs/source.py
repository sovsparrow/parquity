from __future__ import annotations

from dataclasses import dataclass

from ..evidence import EngineVersion, EnvironmentEvidence
from ..generation.evidence import (
    CHECK_COMPLETE,
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    MINIMIZATION_OVERFLOW,
    STRATEGY_EXHAUSTED,
    DiscoveryEvidence,
    GenerationEvidence,
)
from ..generation.search.identity import FindingKey, finding_key
from ..generation.search.records import GeneratedOccurrence, OverflowObservation, SearchFinding
from ..profiles import WriterProfilePlan


@dataclass(frozen=True, slots=True)
class RunSource:
    command: str
    findings: tuple[SearchFinding, ...]
    overflow: tuple[OverflowObservation, ...]
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    environment: EnvironmentEvidence
    generation: GenerationEvidence | None = None
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        saved = tuple(item.key for item in self.findings)
        overflow = tuple(finding_key(item.fingerprint) for item in self.overflow)
        if len(saved) != len(set(saved)):
            raise ValueError("run source saved finding keys must be unique")
        if len(overflow) != len(set(overflow)):
            raise ValueError("run source overflow finding keys must be unique")
        if set(saved) & set(overflow):
            raise ValueError("run source saved and overflow finding keys must be disjoint")


@dataclass(frozen=True, slots=True)
class RunV2Source:
    command: str
    findings: tuple[SearchFinding, ...]
    overflow: tuple[OverflowObservation, ...]
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    environment: EnvironmentEvidence
    occurrences: tuple[GeneratedOccurrence, ...]
    evaluated_inputs: int
    executed_checks: int
    generation: GenerationEvidence | None = None
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        saved = tuple(item.key for item in self.findings)
        overflow = tuple(finding_key(item.fingerprint) for item in self.overflow)
        if len(saved) != len(set(saved)) or len(overflow) != len(set(overflow)):
            raise ValueError("run.v2 representative finding keys must be unique")
        if set(saved) & set(overflow):
            raise ValueError("run.v2 saved and manifest-only finding keys must be disjoint")
        if self.occurrences:
            _validate_occurrence_partition(set(saved) | set(overflow), self.occurrences)
        _validate_execution_evidence(
            self.command,
            self.discovery,
            self.evaluated_inputs,
            self.executed_checks,
        )
        if (self.findings or self.overflow) and not self.occurrences:
            raise ValueError("run.v2 represented findings require occurrence evidence")


def planned_finding_keys(source: RunSource | RunV2Source) -> set[FindingKey]:
    saved = {item.key for item in source.findings}
    return saved | {finding_key(item.fingerprint) for item in source.overflow}


def _validate_occurrence_partition(
    representative_keys: set[FindingKey],
    occurrences: tuple[GeneratedOccurrence, ...],
) -> None:
    targets = tuple(item.target for item in occurrences)
    if len(targets) != len(set(targets)):
        raise ValueError("run source occurrence targets must be unique")
    occurrence_keys = {item.key for item in occurrences}
    if occurrence_keys != representative_keys:
        raise ValueError("run source occurrences must partition the represented finding keys")
    discovery_keys = {item.key for item in occurrences if item.origin == DISCOVERY_OVERFLOW}
    minimized_keys = tuple(item.key for item in occurrences if item.origin == MINIMIZATION_OVERFLOW)
    if len(minimized_keys) != len(set(minimized_keys)) or discovery_keys & set(minimized_keys):
        raise ValueError("run source minimization occurrences must introduce sibling finding keys")


def _validate_execution_evidence(
    command: str,
    discovery: DiscoveryEvidence,
    evaluated_inputs: int,
    executed_checks: int,
) -> None:
    if any(isinstance(value, bool) for value in (evaluated_inputs, executed_checks)):
        raise ValueError("run.v2 source execution counts must be integers")
    if evaluated_inputs < 1 or executed_checks < evaluated_inputs:
        raise ValueError("run.v2 source execution counts are invalid")
    if command not in ("check", "fuzz"):
        raise ValueError("run.v2 source command must be check or fuzz")
    if (command == "check") != (discovery.stop_reason == CHECK_COMPLETE):
        raise ValueError("run.v2 source command conflicts with discovery evidence")
    if command == "check" and evaluated_inputs != 1:
        raise ValueError("run.v2 check source must bind one evaluated input")
    discovery_counts = discovery.evaluated_cases, discovery.evaluated_cells
    if command == "fuzz" and discovery_counts != (evaluated_inputs, executed_checks):
        raise ValueError("run.v2 fuzz counts conflict with discovery evidence")
    if (
        command == "fuzz"
        and discovery.stop_reason == EXAMPLE_BOUND_REACHED
        and evaluated_inputs != discovery.examples
    ):
        raise ValueError("run.v2 example-bound stop requires the full requested bound")
    if (
        command == "fuzz"
        and discovery.stop_reason == STRATEGY_EXHAUSTED
        and (discovery.examples is None or evaluated_inputs >= discovery.examples)
    ):
        raise ValueError("run.v2 strategy exhaustion requires fewer evaluated inputs")


__all__ = [
    "RunSource",
    "RunV2Source",
    "planned_finding_keys",
]
