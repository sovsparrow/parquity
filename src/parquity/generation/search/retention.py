from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ...model import Case
from ...verdicts import CaseEvaluator, CellResult, FailureFingerprint, MatrixRun
from ..evidence import (
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    MINIMIZATION_OVERFLOW,
    SAVED_EVIDENCE_LIMIT_REACHED,
    STRATEGY_EXHAUSTED,
)
from ..progress import (
    FuzzPhase,
    FuzzProgress,
    ProgressCallback,
    ProgressNotifier,
    resilient_progress,
)
from .identity import FindingKey, finding_key
from .records import (
    DiscoveredObservation,
    GeneratedOccurrence,
    OverflowObservation,
    SearchCampaign,
    SearchFinding,
    occurrence_sort_key,
)

Evaluate = Callable[[Case, CaseEvaluator], MatrixRun]
Minimize = Callable[[DiscoveredObservation, FailureFingerprint], SearchFinding]


@dataclass(slots=True)
class FindingCollector:
    evaluator: CaseEvaluator
    max_saved: int
    evaluate: Evaluate
    progress: ProgressCallback | None = None
    _retained: dict[FindingKey, DiscoveredObservation] = field(
        default_factory=dict[FindingKey, DiscoveredObservation]
    )
    _overflow: dict[FindingKey, OverflowObservation] = field(
        default_factory=dict[FindingKey, OverflowObservation]
    )
    _occurrences: dict[tuple[str, FailureFingerprint], GeneratedOccurrence] = field(
        default_factory=dict[tuple[str, FailureFingerprint], GeneratedOccurrence]
    )
    _progress_notifier: ProgressNotifier = field(init=False, repr=False)
    evaluated_cases: int = 0
    evaluated_cells: int = 0

    def __post_init__(self) -> None:
        self._progress_notifier = resilient_progress(self.progress)

    @property
    def stopped(self) -> bool:
        return bool(self._overflow)

    @property
    def has_findings(self) -> bool:
        return bool(self._retained)

    def observe(self, case: Case) -> None:
        if self.stopped:
            return
        run = self.evaluate(case, self.evaluator)
        self.evaluated_cases += 1
        self.evaluated_cells += len(run.results)
        self._admit_run(case, run, DISCOVERY_OVERFLOW)
        self._notify(
            FuzzProgress(
                FuzzPhase.DISCOVERY,
                self.evaluated_cases,
                self.evaluated_cells,
                len(self._retained),
                len(self._overflow),
            )
        )

    def close(
        self,
        minimize: Minimize,
        *,
        examples: int,
        seed: int,
    ) -> SearchCampaign:
        from .campaign import close_discovery  # noqa: PLC0415 - compatibility entry point.

        findings = close_discovery(
            self.retained_observations(),
            minimize,
            sibling_admission=self.admit_minimized,
            progress=self.report_minimization,
        )
        return self.complete(findings, examples=examples, seed=seed)

    def retained_observations(self) -> dict[FindingKey, DiscoveredObservation]:
        return dict(self._retained)

    def admit_minimized(
        self,
        key: FindingKey,
        observation: DiscoveredObservation,
    ) -> bool:
        if key in self._retained or key in self._overflow:
            return False
        self._record_occurrence(observation.case, observation.result, MINIMIZATION_OVERFLOW)
        return self._admit(key, observation, MINIMIZATION_OVERFLOW)

    def report_minimization(self, completed: int, total: int) -> None:
        self._notify(
            FuzzProgress(
                FuzzPhase.MINIMIZATION,
                self.evaluated_cases,
                self.evaluated_cells,
                len(self._retained),
                len(self._overflow),
                completed,
                total,
            )
        )

    def complete(
        self,
        findings: tuple[SearchFinding, ...],
        *,
        examples: int,
        seed: int,
    ) -> SearchCampaign:
        overflow = tuple(self._overflow[key] for key in sorted(self._overflow))
        stop_reason = SAVED_EVIDENCE_LIMIT_REACHED if overflow else EXAMPLE_BOUND_REACHED
        if not overflow and self.evaluated_cases < examples:
            stop_reason = STRATEGY_EXHAUSTED
        return SearchCampaign(
            findings,
            overflow,
            examples,
            seed,
            self.max_saved,
            stop_reason,
            self.evaluated_cases,
            self.evaluated_cells,
            tuple(sorted(self._occurrences.values(), key=occurrence_sort_key)),
        )

    def _admit_run(self, case: Case, run: MatrixRun, origin: str) -> None:
        for result in run.distinct_failures:
            fingerprint = _required_fingerprint(result)
            self._record_occurrence(case, result, DISCOVERY_OVERFLOW)
            key = finding_key(fingerprint)
            self._admit(key, DiscoveredObservation(case, result, run), origin)

    def _record_occurrence(self, case: Case, result: CellResult, origin: str) -> None:
        fingerprint = _required_fingerprint(result)
        occurrence = GeneratedOccurrence(case.case_id, fingerprint, origin)
        self._occurrences.setdefault(occurrence.target, occurrence)

    def _admit(
        self,
        key: FindingKey,
        observation: DiscoveredObservation,
        origin: str,
    ) -> bool:
        if key in self._retained or key in self._overflow:
            return False
        if len(self._retained) < self.max_saved:
            self._retained[key] = observation
            return True
        self._overflow[key] = OverflowObservation(
            observation.case,
            observation.result,
            origin,
        )
        return False

    def _notify(self, snapshot: FuzzProgress) -> None:
        self._progress_notifier(snapshot)


def _required_fingerprint(result: CellResult) -> FailureFingerprint:
    fingerprint = result.fingerprint
    if fingerprint is None:
        raise RuntimeError("retained finding is passing")
    return fingerprint


__all__ = ["FindingCollector"]
