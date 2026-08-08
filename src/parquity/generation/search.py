from __future__ import annotations

import random
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import cast

from hypothesis import HealthCheck, Phase, find, given, settings
from hypothesis import seed as hypothesis_seed
from hypothesis.errors import NoSuchExample
from hypothesis.strategies import SearchStrategy

from ..engines import EngineSelection
from ..engines.base import EngineReader, EngineWriter
from ..findings.evidence import (
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    FINDING_CAP_REACHED,
    MINIMIZATION_OVERFLOW,
)
from ..model import Case
from ..verdicts import CellResult, FailureFingerprint, MatrixRun
from ..writer_profiles import WriterProfilePlan
from . import DEFAULT_MAX_FINDINGS, MAX_FINDINGS, MAX_SEED, CaseEvaluator
from .reduce import CandidateAdmission, ReductionCounts, admit_every_candidate, reduce_case

RunMatrix = Callable[
    [Case, Path, Sequence[EngineWriter], Sequence[EngineReader], WriterProfilePlan | None],
    MatrixRun,
]


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


@dataclass(frozen=True, slots=True)
class OverflowObservation:
    case_id: str
    fingerprint: FailureFingerprint
    case: Case
    result: CellResult
    stop_reason: str = FINDING_CAP_REACHED
    origin: str = DISCOVERY_OVERFLOW

    def __post_init__(self) -> None:
        if self.case_id != self.case.case_id or self.fingerprint != self.result.fingerprint:
            raise ValueError("overflow summary conflicts with its typed evidence")


@dataclass(frozen=True, slots=True)
class SearchCampaign:
    findings: tuple[SearchFinding, ...]
    overflow: tuple[OverflowObservation, ...]
    discovery_bound: int
    seed: int
    max_findings: int
    stop_reason: str
    evaluated_cases: int
    evaluated_cells: int


@dataclass(frozen=True, slots=True)
class _Discovered:
    case: Case
    result: CellResult
    run: MatrixRun


@dataclass(slots=True)
class _Collector:
    evaluator: CaseEvaluator
    max_findings: int
    retained: dict[FailureFingerprint, _Discovered]
    overflow: dict[FailureFingerprint, OverflowObservation]
    evaluated_cases: int = 0
    evaluated_cells: int = 0

    @property
    def capped(self) -> bool:
        return bool(self.overflow)

    def observe(self, case: Case) -> None:
        if self.capped:
            return
        run = _evaluate(case, self.evaluator)
        self.evaluated_cases += 1
        self.evaluated_cells += len(run.results)
        for fingerprint, result in _observations(run):
            if fingerprint in self.retained or fingerprint in self.overflow:
                continue
            if len(self.retained) < self.max_findings:
                self.retained[fingerprint] = _Discovered(case, result, run)
            else:
                observed = OverflowObservation(case.case_id, fingerprint, case, result)
                self.overflow[fingerprint] = observed


def evaluate_selected_case(
    case: Case,
    directory: Path,
    selection: EngineSelection,
    writer_profiles: WriterProfilePlan | None = None,
) -> MatrixRun:
    module = import_module("parquity.matrix")
    execute_value = cast(object, getattr(module, "run_matrix", None))
    if not callable(execute_value):
        raise TypeError("matrix module does not expose a callable run_matrix")
    execute = cast(RunMatrix, execute_value)
    return execute(case, directory, selection.writers, selection.readers, writer_profiles)


def search_cases(
    strategy: SearchStrategy[Case],
    *,
    examples: int,
    seed: int,
    evaluator: CaseEvaluator,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    candidate_admission: CandidateAdmission = admit_every_candidate,
) -> SearchCampaign | None:
    _validate_parameters(examples, seed, max_findings)
    collector = _Collector(evaluator, max_findings, {}, {})

    @settings(
        max_examples=examples,
        database=None,
        deadline=None,
        phases=(Phase.generate,),
        suppress_health_check=(HealthCheck.too_slow,),
    )
    @hypothesis_seed(seed)
    @given(strategy)
    def discover(case: Case) -> None:
        collector.observe(case)

    discover()
    if not collector.retained:
        return None
    findings, overflow = _close_discovery(
        collector.retained,
        collector.overflow,
        max_findings,
        lambda discovered, fingerprint: _minimize(
            strategy,
            discovered,
            fingerprint,
            examples,
            seed,
            evaluator,
            candidate_admission,
        ),
    )
    stop_reason = FINDING_CAP_REACHED if overflow else EXAMPLE_BOUND_REACHED
    return SearchCampaign(
        findings,
        overflow,
        examples,
        seed,
        max_findings,
        stop_reason,
        collector.evaluated_cases,
        collector.evaluated_cells,
    )


def find_case_observations(
    case: Case,
    evaluator: CaseEvaluator,
    candidate_admission: CandidateAdmission = admit_every_candidate,
) -> tuple[SearchFinding, ...]:
    discovered_run = _evaluate(case, evaluator)
    by_fingerprint = {
        fingerprint: _Discovered(case, result, discovered_run)
        for fingerprint, result in _observations(discovered_run)
    }
    findings, overflow = _close_discovery(
        by_fingerprint,
        {},
        None,
        lambda discovered, fingerprint: _structurally_minimize(
            discovered, fingerprint, None, evaluator, candidate_admission
        ),
    )
    if overflow:
        raise AssertionError("uncapped discovery cannot overflow")
    return findings


def _close_discovery(
    retained: dict[FailureFingerprint, _Discovered],
    overflow: dict[FailureFingerprint, OverflowObservation],
    capacity: int | None,
    minimize: Callable[[_Discovered, FailureFingerprint], SearchFinding],
) -> tuple[tuple[SearchFinding, ...], tuple[OverflowObservation, ...]]:
    planned = dict(retained)
    pending = dict(retained)
    bounded = dict(overflow)
    findings: dict[FailureFingerprint, SearchFinding] = {}
    while pending:
        fingerprint = min(pending, key=FailureFingerprint.canonical_bytes)
        finding = minimize(pending.pop(fingerprint), fingerprint)
        findings[fingerprint] = finding
        for sibling, result in _observations(finding.run):
            if sibling in planned or sibling in bounded:
                continue
            if capacity is None or len(planned) < capacity:
                discovered = _Discovered(finding.case, result, finding.run)
                planned[sibling] = discovered
                pending[sibling] = discovered
            else:
                bounded[sibling] = OverflowObservation(
                    finding.case.case_id,
                    sibling,
                    finding.case,
                    result,
                    FINDING_CAP_REACHED,
                    MINIMIZATION_OVERFLOW,
                )
    ordered = tuple(sorted(findings.values(), key=lambda item: item.fingerprint.canonical_bytes()))
    excess = tuple(sorted(bounded.values(), key=lambda item: item.fingerprint.canonical_bytes()))
    return ordered, excess


def _observations(run: MatrixRun) -> tuple[tuple[FailureFingerprint, CellResult], ...]:
    observed = {
        result.fingerprint: result for result in run.failures if result.fingerprint is not None
    }
    return tuple(sorted(observed.items(), key=lambda item: item[0].canonical_bytes()))


def _minimize(
    strategy: SearchStrategy[Case],
    discovered: _Discovered,
    fingerprint: FailureFingerprint,
    examples: int,
    seed: int,
    evaluator: CaseEvaluator,
    candidate_admission: CandidateAdmission,
) -> SearchFinding:
    try:
        candidate = find(
            strategy,
            lambda case: (
                candidate_admission(case)
                and _matching_failure(_evaluate(case, evaluator), fingerprint) is not None
            ),
            settings=_settings(examples),
            random=random.Random(seed),  # noqa: S311 - deterministic search seed, not security.
        )
        candidate_run = _evaluate(candidate, evaluator)
    except NoSuchExample:
        candidate = discovered.case
        candidate_run = discovered.run
    return _structurally_minimize(
        discovered,
        fingerprint,
        examples,
        evaluator,
        candidate_admission,
        candidate,
        candidate_run,
    )


def _structurally_minimize(
    discovered: _Discovered,
    fingerprint: FailureFingerprint,
    examples: int | None,
    evaluator: CaseEvaluator,
    candidate_admission: CandidateAdmission,
    candidate: Case | None = None,
    candidate_run: MatrixRun | None = None,
) -> SearchFinding:
    start = discovered.case if candidate is None else candidate
    run = discovered.run if candidate_run is None else candidate_run
    reduced = reduce_case(
        start,
        run,
        fingerprint,
        lambda case: _evaluate(case, evaluator),
        candidate_admission,
    )
    result = _matching_failure(reduced.run, fingerprint)
    if result is None:
        raise RuntimeError("reduced case no longer contains the selected observation")
    return SearchFinding(
        discovered_case=discovered.case,
        case=reduced.case,
        fingerprint=fingerprint,
        result=result,
        run=reduced.run,
        discovery_bound=0 if examples is None else examples,
        hypothesis_reduced=start.canonical_bytes() != discovered.case.canonical_bytes(),
        reductions=reduced.counts,
    )


def _settings(examples: int) -> settings:
    return settings(
        max_examples=examples,
        database=None,
        deadline=None,
        phases=(Phase.generate, Phase.shrink),
        suppress_health_check=(HealthCheck.too_slow,),
    )


def _evaluate(case: Case, evaluator: CaseEvaluator) -> MatrixRun:
    with tempfile.TemporaryDirectory(prefix="parquity-case-") as raw_directory:
        root = Path(raw_directory)
        run = evaluator(case, root / "evaluation")
        return run.normalized((root,))


def _matching_failure(run: MatrixRun, fingerprint: FailureFingerprint) -> CellResult | None:
    return next((result for result in run.failures if result.fingerprint == fingerprint), None)


def _validate_parameters(examples: int, seed: int, max_findings: int) -> None:
    if isinstance(examples, bool) or examples < 1:
        raise ValueError("examples must be a positive integer")
    if isinstance(seed, bool) or not 0 <= seed <= MAX_SEED:
        raise ValueError(f"seed must be in [0, {MAX_SEED}]")
    if isinstance(max_findings, bool) or not 1 <= max_findings <= MAX_FINDINGS:
        raise ValueError(f"max_findings must be in [1, {MAX_FINDINGS}]")


__all__ = [
    "OverflowObservation",
    "SearchCampaign",
    "SearchFinding",
    "evaluate_selected_case",
    "find_case_observations",
    "search_cases",
]
