from __future__ import annotations

import random
from collections.abc import Callable

from hypothesis import HealthCheck, Phase, find, given, settings
from hypothesis import seed as hypothesis_seed
from hypothesis.errors import NoSuchExample
from hypothesis.strategies import SearchStrategy

from ...configuration import (
    DEFAULT_FUZZ_SAVED_LIMIT,
    MAX_FUZZ_SAVED_LIMIT,
    MAX_FUZZ_SEED,
    fuzz_examples_is_valid,
    fuzz_saved_limit_is_valid,
    fuzz_seed_is_valid,
)
from ...model import Case
from ...verdicts import CaseEvaluator, CellResult, FailureFingerprint, MatrixRun
from ..evidence import DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW
from ..progress import ProgressCallback
from ..reduce import (
    CandidateAdmission,
    ObservationAdmission,
    admit_every_candidate,
    admit_every_observation,
    reduce_case,
)
from . import records
from .evaluation import CampaignEvaluator, EvaluationContext
from .identity import FindingKey, finding_key
from .retention import FindingCollector

_Minimize = Callable[[records.DiscoveredObservation, FailureFingerprint], records.SearchFinding]
_SiblingAdmission = Callable[[FindingKey, records.DiscoveredObservation], bool]
_ClosureProgress = Callable[[int, int], None]


def search_cases(
    strategy: SearchStrategy[Case],
    *,
    examples: int,
    seed: int,
    evaluator: CaseEvaluator,
    max_saved: int = DEFAULT_FUZZ_SAVED_LIMIT,
    candidate_admission: CandidateAdmission = admit_every_candidate,
    progress: ProgressCallback | None = None,
    evaluation_context: EvaluationContext | None = None,
) -> records.SearchCampaign:
    _validate_parameters(examples, seed, max_saved)
    evaluation = CampaignEvaluator(evaluator, context=evaluation_context)
    collector = FindingCollector(
        evaluator,
        max_saved,
        lambda case, _evaluator: evaluation(case),
        progress,
    )

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
    findings = close_discovery(
        collector.retained_observations(),
        lambda discovered, fingerprint: _minimize(
            strategy,
            discovered,
            fingerprint,
            examples,
            seed,
            evaluation,
            candidate_admission,
        ),
        sibling_admission=collector.admit_minimized,
        progress=collector.report_minimization,
    )
    return collector.complete(
        findings,
        examples=examples,
        seed=seed,
    )


def find_case_observations(
    case: Case,
    evaluator: CaseEvaluator,
    candidate_admission: CandidateAdmission = admit_every_candidate,
    *,
    evaluation_context: EvaluationContext | None = None,
) -> tuple[records.SearchFinding, ...]:
    return find_case_evidence(
        case,
        evaluator,
        candidate_admission,
        evaluation_context=evaluation_context,
    ).findings


def find_case_evidence(
    case: Case,
    evaluator: CaseEvaluator,
    candidate_admission: CandidateAdmission = admit_every_candidate,
    *,
    evaluation_context: EvaluationContext | None = None,
) -> records.CaseSearch:
    evaluation = CampaignEvaluator(evaluator, context=evaluation_context)
    discovered_run = evaluation(case)
    by_key: dict[FindingKey, records.DiscoveredObservation] = {}
    occurrences: dict[tuple[str, FailureFingerprint], records.GeneratedOccurrence] = {}
    for result in discovered_run.distinct_failures:
        fingerprint = _required_fingerprint(result)
        occurrence = records.GeneratedOccurrence(case.case_id, fingerprint, DISCOVERY_OVERFLOW)
        occurrences.setdefault(occurrence.target, occurrence)
        by_key.setdefault(
            finding_key(fingerprint),
            records.DiscoveredObservation(case, result, discovered_run),
        )

    def admit_sibling(key: FindingKey, observation: records.DiscoveredObservation) -> bool:
        fingerprint = _required_fingerprint(observation.result)
        occurrence = records.GeneratedOccurrence(
            observation.case.case_id,
            fingerprint,
            MINIMIZATION_OVERFLOW,
        )
        if occurrence.key != key:
            raise RuntimeError("minimization occurrence changed the sibling finding key")
        occurrences.setdefault(occurrence.target, occurrence)
        return True

    findings = close_discovery(
        by_key,
        lambda discovered, fingerprint: _structurally_minimize(
            discovered,
            fingerprint,
            None,
            evaluation,
            candidate_admission,
        ),
        sibling_admission=admit_sibling,
    )
    return records.CaseSearch(
        findings,
        tuple(sorted(occurrences.values(), key=records.occurrence_sort_key)),
        1,
        len(discovered_run.results),
    )


def close_discovery(
    retained: dict[FindingKey, records.DiscoveredObservation],
    minimize: _Minimize,
    *,
    sibling_admission: _SiblingAdmission | None = None,
    progress: _ClosureProgress | None = None,
) -> tuple[records.SearchFinding, ...]:
    planned = set(retained)
    pending = dict(retained)
    findings: dict[FindingKey, records.SearchFinding] = {}
    if progress is not None:
        progress(0, len(pending))
    while pending:
        key = min(pending)
        discovered = pending.pop(key)
        fingerprint = _required_fingerprint(discovered.result)
        finding = minimize(discovered, fingerprint)
        if finding.fingerprint != fingerprint or finding.result.fingerprint != fingerprint:
            raise RuntimeError("minimized finding changed the selected fingerprint")
        if finding.key != key:
            raise RuntimeError("minimized finding changed the selected finding key")
        findings[key] = finding
        for result in finding.run.distinct_failures:
            sibling = _required_fingerprint(result)
            sibling_key = finding_key(sibling)
            if sibling_key in planned:
                continue
            planned.add(sibling_key)
            observation = records.DiscoveredObservation(finding.case, result, finding.run)
            if sibling_admission is None or sibling_admission(sibling_key, observation):
                pending[sibling_key] = observation
        if progress is not None:
            progress(len(findings), len(findings) + len(pending))
    return tuple(findings[key] for key in sorted(findings))


def _minimize(
    strategy: SearchStrategy[Case],
    discovered: records.DiscoveredObservation,
    fingerprint: FailureFingerprint,
    examples: int,
    seed: int,
    evaluate: Callable[[Case], MatrixRun],
    candidate_admission: CandidateAdmission,
) -> records.SearchFinding:
    try:
        candidate = find(
            strategy,
            lambda case: (
                candidate_admission(case)
                and _matching_failure(evaluate(case), fingerprint) is not None
            ),
            settings=_settings(examples),
            random=random.Random(seed),  # noqa: S311 - deterministic search seed, not security.
        )
        candidate_run = evaluate(candidate)
    except NoSuchExample:
        candidate = discovered.case
        candidate_run = discovered.run
    return _structurally_minimize(
        discovered,
        fingerprint,
        examples,
        evaluate,
        candidate_admission,
        candidate,
        candidate_run,
    )


def _structurally_minimize(
    discovered: records.DiscoveredObservation,
    fingerprint: FailureFingerprint,
    examples: int | None,
    evaluate: Callable[[Case], MatrixRun],
    candidate_admission: CandidateAdmission,
    candidate: Case | None = None,
    candidate_run: MatrixRun | None = None,
    observation_admission: ObservationAdmission = admit_every_observation,
) -> records.SearchFinding:
    start = discovered.case if candidate is None else candidate
    run = discovered.run if candidate_run is None else candidate_run
    reduced = reduce_case(
        start,
        run,
        fingerprint,
        evaluate,
        candidate_admission,
        observation_admission,
    )
    result = _matching_failure(reduced.run, fingerprint)
    if result is None:
        raise RuntimeError("reduced case no longer contains the selected observation")
    return records.SearchFinding(
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


def _matching_failure(run: MatrixRun, fingerprint: FailureFingerprint) -> CellResult | None:
    return next(
        (result for result in run.distinct_failures if result.fingerprint == fingerprint), None
    )


def _required_fingerprint(result: CellResult) -> FailureFingerprint:
    fingerprint = result.fingerprint
    if fingerprint is None:
        raise RuntimeError("retained finding is passing")
    return fingerprint


def _validate_parameters(examples: int, seed: int, max_saved: int) -> None:
    if not fuzz_examples_is_valid(examples):
        raise ValueError("examples must be a positive integer")
    if not fuzz_seed_is_valid(seed):
        raise ValueError(f"seed must be in [0, {MAX_FUZZ_SEED}]")
    if not fuzz_saved_limit_is_valid(max_saved):
        raise ValueError(f"max_saved must be in [1, {MAX_FUZZ_SAVED_LIMIT}]")


__all__ = [
    "find_case_evidence",
    "find_case_observations",
    "search_cases",
]
