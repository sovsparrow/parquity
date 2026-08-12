from __future__ import annotations

from pathlib import Path

import pytest

from parquity.evidence import EngineVersion
from parquity.generation.evidence import (
    EXAMPLE_BOUND_REACHED,
    MINIMIZATION_OVERFLOW,
    SAVED_EVIDENCE_LIMIT_REACHED,
    STRATEGY_EXHAUSTED,
)
from parquity.generation.reduce import ReductionCounts
from parquity.generation.search.identity import finding_key
from parquity.generation.search.records import DiscoveredObservation, SearchFinding
from parquity.generation.search.retention import FindingCollector
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, FailureFingerprint, MatrixRun, Verdict


def _case(value: int) -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((value,),))


def _failure(writer: str, detail: str, *, path: str = "$") -> CellResult:
    return CellResult(
        writer,
        "1",
        "*",
        "*",
        "write",
        Verdict.WRITE_ERROR,
        path,
        detail,
        "ControlledError",
    )


def _run(case: Case, *failures: CellResult) -> MatrixRun:
    writers = tuple(EngineVersion(item.writer, item.writer_version) for item in failures)
    return MatrixRun(
        case.case_id,
        tuple(failures),
        (),
        writers,
        (EngineVersion("reader", "1"),),
    )


def _collector(
    runs: dict[str, MatrixRun],
    max_saved: int,
) -> FindingCollector:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        return runs[case.case_id]

    return FindingCollector(
        evaluate,
        max_saved,
        lambda case, evaluator: evaluator(case, Path(".")),
    )


def _finding(
    discovered: DiscoveredObservation,
    fingerprint: FailureFingerprint,
    run: MatrixRun | None = None,
) -> SearchFinding:
    selected_run = discovered.run if run is None else run
    result = next(
        item for item in selected_run.distinct_failures if item.fingerprint == fingerprint
    )
    return SearchFinding(
        discovered.case,
        discovered.case,
        fingerprint,
        result,
        selected_run,
        4,
        False,
        ReductionCounts(),
    )


def test_exact_siblings_with_one_finding_key_consume_one_saved_slot() -> None:
    first = _case(1)
    second = _case(2)
    first_result = _failure("writer", "same failure", path="$schema.field_1")
    second_result = _failure("writer", "same failure", path="$schema.field_2")
    first_fingerprint = first_result.fingerprint or pytest.fail("fingerprint missing")
    second_fingerprint = second_result.fingerprint or pytest.fail("fingerprint missing")
    assert first_fingerprint != second_fingerprint
    assert finding_key(first_fingerprint) == finding_key(second_fingerprint)
    collector = _collector(
        {
            first.case_id: _run(first, first_result),
            second.case_id: _run(second, second_result),
        },
        max_saved=2,
    )

    collector.observe(first)
    collector.observe(second)
    campaign = collector.close(_finding, examples=2, seed=1)

    assert campaign.stop_reason == EXAMPLE_BOUND_REACHED
    assert len(campaign.findings) == 1
    assert campaign.findings[0].discovered_case == first
    assert campaign.overflow == ()


def test_one_matrix_run_fills_the_cap_and_routes_remaining_fingerprints_to_overflow() -> None:
    case = _case(1)
    failures = tuple(_failure(f"writer-{index}", f"failure {index}") for index in range(4))
    collector = _collector({case.case_id: _run(case, *failures)}, max_saved=2)

    collector.observe(case)
    campaign = collector.close(_finding, examples=8, seed=1)

    saved = tuple(item.fingerprint for item in campaign.findings)
    overflow = tuple(item.fingerprint for item in campaign.overflow)
    expected = {item.fingerprint for item in failures}
    saved_keys = {finding_key(item) for item in saved}
    overflow_keys = {finding_key(item) for item in overflow}
    assert campaign.stop_reason == SAVED_EVIDENCE_LIMIT_REACHED
    assert campaign.evaluated_cases == 1
    assert len(saved) == len(overflow) == 2
    assert set(saved) | set(overflow) == expected
    assert set(saved).isdisjoint(overflow)
    assert saved_keys.isdisjoint(overflow_keys)
    assert len(saved_keys) == len(saved)
    assert len(overflow_keys) == len(overflow)
    assert tuple(map(finding_key, saved)) == tuple(sorted(saved_keys))
    assert tuple(map(finding_key, overflow)) == tuple(sorted(overflow_keys))


@pytest.mark.parametrize(
    ("max_saved", "saved_count", "overflow_count"),
    ((2, 2, 0), (1, 1, 1)),
)
def test_minimization_siblings_follow_the_remaining_fingerprint_capacity(
    max_saved: int,
    saved_count: int,
    overflow_count: int,
) -> None:
    case = _case(1)
    primary = _failure("writer-a", "primary")
    sibling = _failure("writer-b", "sibling")
    discovered = _run(case, primary)
    minimized = _run(case, primary, sibling)
    collector = _collector({case.case_id: discovered}, max_saved=max_saved)
    collector.observe(case)

    def minimize(
        observation: DiscoveredObservation,
        fingerprint: FailureFingerprint,
    ) -> SearchFinding:
        return _finding(observation, fingerprint, minimized)

    campaign = collector.close(minimize, examples=4, seed=1)

    assert len(campaign.findings) == saved_count
    assert len(campaign.overflow) == overflow_count
    if overflow_count:
        assert campaign.stop_reason == SAVED_EVIDENCE_LIMIT_REACHED
        assert campaign.overflow[0].origin == MINIMIZATION_OVERFLOW
        assert campaign.overflow[0].fingerprint == sibling.fingerprint
    else:
        assert campaign.stop_reason == STRATEGY_EXHAUSTED
        assert {item.fingerprint for item in campaign.findings} == {
            primary.fingerprint,
            sibling.fingerprint,
        }


def test_matrix_input_order_does_not_change_campaign_finding_order() -> None:
    case = _case(1)
    failures = tuple(_failure(f"writer-{index}", f"failure {index}") for index in range(3))

    def collect(ordered: tuple[CellResult, ...]) -> tuple[FailureFingerprint, ...]:
        collector = _collector({case.case_id: _run(case, *ordered)}, max_saved=3)
        collector.observe(case)
        return tuple(
            item.fingerprint for item in collector.close(_finding, examples=1, seed=1).findings
        )

    forward = collect(failures)
    reversed_order = collect(tuple(reversed(failures)))

    assert forward == reversed_order
    assert tuple(map(finding_key, forward)) == tuple(sorted(map(finding_key, forward)))
