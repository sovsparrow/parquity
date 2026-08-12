from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import strategies as st

from parquity.configuration import (
    fuzz_examples_is_valid,
    fuzz_saved_limit_is_valid,
    fuzz_seed_is_valid,
)
from parquity.evidence import EngineVersion
from parquity.findings.model import FindingValidationError
from parquity.generation.evidence import EXAMPLE_BOUND_REACHED, DiscoveryEvidence
from parquity.generation.search.campaign import search_cases
from parquity.generation.search.evaluation import CampaignEvaluator, EvaluationContext
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.profiles import (
    CapabilityStatus,
    WriterProfileCapability,
    WriterProfileIdentity,
    WriterProfilePlan,
)
from parquity.verdicts import CellResult, MatrixRun, Verdict


def _case(value: int) -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32)),), ((value,),))


@pytest.mark.parametrize(
    ("examples", "seed", "max_saved"),
    (
        (True, 0, 1),
        (1, True, 1),
        (1, 0, True),
        (0, 0, 1),
        (1, -1, 1),
        (1, 2**64, 1),
        (1, 0, 0),
        (1, 0, 65),
    ),
)
def test_every_fuzz_boundary_rejects_the_same_invalid_table(
    examples: int, seed: int, max_saved: int
) -> None:
    assert not (
        fuzz_examples_is_valid(examples)
        and fuzz_seed_is_valid(seed)
        and fuzz_saved_limit_is_valid(max_saved)
    )
    with pytest.raises(ValueError):
        search_cases(
            st.just(_case(1)),
            examples=examples,
            seed=seed,
            max_saved=max_saved,
            evaluator=_unreachable,
        )
    with pytest.raises(FindingValidationError):
        DiscoveryEvidence(examples, seed, max_saved, EXAMPLE_BOUND_REACHED)


def _unreachable(case: Case, directory: Path) -> MatrixRun:
    del case, directory
    raise AssertionError("invalid search bounds reached the evaluator")


def _profile_plan(writer: EngineVersion) -> WriterProfilePlan:
    profile = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    return WriterProfilePlan(
        ("compression-gzip",),
        (
            WriterProfileCapability(
                writer,
                "compression-gzip",
                CapabilityStatus.SUPPORTED,
                profile,
            ),
        ),
    )


def _passing_run(
    case: Case,
    writer: EngineVersion,
    reader: EngineVersion,
    plan: WriterProfilePlan | None = None,
) -> MatrixRun:
    executions = (
        ((writer, None),)
        if plan is None
        else tuple((item.writer, item.writer_profile) for item in plan.executions((writer,)))
    )
    results = tuple(
        CellResult(
            execution_writer.name,
            execution_writer.version,
            reader.name,
            reader.version,
            "compare",
            Verdict.PASS,
            "$",
            "match",
            writer_profile=profile,
        )
        for execution_writer, profile in executions
    )
    return MatrixRun(case.case_id, results, (), (writer,), (reader,), plan)


def test_explicit_campaign_context_checks_the_first_and_later_fresh_runs() -> None:
    writer = EngineVersion("writer", "1")
    reader = EngineVersion("reader", "1")
    context = EvaluationContext((writer,), (reader,))

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        current = writer if candidate == _case(1) else EngineVersion("writer", "2")
        return _passing_run(candidate, current, reader)

    evaluation = CampaignEvaluator(evaluate, context=context)
    evaluation(_case(1))
    with pytest.raises(RuntimeError, match="evaluation context changed"):
        evaluation(_case(2))

    plan = _profile_plan(writer)
    profiled_context = EvaluationContext((writer,), (EngineVersion("reader", "1"),), plan)

    def evaluate_without_profile(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        return _passing_run(candidate, writer, reader)

    profiled = CampaignEvaluator(evaluate_without_profile, context=profiled_context)
    with pytest.raises(RuntimeError, match="evaluation context changed"):
        profiled(_case(3))


@pytest.mark.parametrize("dimension", ("writer", "reader", "writer_profile"))
def test_inferred_campaign_context_rejects_each_independent_drift(dimension: str) -> None:
    writer = EngineVersion("writer", "1")
    reader = EngineVersion("reader", "1")

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        if candidate == _case(1):
            return _passing_run(candidate, writer, reader)
        changed_writer = EngineVersion("writer", "2") if dimension == "writer" else writer
        changed_reader = EngineVersion("reader", "2") if dimension == "reader" else reader
        plan = _profile_plan(changed_writer) if dimension == "writer_profile" else None
        return _passing_run(candidate, changed_writer, changed_reader, plan)

    inferred = CampaignEvaluator(evaluate)
    inferred(_case(1))
    with pytest.raises(RuntimeError, match="evaluation context changed"):
        inferred(_case(2))
