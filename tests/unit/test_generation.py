from __future__ import annotations

import random
from functools import partial
from pathlib import Path
from typing import cast

import pytest
from hypothesis import HealthCheck, find, given, settings
from hypothesis import strategies as st

from parquity.generation.reduce import reduce_case
from parquity.generation.search import (
    EXAMPLE_BOUND_REACHED,
    FINDING_CAP_REACHED,
    find_case_observations,
    search_cases,
)
from parquity.generation.strategies import bounded_cases
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict


def _integer_case(value: int) -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((value,),))


def _failure(
    *,
    writer: str = "pyarrow",
    version: str = "1",
    detail: str = "controlled failure",
    diagnostic_kind: str = "ControlledError",
) -> CellResult:
    return CellResult(
        writer, version, "*", "*", "write", Verdict.WRITE_ERROR, "$", detail, diagnostic_kind
    )


def _run(case: Case, *failures: CellResult) -> MatrixRun:
    readers = (EngineVersion("reader", "1"),)
    if failures:
        writers = tuple(EngineVersion(item.writer, item.writer_version) for item in failures)
        return MatrixRun(case.case_id, failures, (), writers, readers)
    passing = CellResult("pyarrow", "1", "reader", "1", "compare", Verdict.PASS, "$", "")
    return MatrixRun(case.case_id, (passing,), (), (EngineVersion("pyarrow", "1"),), readers)


def _value(case: Case) -> int | None:
    return cast(int, case.rows[0][0]) if case.rows else None


def _has_top_level_kind(candidate: Case, *, kind: Kind) -> bool:
    return any(field.type_spec.kind is kind for field in candidate.fields)


def _assert_bounded_value(spec: TypeSpec, nullable: bool, value: object) -> None:
    if value is None:
        assert nullable
        return
    if spec.kind is Kind.STRING:
        assert isinstance(value, str)
        assert len(value) <= 12
    elif spec.kind is Kind.BINARY:
        assert isinstance(value, bytes)
        assert len(value) <= 12
    elif spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        assert isinstance(value, list)
        items = cast(list[object], value)
        maximum = 4 if spec.size is None else spec.size
        assert len(items) <= maximum
        if spec.size is not None:
            assert len(items) == spec.size
        item = cast(TypeSpec, spec.item)
        for child in items:
            _assert_bounded_value(item, spec.item_nullable, child)
    elif spec.kind is Kind.STRUCT:
        assert isinstance(value, dict)
        mapping = cast(dict[str, object], value)
        assert 1 <= len(spec.fields) <= 3
        for field in spec.fields:
            assert field.type_spec.kind in (
                Kind.BOOL,
                Kind.INT32,
                Kind.INT64,
                Kind.STRING,
                Kind.BINARY,
            )
            _assert_bounded_value(field.type_spec, field.nullable, mapping[field.name])


@settings(
    max_examples=40,
    database=None,
    deadline=None,
    derandomize=True,
    suppress_health_check=(HealthCheck.too_slow,),
)
@given(case=bounded_cases())
def test_bounded_cases_respect_every_public_size_and_shape_limit(case: Case) -> None:
    assert 1 <= len(case.fields) <= 4
    assert len(case.rows) <= 4
    for row in case.rows:
        for field, value in zip(case.fields, row, strict=True):
            _assert_bounded_value(field.type_spec, field.nullable, value)


def test_bounded_cases_reach_every_supported_kind_with_real_hypothesis() -> None:
    search_settings = settings(
        max_examples=500,
        database=None,
        deadline=None,
        suppress_health_check=(HealthCheck.too_slow,),
    )
    for kind in Kind:
        case = find(
            bounded_cases(),
            partial(_has_top_level_kind, kind=kind),
            settings=search_settings,
            random=random.Random(0),  # noqa: S311 - deterministic test search, not security.
        )
        assert any(field.type_spec.kind is kind for field in case.fields)


def test_one_case_retains_every_failure_and_orders_full_fingerprints_canonically() -> None:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        return _run(case, _failure(writer="pyarrow"), _failure(writer="duckdb"))

    campaign = search_cases(st.just(_integer_case(3)), examples=4, seed=7, evaluator=evaluate)

    assert campaign is not None
    fingerprints = [finding.fingerprint for finding in campaign.findings]
    assert {fingerprint.writer for fingerprint in fingerprints} == {"pyarrow", "duckdb"}
    assert fingerprints == sorted(fingerprints, key=lambda item: item.canonical_bytes())
    assert campaign.stop_reason == EXAMPLE_BOUND_REACHED


def test_discovery_continues_after_first_failing_case_and_deduplicates_across_cases() -> None:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        value = _value(case)
        if value == 0 or value is None:
            return _run(case)
        writer = "pyarrow" if value in (1, 3) else "duckdb"
        return _run(case, _failure(writer=writer))

    strategy = st.sampled_from((0, 1, 2, 3)).map(_integer_case)
    campaign = search_cases(strategy, examples=8, seed=1, evaluator=evaluate)

    assert campaign is not None
    assert {finding.fingerprint.writer for finding in campaign.findings} == {
        "pyarrow",
        "duckdb",
    }
    assert len(campaign.findings) == 2


def test_detail_normalization_removes_only_whitespace_and_owned_temporary_paths() -> None:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        value = _value(case)
        detail = f" controlled   failure\ninside {directory} value 7 "
        kind = "FirstError" if value in (1, 2) else "SecondError"
        return _run(case, _failure(detail=detail, diagnostic_kind=kind))

    strategy = st.sampled_from((1, 2, 3)).map(_integer_case)
    campaign = search_cases(strategy, examples=6, seed=4, evaluator=evaluate)

    assert campaign is not None
    assert len(campaign.findings) == 2
    first = next(
        item for item in campaign.findings if item.fingerprint.diagnostic_kind == "FirstError"
    )
    assert first.result.detail == "controlled failure inside <parquity-temp>/evaluation value 7"
    assert "7" in first.result.detail


def test_finding_cap_records_the_unmaterialized_fingerprint_without_exhaustive_claim() -> None:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        value = _value(case)
        if value is None:
            return _run(case)
        return _run(case, _failure(detail=f"failure {value}"))

    strategy = st.sampled_from((1, 2, 3)).map(_integer_case)
    campaign = search_cases(
        strategy,
        examples=8,
        seed=2,
        evaluator=evaluate,
        max_findings=1,
    )

    assert campaign is not None
    assert len(campaign.findings) == 1
    assert len(campaign.overflow) >= 1
    assert campaign.stop_reason == FINDING_CAP_REACHED
    assert all(item.stop_reason == FINDING_CAP_REACHED for item in campaign.overflow)


def test_structural_reduction_reaches_a_cross_category_fixed_point() -> None:
    integer = TypeSpec(Kind.INT32)
    fields = (Field("irrelevant", integer, False), Field("target", integer, False))
    case = Case(fields, ((99, 2), (88, 1)))

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        names = [field.name for field in candidate.fields]
        if "target" not in names:
            return _run(candidate)
        target = names.index("target")
        values = tuple(row[target] for row in candidate.rows)
        failed = values == (2, 1) or 0 in values
        failures = [_failure(detail="controlled target")] if failed else []
        if failed and "irrelevant" not in names:
            failures.append(_failure(writer="duckdb", detail="minimized sibling"))
        return _run(candidate, *failures)

    findings = find_case_observations(case, evaluate)
    assert {item.fingerprint.writer for item in findings} == {"pyarrow", "duckdb"}
    finding = next(item for item in findings if item.fingerprint.writer == "pyarrow")
    assert tuple(field.name for field in finding.case.fields) == ("target",)
    assert finding.case.rows == ((0,),)
    counts = (finding.reductions.fields, finding.reductions.rows, finding.reductions.scalars)
    assert counts == (1, 1, 2)
    assert finding.result.fingerprint == finding.fingerprint
    evaluate_case = partial(evaluate, directory=Path("."))
    second = reduce_case(finding.case, finding.run, finding.fingerprint, evaluate_case)
    assert second.case.canonical_bytes() == finding.case.canonical_bytes()
    assert second.run == finding.run and second.counts.total == 0
    retained = search_cases(st.just(case), examples=2, seed=1, evaluator=evaluate, max_findings=2)
    assert retained is not None and len(retained.findings) == 2 and not retained.overflow
    campaign = search_cases(st.just(case), examples=2, seed=1, evaluator=evaluate, max_findings=1)
    assert campaign is not None
    assert len(campaign.findings) == len(campaign.overflow) == 1
    assert campaign.overflow[0].fingerprint.writer == "duckdb"


def test_structural_reduction_rejects_a_coarse_match_with_changed_diagnostic_kind() -> None:
    case = Case(
        (
            Field("target", TypeSpec(Kind.INT32), nullable=False),
            Field("guard", TypeSpec(Kind.INT32), nullable=False),
        ),
        ((7, 1),),
    )

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        names = [field.name for field in candidate.fields]
        if "target" not in names or not candidate.rows:
            return _run(candidate)
        kind = "OriginalError" if "guard" in names else "ChangedError"
        return _run(candidate, _failure(diagnostic_kind=kind))

    finding = find_case_observations(case, evaluate)[0]

    assert [field.name for field in finding.case.fields] == ["target", "guard"]
    assert finding.fingerprint.diagnostic_kind == "OriginalError"
    assert finding.reductions.fields == 0


def test_no_satisfying_case_is_the_only_no_finding_result() -> None:
    def pass_case(case: Case, directory: Path) -> MatrixRun:
        del directory
        return _run(case)

    assert search_cases(st.just(_integer_case(0)), examples=3, seed=5, evaluator=pass_case) is None


@pytest.mark.parametrize(
    ("examples", "seed", "max_findings"),
    ((0, 0, 1), (True, 0, 1), (1, -1, 1), (1, True, 1), (1, 0, 0), (1, 0, 65)),
)
def test_search_rejects_invalid_bounds(examples: int, seed: int, max_findings: int) -> None:
    with pytest.raises(ValueError):
        search_cases(
            st.just(_integer_case(1)),
            examples=examples,
            seed=seed,
            max_findings=max_findings,
            evaluator=lambda case, directory: _run(case),
        )


def test_same_seed_reproduces_all_reduced_findings_in_one_controlled_environment() -> None:
    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        value = _value(case)
        results = () if value is None or value < 4 else (_failure(writer="polars"),)
        return _run(case, *results)

    strategy = st.integers(min_value=0, max_value=20).map(_integer_case)
    first = search_cases(strategy, examples=30, seed=19, evaluator=evaluate)
    second = search_cases(strategy, examples=30, seed=19, evaluator=evaluate)

    assert first is not None and second is not None
    assert [item.case.canonical_bytes() for item in first.findings] == [
        item.case.canonical_bytes() for item in second.findings
    ]
    assert [item.fingerprint for item in first.findings] == [
        item.fingerprint for item in second.findings
    ]


def test_structural_reduction_traverses_every_nested_category() -> None:
    integer = TypeSpec(Kind.INT32)
    variable = TypeSpec(Kind.LIST, item=integer, item_nullable=True)
    fixed = TypeSpec(Kind.FIXED_LIST, item=integer, item_nullable=True, size=2)
    record = TypeSpec(Kind.STRUCT, fields=(Field("d", integer), Field("k", integer)))
    nested_list = TypeSpec(Kind.FIXED_LIST, item=variable, item_nullable=True, size=1)
    nested_record = TypeSpec(Kind.STRUCT, fields=(Field("i", variable),))
    fields = (
        Field("flag", TypeSpec(Kind.BOOL)),
        Field("number", TypeSpec(Kind.INT64)),
        Field("text", TypeSpec(Kind.STRING)),
        Field("payload", TypeSpec(Kind.BINARY)),
        Field("items", variable),
        Field("fixed", fixed),
        Field("record", record),
        Field("nested_list", nested_list),
        Field("nested_record", nested_record),
    )
    values = (True, 7, "x", b"x", [7], [7, 8], {"d": 7, "k": 8}, [[7]], {"i": [7]})
    case = Case(fields, (values,))
    required = {field.name for field in fields}

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        names = {field.name for field in candidate.fields}
        results = (_failure(),) if candidate.rows and names in (required, {"nullable"}) else ()
        return _run(candidate, *results)

    finding = find_case_observations(case, evaluate)[0]

    empty: list[object] = []
    expected = (False, 0, "", b"", empty, [0], {"k": 0}, [empty], {"i": empty})
    assert finding.case.rows == (expected,)
    assert finding.reductions.fields == 0
    assert finding.reductions.nullability >= 9
    assert finding.reductions.containers >= 5
    assert finding.reductions.scalars >= 6
    assert finding.reductions.to_data()["total"] == finding.reductions.total

    nullable = Case(
        (Field("nullable", TypeSpec(Kind.LIST, item=integer, item_nullable=False)),), ((None,),)
    )
    unchanged = find_case_observations(nullable, evaluate)[0]
    assert unchanged.case == nullable
