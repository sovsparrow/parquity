from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import cast

from hypothesis import HealthCheck, find, given, settings
from hypothesis import strategies as st

from parquity.evidence import EngineVersion
from parquity.generation.evidence import SAVED_EVIDENCE_LIMIT_REACHED
from parquity.generation.reduce import reduce_case
from parquity.generation.search.campaign import (
    find_case_observations,
    search_cases,
)
from parquity.generation.strategies import bounded_cases
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, MatrixRun, Verdict

_LEGACY_KINDS = {Kind.BOOL, Kind.INT32, Kind.INT64, Kind.STRING, Kind.BINARY}
_EVALUATION_WRITERS = tuple(EngineVersion(name, "1") for name in ("pyarrow", "duckdb", "polars"))
_EVALUATION_READERS = (EngineVersion("reader", "1"),)


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


def _passing(writer: EngineVersion, reader: EngineVersion) -> CellResult:
    engines = (writer.name, writer.version, reader.name, reader.version)
    return CellResult(*engines, "compare", Verdict.PASS, "$", "")


def _run(case: Case, *failures: CellResult) -> MatrixRun:
    by_writer = {item.writer: item for item in failures}
    reader = _EVALUATION_READERS[0]
    results = tuple(
        by_writer.get(writer.name) or _passing(writer, reader) for writer in _EVALUATION_WRITERS
    )
    return MatrixRun(case.case_id, results, (), _EVALUATION_WRITERS, _EVALUATION_READERS)


def _value(case: Case) -> int | None:
    return cast(int, case.rows[0][0]) if case.rows else None


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
            assert field.type_spec.kind in _LEGACY_KINDS
            _assert_bounded_value(field.type_spec, field.nullable, mapping[field.name])


def _contains_kind(spec: TypeSpec, target: Kind) -> bool:
    if spec.kind is target:
        return True
    children = (
        *(field.type_spec for field in spec.fields),
        *(value for value in (spec.item, spec.key, spec.value) if value is not None),
    )
    return any(_contains_kind(child, target) for child in children)


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


def test_bounded_cases_reach_every_supported_kind_through_the_public_strategy() -> None:
    search_settings = settings(
        max_examples=5_000,
        database=None,
        deadline=None,
        derandomize=True,
        suppress_health_check=(HealthCheck.too_slow,),
    )
    for target in Kind:
        case = find(
            bounded_cases(),
            lambda candidate, target=target: any(
                _contains_kind(field.type_spec, target) for field in candidate.fields
            ),
            settings=search_settings,
        )
        assert any(_contains_kind(field.type_spec, target) for field in case.fields), target


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


def test_fingerprint_cap_stops_after_recording_the_first_overflow() -> None:
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
        max_saved=1,
    )

    assert campaign is not None
    assert len(campaign.findings) == 1
    assert len(campaign.overflow) == 1
    assert campaign.stop_reason == SAVED_EVIDENCE_LIMIT_REACHED
    assert campaign.evaluated_cases == 2


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
    retained = search_cases(st.just(case), examples=2, seed=1, evaluator=evaluate, max_saved=2)
    assert retained is not None and len(retained.findings) == 2 and not retained.overflow
    campaign = search_cases(st.just(case), examples=2, seed=1, evaluator=evaluate, max_saved=1)
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
    nested_list = TypeSpec(Kind.FIXED_LIST, item=variable, item_nullable=True, size=1)
    map_key = TypeSpec(Kind.STRUCT, fields=(Field("ki", variable), Field("guard", integer)))
    map_value = TypeSpec(Kind.STRUCT, fields=(Field("vi", variable),))
    mapping = TypeSpec(Kind.MAP, key=map_key, value=map_value, value_nullable=True)
    fields = (
        Field("flag", TypeSpec(Kind.BOOL)),
        Field("number", TypeSpec(Kind.INT64)),
        Field("text", TypeSpec(Kind.STRING)),
        Field("payload", TypeSpec(Kind.BINARY)),
        Field("fixed", fixed),
        Field("nested_list", nested_list),
        Field("mapping", mapping),
    )
    map_row = [[{"ki": [7], "guard": 8}, {"vi": [7]}]]
    values = (True, 7, "x", b"x", [7, 8], [[7]], map_row)
    case = Case(fields, (values,))
    required = {field.name for field in fields}

    def evaluate(candidate: Case, directory: Path) -> MatrixRun:
        del directory
        names = {field.name for field in candidate.fields}
        populated_map = bool(candidate.rows) and names == required and bool(candidate.rows[0][-1])
        results = (
            (_failure(),) if candidate.rows and (populated_map or names == {"nullable"}) else ()
        )
        return _run(candidate, *results)

    finding = find_case_observations(case, evaluate)[0]

    empty: list[object] = []
    minimized_map = [[{"guard": 0}, {"vi": empty}]]
    expected = (False, 0, "", b"", [0], [empty], minimized_map)
    assert finding.case.rows == (expected,)
    assert finding.reductions.fields == 0
    reductions = finding.reductions
    assert reductions.nullability >= 14 and reductions.containers >= 4 and reductions.scalars >= 6
    assert reductions.to_data()["total"] == reductions.total

    nullable = Case(
        (Field("nullable", TypeSpec(Kind.LIST, item=integer, item_nullable=False)),), ((None,),)
    )
    unchanged = find_case_observations(nullable, evaluate)[0]
    assert unchanged.case == nullable
