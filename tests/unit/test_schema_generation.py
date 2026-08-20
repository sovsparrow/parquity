from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from hypothesis import HealthCheck, find, settings

from parquity.evidence import EngineVersion
from parquity.generation.evidence import DISCOVERY_OVERFLOW
from parquity.generation.schema import SchemaPlan, SchemaProfileError, load_schema
from parquity.generation.search.campaign import find_case_observations, search_cases
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, MatrixRun, Verdict


def _field(name: str, spec: TypeSpec | None = None, *, nullable: bool = False) -> Field:
    return Field(name, TypeSpec(Kind.INT32) if spec is None else spec, nullable=nullable)


def _nested_list(depth: int) -> TypeSpec:
    spec = TypeSpec(Kind.INT32)
    for _ in range(depth - 1):
        spec = TypeSpec(Kind.LIST, item=spec, item_nullable=True)
    return spec


def _failure(case: Case, detail: str = "controlled failure") -> MatrixRun:
    result = CellResult(
        "writer", "1", "*", "*", "write", Verdict.WRITE_ERROR, "$", detail, "Controlled"
    )
    return MatrixRun(
        case.case_id,
        (result,),
        (),
        (EngineVersion("writer", "1"),),
        (EngineVersion("reader", "1"),),
    )


def _pass(case: Case) -> MatrixRun:
    result = CellResult("writer", "1", "reader", "1", "compare", Verdict.PASS, "$", "")
    return MatrixRun(
        case.case_id,
        (result,),
        (),
        (EngineVersion("writer", "1"),),
        (EngineVersion("reader", "1"),),
    )


def _search_settings() -> settings:
    return settings(
        max_examples=500,
        database=None,
        deadline=None,
        derandomize=True,
        suppress_health_check=(HealthCheck.too_slow,),
    )


def _schema_document(type_data: dict[str, object]) -> dict[str, object]:
    return {
        "format": "parquity.case.v1",
        "schema": [{"name": "value", "nullable": False, "type": type_data}],
        "rows": [],
    }


def test_schema_plan_uses_the_ordinary_empty_row_identity_and_exact_budget_boundaries() -> None:
    identity_case = Case((_field("value"),), ())
    expected_payload = json.dumps(
        _schema_document({"kind": "int32"}),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert (
        SchemaPlan.from_case(identity_case).schema_case_id
        == hashlib.sha256(expected_payload).hexdigest()
    )

    depth_boundary = Case((_field("value", _nested_list(4)),), ())
    depth_plan = SchemaPlan.from_case(depth_boundary)
    assert depth_plan.schema_case_id == depth_boundary.case_id

    node_boundary = Case(tuple(_field(f"field_{index}") for index in range(64)), ())
    assert SchemaPlan.from_case(node_boundary).schema_case_id == node_boundary.case_id

    slot_boundary = Case(
        (_field("values", TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=256)),),
        (),
    )
    assert SchemaPlan.from_case(slot_boundary).schema_case_id == slot_boundary.case_id

    over = (
        Case((_field("value", _nested_list(5)),), ()),
        Case(tuple(_field(f"field_{index}") for index in range(65)), ()),
        Case(
            (
                _field(
                    "values",
                    TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=257),
                ),
            ),
            (),
        ),
    )
    for case in over:
        with pytest.raises(SchemaProfileError) as raised:
            SchemaPlan.from_case(case)
        assert raised.value.kind == "SCHEMA_LIMIT_EXCEEDED"


def test_schema_loading_rejects_unreadable_malformed_wrong_format_and_non_empty_cases(
    tmp_path: Path,
) -> None:
    invalid = {
        "missing": tmp_path / "missing.json",
        "malformed": tmp_path / "malformed.json",
        "duplicate": tmp_path / "duplicate.json",
        "wrong": tmp_path / "wrong.json",
        "rows": tmp_path / "rows.json",
    }
    invalid["malformed"].write_text("{", encoding="utf-8")
    invalid["duplicate"].write_text(
        '{"format":"parquity.case.v1","schema":[],"schema":[],"rows":[]}', encoding="utf-8"
    )
    invalid["wrong"].write_text('{"format":"other","schema":[],"rows":[]}', encoding="utf-8")
    case = Case((_field("value"),), ((1,),))
    invalid["rows"].write_bytes(case.canonical_bytes())
    for name, path in invalid.items():
        with pytest.raises(SchemaProfileError) as raised:
            load_schema(path)
        expected = "SCHEMA_UNREADABLE" if name == "missing" else "INVALID_SCHEMA"
        assert raised.value.kind == expected

    malformed_grammar: dict[str, dict[str, object]] = {
        "root_missing": {"format": "parquity.case.v1", "schema": []},
        "root_extra": {**_schema_document({"kind": "int32"}), "extra": True},
        "field_missing": {
            "format": "parquity.case.v1",
            "schema": [{"name": "value", "type": {"kind": "int32"}}],
            "rows": [],
        },
        "field_extra": {
            "format": "parquity.case.v1",
            "schema": [{"name": "value", "nullable": False, "type": {"kind": "int32"}, "x": 1}],
            "rows": [],
        },
        "scalar_forbidden": _schema_document({"kind": "int32", "size": 1}),
        "list_missing": _schema_document({"kind": "list", "item": {"kind": "int32"}}),
        "list_forbidden": _schema_document(
            {"kind": "list", "item": {"kind": "int32"}, "item_nullable": False, "size": 2}
        ),
        "fixed_missing": _schema_document(
            {"kind": "fixed_list", "item": {"kind": "int32"}, "item_nullable": False}
        ),
        "fixed_extra": _schema_document(
            {
                "kind": "fixed_list",
                "item": {"kind": "int32"},
                "item_nullable": False,
                "size": 2,
                "fields": [],
            }
        ),
        "struct_missing": _schema_document({"kind": "struct"}),
        "struct_forbidden": _schema_document(
            {"kind": "struct", "fields": [], "item_nullable": False}
        ),
        "recursive_invalid": _schema_document(
            {
                "kind": "struct",
                "fields": [
                    {
                        "name": "child",
                        "nullable": False,
                        "type": {
                            "kind": "list",
                            "item": {"kind": "bool", "fields": []},
                            "item_nullable": True,
                        },
                    }
                ],
            }
        ),
    }
    for name, document in malformed_grammar.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(SchemaProfileError) as raised:
            load_schema(path)
        assert raised.value.kind == "INVALID_SCHEMA"

    over_budget = tmp_path / "over-budget.json"
    over_budget.write_bytes(Case((_field("value", _nested_list(5)),), ()).canonical_bytes())
    with pytest.raises(SchemaProfileError) as raised:
        load_schema(over_budget)
    assert raised.value.kind == "SCHEMA_LIMIT_EXCEEDED"


def test_fixed_schema_strategy_covers_bounded_rows_nested_values_and_fixed_width() -> None:
    scalar = TypeSpec(Kind.INT64)
    fields = (
        _field("optional", TypeSpec(Kind.STRING), nullable=True),
        _field("binary", TypeSpec(Kind.BINARY)),
        _field("items", TypeSpec(Kind.LIST, item=scalar, item_nullable=True)),
        _field(
            "fixed",
            TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), item_nullable=False, size=6),
        ),
        _field(
            "record",
            TypeSpec(
                Kind.STRUCT,
                fields=(
                    _field("flag", TypeSpec(Kind.BOOL), nullable=True),
                    _field("text", TypeSpec(Kind.STRING)),
                ),
            ),
        ),
    )
    plan = SchemaPlan.from_case(Case(fields, ()))
    zero = find(plan.cases(), lambda case: len(case.rows) == 0, settings=_search_settings())
    four = find(plan.cases(), lambda case: len(case.rows) == 4, settings=_search_settings())
    populated = find(
        plan.cases(),
        lambda case: (
            bool(case.rows)
            and isinstance(case.rows[0][0], str)
            and bool(case.rows[0][0])
            and isinstance(case.rows[0][1], bytes)
            and bool(case.rows[0][1])
            and len(cast(list[object], case.rows[0][2])) == 4
            and isinstance(cast(dict[str, object], case.rows[0][4])["text"], str)
            and bool(cast(dict[str, object], case.rows[0][4])["text"])
        ),
        settings=_search_settings(),
    )
    nullable = find(
        plan.cases(),
        lambda case: (
            bool(case.rows)
            and case.rows[0][0] is None
            and None in cast(list[object], case.rows[0][2])
            and cast(dict[str, object], case.rows[0][4])["flag"] is None
        ),
        settings=_search_settings(),
    )
    assert all(plan.admits(case) for case in (zero, four, populated, nullable))
    assert zero.rows == () and len(four.rows) == 4
    row = populated.rows[0]
    assert 0 < len(cast(str, row[0])) <= 12
    assert 0 < len(cast(bytes, row[1])) <= 12
    assert len(cast(list[object], row[2])) == 4
    assert len(cast(list[object], row[3])) == 6
    assert all(isinstance(value, bool) for value in cast(list[object], row[3]))
    record = cast(dict[str, object], row[4])
    assert set(record) == {"flag", "text"}
    assert 0 < len(cast(str, record["text"])) <= 12


def test_schema_guard_precedes_evaluation_and_reduction_changes_only_rows_and_values(
    tmp_path: Path,
) -> None:
    integer = TypeSpec(Kind.INT32)
    variable = TypeSpec(Kind.LIST, item=integer, item_nullable=False)
    fixed = TypeSpec(Kind.FIXED_LIST, item=integer, item_nullable=False, size=2)
    fields = (_field("items", variable), _field("fixed", fixed))
    discovered = Case(fields, (([7, 8], [7, 8]), ([9, 10], [9, 9])))
    plan = SchemaPlan.from_case(Case(fields, ()))

    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        assert plan.admits(case)
        items = cast(list[object], case.rows[0][0]) if case.rows else []
        return _failure(case) if items else _pass(case)

    guarded = plan.bind(evaluate)
    finding = find_case_observations(discovered, guarded, plan.admits)[0]
    assert finding.case.rows == (([0], [0, 0]),)
    assert finding.reductions.rows == 1
    assert finding.reductions.containers >= 1
    assert finding.reductions.scalars >= 1
    assert (finding.reductions.fields, finding.reductions.nullability) == (0, 0)

    foreign = Case((_field("other"),), ((1,),))
    with pytest.raises(RuntimeError):
        guarded(foreign, tmp_path)


def test_schema_search_retains_fingerprints_records_overflow_and_is_seeded() -> None:
    fields = (_field("value"),)
    plan = SchemaPlan.from_case(Case(fields, ()))

    def evaluate(case: Case, directory: Path) -> MatrixRun:
        del directory
        first = CellResult(
            "first", "1", "*", "*", "write", Verdict.WRITE_ERROR, "$", "first", "First"
        )
        second = CellResult(
            "second", "1", "*", "*", "write", Verdict.WRITE_ERROR, "$", "second", "Second"
        )
        return MatrixRun(
            case.case_id,
            (first, second),
            (),
            (EngineVersion("first", "1"), EngineVersion("second", "1")),
            (EngineVersion("reader", "1"),),
        )

    evaluator = plan.bind(evaluate)
    complete = search_cases(
        plan.cases(),
        examples=4,
        seed=17,
        evaluator=evaluator,
        candidate_admission=plan.admits,
        max_saved=2,
    )
    capped = search_cases(
        plan.cases(),
        examples=4,
        seed=17,
        evaluator=evaluator,
        candidate_admission=plan.admits,
        max_saved=1,
    )
    repeated = search_cases(
        plan.cases(),
        examples=4,
        seed=17,
        evaluator=evaluator,
        candidate_admission=plan.admits,
        max_saved=2,
    )
    assert complete is not None and capped is not None and repeated is not None
    assert len(complete.findings) == 2 and not complete.overflow
    assert len(capped.findings) == len(capped.overflow) == 1
    assert (complete.evaluated_cases, complete.evaluated_cells) == (4, 8)
    assert (capped.evaluated_cases, capped.evaluated_cells) == (1, 2)
    assert capped.overflow[0].origin == DISCOVERY_OVERFLOW
    assert [item.case.canonical_bytes() for item in complete.findings] == [
        item.case.canonical_bytes() for item in repeated.findings
    ]
    assert all(plan.admits(item.case) for item in complete.findings)
