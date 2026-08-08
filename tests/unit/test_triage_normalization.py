import hashlib
from collections.abc import Mapping
from copy import deepcopy
from functools import partial
from typing import cast

import pytest

from parquity.model import Case, Field, Kind, TypeSpec
from parquity.scans import replay_evidence, symptoms
from parquity.triage.normalization import (
    DETAIL_RULES_V1,
    detail_sha256_v1,
    field_shape,
    normalize_detail_v1,
    normalize_generated_path,
    normalize_scan_path,
)


def test_detail_rules_are_declarative_versioned_and_conservative() -> None:
    source = " failure\ninside <parquity-temp>\\evaluation  value 7 "
    expected = "failure inside <parquity-temp>/evaluation value 7"
    assert tuple(rule.name for rule in DETAIL_RULES_V1) == (
        "temporary-root-separator",
        "whitespace",
    )
    assert normalize_detail_v1(source) == expected
    assert detail_sha256_v1(source) == hashlib.sha256(expected.encode()).hexdigest()
    assert normalize_detail_v1("field_17 expected 1, got 2: ValueError") == (
        "field_17 expected 1, got 2: ValueError"
    )


def test_generated_rows_and_columns_use_name_free_semantic_shape() -> None:
    items = TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), item_nullable=False, size=2)
    nested = TypeSpec(Kind.STRUCT, fields=(Field("child_name", items, nullable=False),))
    renamed_nested = TypeSpec(Kind.STRUCT, fields=(Field("renamed_child", items, nullable=False),))
    first = Case((Field("alpha", nested, nullable=False),), (({"child_name": [1, 2]},),))
    renamed = Case((Field("beta", renamed_nested, False),), (({"renamed_child": [1, 2]},),))
    first_path = normalize_generated_path("$rows[7].alpha.child_name[1]", first)
    renamed_path = normalize_generated_path("$rows[0].beta.renamed_child[1]", renamed)
    assert first_path == renamed_path
    assert first_path == {
        "root": "rows",
        "row": "*",
        "column": field_shape(first.fields[0]),
        "path": [
            {"struct_field": 0, "shape": field_shape(nested.fields[0])},
            {"container_item": 1, "shape": {"nullable": False, "type": {"kind": "int32"}}},
        ],
    }
    rendered_paths = repr((first_path, renamed_path))
    field_names = ("alpha", "beta", "child_name", "renamed_child")
    assert all(name not in rendered_paths for name in field_names)
    assert normalize_generated_path("$rows[7].alpha.child_name[0]", first) != first_path
    changed_items = TypeSpec(
        Kind.FIXED_LIST, item=TypeSpec(Kind.INT64), item_nullable=False, size=2
    )
    changed = TypeSpec(Kind.STRUCT, fields=(Field("child_name", changed_items, nullable=False),))
    changed_case = Case((Field("alpha", changed, nullable=False),), (({"child_name": [1, 2]},),))
    assert normalize_generated_path("$rows[0].alpha.child_name[1]", changed_case) != first_path
    assert normalize_generated_path("$schema.alpha.child_name[]", first) != first_path


def test_generated_shape_changes_and_untransformable_paths_remain_distinct() -> None:
    integer = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))
    required = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))
    string = Case((Field("value", TypeSpec(Kind.STRING)),), (("x",),))
    nullable_path = normalize_generated_path("$schema.value", integer)
    required_path = normalize_generated_path("$schema.value", required)
    string_path = normalize_generated_path("$schema.value", string)
    assert len({repr(nullable_path), repr(required_path), repr(string_path)}) == 3
    assert field_shape(integer.fields[0]) == {"nullable": True, "type": {"kind": "int32"}}
    assert normalize_generated_path("$rows[12]", integer) == "$rows[*]"
    assert normalize_generated_path("$rows", integer) == "$rows"
    assert normalize_generated_path("$", integer) == "$"
    assert normalize_generated_path("$schema.unknown", integer) == "$schema.unknown"

    key = TypeSpec(Kind.STRUCT, fields=(Field("member", TypeSpec(Kind.INT32)),))
    value = TypeSpec(Kind.LIST, item=TypeSpec(Kind.STRING), item_nullable=False)
    mapping = TypeSpec(Kind.MAP, key=key, value=value, value_nullable=False)
    map_case = Case((Field("mapping", mapping),), ())
    normalize_map = partial(normalize_generated_path, case=map_case)
    key_path = cast(dict[str, object], normalize_map("$schema.mapping.key.member"))
    value_path = cast(dict[str, object], normalize_map("$schema.mapping.value[]"))
    key_steps = cast(list[Mapping[str, object]], key_path["path"])
    value_steps = cast(list[Mapping[str, object]], value_path["path"])
    assert key_path != value_path
    assert [set(step) for step in key_steps] == [{"map_key", "shape"}, {"struct_field", "shape"}]
    assert [set(step) for step in value_steps] == [
        {"map_value", "shape"},
        {"container_item", "shape"},
    ]


def test_scan_normalization_changes_rows_only() -> None:
    assert normalize_scan_path("$.rows[19].columns[7]") == "$.rows[*].columns[7]"
    assert normalize_scan_path("$.rows") == "$.rows"
    assert normalize_scan_path("$.schema.fields[4]") == "$.schema.fields[4]"


def _outcome(engine: str, kind: str = "SUCCESS") -> Mapping[str, object]:
    return {
        "engine": engine,
        "kind": kind,
        "diagnostic_kind": kind,
        "detail": "" if kind == "SUCCESS" else "failure",
    }


def _edge(left: int, right: int, path: str, detail: str) -> Mapping[str, object]:
    return {
        "left_group": f"group-{left}",
        "right_group": f"group-{right}",
        "kind": "VALUE_DIFFERENCE",
        "path": path,
        "detail": detail,
    }


def _validate(result: Mapping[str, object], original: symptoms.ScanSymptom) -> None:
    originals = {original.occurrence_id: original}
    replay_evidence.validate_results(
        (result,), tuple(originals), originals, original.reader_roster, normalize_detail_v1
    )


def test_scan_symptoms_fan_out_conserve_edges_and_type_row_counts() -> None:
    outcomes = (*(_outcome(name) for name in ("a", "b", "c")), _outcome("d", "PROCESS_CRASH"))
    groups = tuple(
        {"id": f"group-{index}", "engines": [name]} for index, name in enumerate(("a", "b", "c"), 1)
    )
    edges = (
        _edge(1, 2, "$.rows[0].columns[2]", "a-b"),
        _edge(1, 3, "$.rows[8].columns[2]", "a-c"),
        _edge(2, 3, "$.rows[9].columns[2]", "b-c"),
    )
    extract = partial(symptoms.extract_evidence, "1" * 64, ("a", "b", "c", "d"), 30)
    compare = partial(replay_evidence.compare, normalize=normalize_detail_v1)
    combined = extract(outcomes, groups, edges, detail_sha256_v1)
    assert {item.signal for item in combined} == {"PROCESS_CRASH", "VALUE_DIFFERENCE"}
    semantic = next(item for item in combined if item.normalized_location is not None)
    assert semantic.normalized_location == "$.rows[*].columns[2]"
    assert len(semantic.evidence) == 3
    separated_edges = (*edges[:2], _edge(2, 3, "$.rows[9].columns[3]", "b-c"))
    separated = extract(outcomes, groups, separated_edges, detail_sha256_v1)
    assert (sum(len(item.evidence_indexes) for item in combined), len(separated)) == (4, 3)
    row_count = symptoms.extract_evidence(
        "2" * 64,
        ("a", "b"),
        30,
        outcomes[:2],
        groups[:2],
        (_edge(1, 2, "$.rows", "1 != 2"),),
        detail_sha256_v1,
    )[0]
    assert row_count.signal == "ROW_COUNT_DIFFERENCE"
    assert all(
        symptoms.summary_occurrence_id(item.finding_id, item.summary(), item.reader_roster)
        == item.occurrence_id
        for item in (*combined, *separated, row_count)
    )
    assert (
        symptoms.summary_occurrence_id("3" * 64, combined[0].summary(), combined[0].reader_roster)
        != combined[0].occurrence_id
    )
    changed_edges = (*edges[:2], _edge(2, 3, "$.rows[9].columns[2]", "changed"))
    related = extract(outcomes, groups, changed_edges, detail_sha256_v1)
    compared = compare(combined, related)
    states = {item["classification"] for item in compared.occurrence_results}
    assert states == {"REPRODUCED", "RELATED_FAILURE"}
    result = next(
        item for item in compared.occurrence_results if item["classification"] == "RELATED_FAILURE"
    )
    observation = cast(Mapping[str, object], result["current_observation"])
    changes = cast(list[Mapping[str, object]], observation["detail_changes"])
    assert len(changes) == 3 and observation["reader_roster"] == ["a", "b", "c", "d"]
    assert {item["original_detail"] for item in changes} == {"a-b", "a-c", "b-c"}

    current_evidence = cast(list[Mapping[str, object]], observation["evidence"])
    validate = partial(_validate, original=semantic)
    validate(result)
    updates: tuple[tuple[str, object], ...] = (
        ("detail_changes", changes[:-1]),
        ("detail_changes", [*changes, changes[0]]),
        ("detail_changes", list(reversed(changes))),
        ("reader_roster", ["a", "b", "foreign"]),
        ("signal", "SCHEMA_DIFFERENCE"),
        ("normalized_location", "$.rows[*].columns[3]"),
        ("evidence", []),
        ("evidence", [{**current_evidence[0], "groups": [["a"], ["d"]]}, *current_evidence[1:]]),
        ("extra", True),
        ("detail_changes", [{**changes[0], "current_detail_sha256": "0" * 64}, *changes[1:]]),
    )
    for key, value in updates:
        with pytest.raises(ValueError):
            validate({**result, "current_observation": {**observation, key: value}})
    for state in ("REPRODUCED", "NOT_REPRODUCED"):
        with pytest.raises(ValueError):
            validate({**result, "classification": state})
    with pytest.raises(ValueError):
        validate({"occurrence_id": semantic.occurrence_id, "classification": "RELATED_FAILURE"})
    changed_outcomes = (*outcomes[:3], _outcome("d", "PROVIDER_ERROR"))
    current = extract(changed_outcomes, groups, edges, detail_sha256_v1)
    compared = compare(combined, current)
    assert compared.classification == "RELATED_FAILURE" and len(compared.new_observations) == 1
    exact, absent = compare(combined, combined), compare(combined, ())
    assert (exact.classification, absent.classification) == ("REPRODUCED", "NOT_REPRODUCED")
    minimal = (*exact.occurrence_results, *absent.occurrence_results)
    assert all(set(item) == {"occurrence_id", "classification"} for item in minimal)


def test_scan_occurrence_summary_rejects_malformed_evidence() -> None:
    roster = ("reader", "a", "b")
    evidence = {
        "outcome_kind": "PROCESS_CRASH",
        "diagnostic_kind": "PROCESS_CRASH",
        "detail_sha256": "a" * 64,
    }
    valid: dict[str, object] = {
        "occurrence_id": "ignored",
        "occurrence_format": symptoms.OCCURRENCE_FORMAT,
        "signal": "PROCESS_CRASH",
        "operation": "read",
        "target_reader": "reader",
        "normalized_location": None,
        "evidence": [evidence],
    }

    def changed(**updates: object) -> Mapping[str, object]:
        return {**valid, **updates}

    semantic = _semantic_summary("VALUE_DIFFERENCE", "$.rows[*].columns[0]", [["a"], ["b"]])
    cast(list[dict[str, object]], semantic["evidence"])[0]["comparison_kind"] = "SCHEMA_DIFFERENCE"
    invalid: tuple[Mapping[str, object], ...] = (
        {},
        changed(occurrence_format="unknown"),
        changed(signal="UNKNOWN"),
        changed(operation="write"),
        changed(target_reader=None),
        changed(target_reader=0),
        changed(evidence=[]),
        changed(evidence=[{**evidence, "extra": True}]),
        changed(evidence=[{**evidence, "detail_sha256": "invalid"}]),
        changed(evidence=[{**evidence, "outcome_kind": "PROVIDER_ERROR"}]),
        semantic,
    )
    for value in invalid:
        with pytest.raises(ValueError):
            symptoms.summary_occurrence_id("f" * 64, value, roster)

    timeout_evidence = {
        **evidence,
        "outcome_kind": "TIMEOUT",
        "diagnostic_kind": "TIMEOUT",
        "timeout_seconds": True,
    }
    invalid += (changed(signal="TIMEOUT", evidence=[timeout_evidence]),)
    with pytest.raises(ValueError):
        symptoms.summary_occurrence_id("f" * 64, invalid[-1], roster)

    timeout_extract = partial(symptoms.extract_evidence, "4" * 64, ("d",), 30)
    timeout_original = timeout_extract((_outcome("d", "TIMEOUT"),), (), (), detail_sha256_v1)[0]
    timeout_outcome = {**_outcome("d", "TIMEOUT"), "detail": "changed"}
    timeout_current = timeout_extract((timeout_outcome,), (), (), detail_sha256_v1)[0]
    compare = partial(replay_evidence.compare, normalize=normalize_detail_v1)
    timeout_result = compare((timeout_original,), (timeout_current,)).occurrence_results[0]
    _validate(timeout_result, timeout_original)
    timeout_observation = cast(dict[str, object], timeout_result["current_observation"])
    exact_observation = deepcopy(timeout_observation)
    exact_observation["occurrence_id"] = timeout_original.occurrence_id
    exact_observation["evidence"] = [dict(timeout_original.evidence[0])]
    exact_change = cast(list[dict[str, object]], exact_observation["detail_changes"])[0]
    exact_change["current_detail"] = exact_change["original_detail"]
    exact_change["current_detail_sha256"] = exact_change["original_detail_sha256"]
    with pytest.raises(ValueError):
        _validate({**timeout_result, "current_observation": exact_observation}, timeout_original)
    timeout_evidence = cast(list[dict[str, object]], timeout_observation["evidence"])
    timeout_evidence[0] = {**timeout_evidence[0], "timeout_seconds": 31}
    summary = {**timeout_current.summary(), "evidence": timeout_evidence}
    timeout_observation["occurrence_id"] = symptoms.summary_occurrence_id(
        timeout_original.finding_id, summary, timeout_original.reader_roster
    )
    with pytest.raises(ValueError):
        _validate({**timeout_result, "current_observation": timeout_observation}, timeout_original)


def _semantic_summary(signal: str, location: str, groups: object) -> dict[str, object]:
    return {
        "occurrence_id": "",
        "occurrence_format": symptoms.OCCURRENCE_FORMAT,
        "signal": signal,
        "operation": "read",
        "target_reader": None,
        "normalized_location": location,
        "evidence": [
            {
                "comparison_kind": signal,
                "groups": groups,
                "detail_sha256": "a" * 64,
            }
        ],
    }


def test_semantic_summary_requires_the_exact_source_grammar() -> None:
    roster = ("a", "b", "c")
    for signal, location in (
        ("ROW_COUNT_DIFFERENCE", "$.rows"),
        ("VALUE_DIFFERENCE", "$.rows[*].columns[0]"),
        ("SCHEMA_DIFFERENCE", "$.schema"),
        ("SCHEMA_DIFFERENCE", "$.schema.fields[12]"),
    ):
        value = _semantic_summary(signal, location, [["a"], ["b", "c"]])
        assert symptoms.summary_occurrence_id("f" * 64, value, roster)

    invalid_locations = (
        ("ROW_COUNT_DIFFERENCE", "$.rows[*]"),
        ("VALUE_DIFFERENCE", "$.rows[0].columns[1]"),
        ("VALUE_DIFFERENCE", "$.rows[*].columns[01]"),
        ("SCHEMA_DIFFERENCE", "$.schema.fields[*]"),
        ("SCHEMA_DIFFERENCE", "$.schema.fields[0].child"),
    )
    for signal, location in invalid_locations:
        value = _semantic_summary(signal, location, [["a"], ["b"]])
        with pytest.raises(ValueError):
            symptoms.summary_occurrence_id("f" * 64, value, roster)

    invalid_groups = (
        [["a"]],
        [["a"], ["b"], ["c"]],
        [[], ["b"]],
        [["b", "a"], ["c"]],
        [["a", "a"], ["b"]],
        [["a"], ["a"]],
        [["a", "b"], ["b", "c"]],
        [["b"], ["a"]],
        [["a"], ["outside"]],
    )
    for groups in invalid_groups:
        value = _semantic_summary("VALUE_DIFFERENCE", "$.rows[*].columns[0]", groups)
        with pytest.raises(ValueError):
            symptoms.summary_occurrence_id("f" * 64, value, roster)

    duplicate = _semantic_summary("VALUE_DIFFERENCE", "$.rows[*].columns[0]", [["a"], ["b"]])
    evidence = cast(list[dict[str, object]], duplicate["evidence"])[0]
    duplicate["evidence"] = [evidence, {**evidence, "detail_sha256": "b" * 64}]
    with pytest.raises(ValueError):
        symptoms.summary_occurrence_id("f" * 64, duplicate, roster)
