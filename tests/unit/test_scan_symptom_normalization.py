import hashlib
from collections.abc import Mapping
from dataclasses import replace
from functools import partial
from typing import cast

import pytest

from parquity.evidence import ReplayClassification
from parquity.evidence.normalization import DETAIL_RULES_V1, detail_sha256_v1, normalize_detail_v1
from parquity.scans import replay, symptoms
from parquity.scans.differences import DifferenceKind, ScanDifference
from parquity.scans.records import ReaderOutcomeKind, ReaderOutcomeRecord


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


def test_scan_normalization_changes_rows_only() -> None:
    cases = (
        (DifferenceKind.VALUE_DIFFERENCE, "$.rows[19].columns[7]", "$.rows[*].columns[7]"),
        (DifferenceKind.ROW_COUNT_DIFFERENCE, "$.rows", "$.rows"),
        (DifferenceKind.SCHEMA_DIFFERENCE, "$.schema.fields[4]", "$.schema.fields[4]"),
    )
    for kind, persisted, normalized in cases:
        assert ScanDifference.from_persisted(kind, persisted).normalized().path == normalized


def _outcome(
    engine: str, kind: ReaderOutcomeKind = ReaderOutcomeKind.SUCCESS
) -> ReaderOutcomeRecord:
    if kind is ReaderOutcomeKind.SUCCESS:
        group = f"group-{ord(engine) - ord('a') + 1}"
        return ReaderOutcomeRecord(
            engine,
            "1",
            kind,
            "SUCCESS",
            "",
            "",
            False,
            1,
            1,
            engine * 64,
            engine * 64,
            16,
            group,
        )
    detail = "failure"
    stderr = detail if kind in (ReaderOutcomeKind.PROCESS_ERROR, ReaderOutcomeKind.TIMEOUT) else ""
    return ReaderOutcomeRecord(
        engine,
        "1",
        kind,
        kind.value,
        detail,
        stderr,
        False,
    )


def _edge(left: int, right: int, path: str, detail: str) -> Mapping[str, object]:
    return {
        "left_group": f"group-{left}",
        "right_group": f"group-{right}",
        "kind": "ROW_COUNT_DIFFERENCE" if path == "$.rows" else "VALUE_DIFFERENCE",
        "path": path,
        "detail": detail,
    }


def test_scan_symptoms_fan_out_conserve_edges_and_type_row_counts() -> None:
    outcomes = (
        *(_outcome(name) for name in ("a", "b", "c")),
        _outcome("d", ReaderOutcomeKind.PROCESS_ERROR),
    )
    groups = tuple(
        {"id": f"group-{index}", "engines": [name]} for index, name in enumerate(("a", "b", "c"), 1)
    )
    edges = (
        _edge(1, 2, "$.rows[0].columns[2]", "a-b"),
        _edge(1, 3, "$.rows[8].columns[2]", "a-c"),
        _edge(2, 3, "$.rows[9].columns[2]", "b-c"),
    )
    extract = partial(symptoms.extract_evidence, "1" * 64, ("a", "b", "c", "d"), 30)
    compare = partial(replay.compare, normalize=normalize_detail_v1)
    combined = extract(outcomes, groups, edges, detail_sha256_v1)
    assert {item.signal for item in combined} == {"PROCESS_CRASH", "VALUE_DIFFERENCE"}
    semantic = next(item for item in combined if item.normalized_location is not None)
    assert semantic.normalized_location == "$.rows[*].columns[2]"
    assert len(semantic.evidence) == 3
    separated_edges = (*edges[:2], _edge(2, 3, "$.rows[9].columns[3]", "b-c"))
    separated = extract(outcomes, groups, separated_edges, detail_sha256_v1)
    assert (sum(len(item.evidence) for item in combined), len(separated)) == (4, 3)
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

    changed_outcomes = (*outcomes[:3], _outcome("d", ReaderOutcomeKind.PROVIDER_ERROR))
    current = extract(changed_outcomes, groups, edges, detail_sha256_v1)
    compared = compare(combined, current)
    assert compared.classification == "RELATED_FAILURE" and len(compared.new_observations) == 1
    exact, absent = compare(combined, combined), compare(combined, ())
    assert (exact.classification, absent.classification) == ("REPRODUCED", "NOT_REPRODUCED")
    minimal = (*exact.occurrence_results, *absent.occurrence_results)
    assert all(set(item) == {"occurrence_id", "classification"} for item in minimal)


def test_scan_replay_classification_owners_cover_uniform_mixed_and_new_results() -> None:
    reproduced = ReplayClassification.REPRODUCED
    absent = ReplayClassification.NOT_REPRODUCED
    related = ReplayClassification.RELATED_FAILURE
    assert (
        replay.finding_classification((reproduced, reproduced), has_new_observations=False)
        is reproduced
    )
    assert replay.finding_classification((absent, absent), has_new_observations=False) is absent
    assert (
        replay.finding_classification((reproduced, absent), has_new_observations=False) is related
    )
    assert replay.finding_classification((reproduced,), has_new_observations=True) is related
    assert replay.run_status((reproduced, reproduced)) is reproduced
    assert replay.run_status((reproduced, absent)) is related

    with pytest.raises(ValueError):
        replay.occurrence_classification({"classification": "UNKNOWN"})


def test_timeout_detail_change_is_related() -> None:
    timeout_extract = partial(symptoms.extract_evidence, "4" * 64, ("d",), 30)
    timeout_original = timeout_extract(
        (_outcome("d", ReaderOutcomeKind.TIMEOUT),), (), (), detail_sha256_v1
    )[0]
    timeout_outcome = replace(
        _outcome("d", ReaderOutcomeKind.TIMEOUT), detail="changed", stderr="changed"
    )
    timeout_current = timeout_extract((timeout_outcome,), (), (), detail_sha256_v1)[0]
    compare = partial(replay.compare, normalize=normalize_detail_v1)
    timeout_result = compare((timeout_original,), (timeout_current,)).occurrence_results[0]
    assert timeout_result["classification"] == "RELATED_FAILURE"
    timeout_observation = cast(Mapping[str, object], timeout_result["current_observation"])
    assert timeout_observation["reader_roster"] == ["d"]
    timeout_changes = cast(list[Mapping[str, object]], timeout_observation["detail_changes"])
    assert len(timeout_changes) == 1
    assert timeout_changes[0]["original_detail"] == "failure"
    assert timeout_changes[0]["current_detail"] == "changed"
