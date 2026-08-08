from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Protocol, cast

import pytest

from parquity.scans import symptoms
from parquity.triage import command as triage_command
from parquity.triage import model as triage_model
from parquity.triage.command import TriageError, triage_run
from parquity.triage.model import (
    FAMILY_FORMAT,
    Focus,
    Occurrence,
    ReproductionState,
    Signal,
    focused_families,
    group_occurrences,
    markdown_literal,
    render_family_report,
)


class _ScanResultBinder(Protocol):
    def __call__(
        self,
        result: Mapping[str, object],
        occurrences: tuple[Occurrence, ...],
        engine_order: tuple[str, ...],
    ) -> tuple[dict[str, ReproductionState], ReproductionState]: ...


_bind = cast(_ScanResultBinder, vars(triage_command)["_scan_result_states"])


def _occurrence(
    finding_id: str,
    *,
    reduced: bool,
    input_bytes: int,
    regime: str = "generated",
    reference_value: str | None = None,
    detail: str = "representative detail",
) -> Occurrence:
    reference = "case_id" if regime == "generated" else "source_path"
    if reference_value is None:
        reference_value = "c" * 64 if regime == "generated" else "source.parquet"
    return Occurrence(
        f"occurrence-{finding_id}",
        finding_id,
        regime,
        Signal.PROVIDER_ERROR,
        {
            "projection_version": FAMILY_FORMAT,
            "evidence_regime": regime,
            "signal": "PROVIDER_ERROR",
            "operation": "read",
            "engine_roles": [{"engine": "reader", "role": "reader"}],
            **({"reader_roster": ["reader"]} if regime == "scan" else {}),
        },
        reference,
        reference_value,
        "input.parquet",
        "d" * 64,
        input_bytes,
        reduced if regime == "generated" else None,
        (("parquity", "0.1.0"),),
        (("reader", "reader", "2"),),
        "$.rows[*].columns[1]" if regime == "scan" else "$rows[*]",
        detail,
        "e" * 64,
    )


def test_report_projection_contains_the_complete_neutral_family_surface() -> None:
    original = _occurrence("b" * 64, reduced=True, input_bytes=20)
    drifted = replace(
        _occurrence("a" * 64, reduced=True, input_bytes=10),
        package_versions=(("parquity", "0.1.1"),),
        provider_versions=(("reader", "reader", "3"),),
    )
    family = group_occurrences((original, drifted))[0]
    data = family.to_data()
    report = render_family_report((family,), "Conformance families")

    assert family.representative.finding_id == "a" * 64
    assert data["projection_version"] == FAMILY_FORMAT
    assert data["evidence_regime"] == "generated"
    assert data["family_kind"] == "conformance"
    assert data["signal"] == "PROVIDER_ERROR"
    assert data["occurrence_count"] == 2
    assert data["reproduction_state_counts"] == {
        "REPRODUCED": 0,
        "RELATED_FAILURE": 0,
        "NOT_REPRODUCED": 0,
        "NOT_CHECKED": 2,
    }
    assert data["representative_reproduction_state"] == "NOT_CHECKED"
    assert "reproduction_state" not in data
    assert data["novelty_state"] == "UNAVAILABLE"
    assert data["member_finding_ids"] == ["a" * 64, "b" * 64]
    assert data["representative_command"] == f"parquity replay RUN_DIR/findings/{'a' * 64}"
    observed = cast(dict[str, object], data["observed_versions"])
    assert cast(list[dict[str, object]], observed["packages"])[0]["versions"] == [
        "0.1.0",
        "0.1.1",
    ]
    assert cast(list[dict[str, object]], observed["providers"])[0]["versions"] == ["2", "3"]
    for expected in (
        "## Conformance families",
        "Retained finding bundles: `2`",
        "Symptom occurrences: `2`",
        "Symptom families: `1`",
        f"Symptom family `{family.family_id}`",
        "Projection: `parquity.triage-family.v1`",
        "Evidence regime: `generated`",
        "Representative reproduction state: `NOT_CHECKED`",
        "Novelty state: `UNAVAILABLE`",
        "reader reader 2,3",
    ):
        assert expected in report
    lowered = report.lower()
    assert all(word not in lowered for word in (" bug", "majority", "blame", "issue-ready"))


def test_report_uses_observation_terminology_for_scan_families() -> None:
    family = group_occurrences(
        (_occurrence("f" * 64, reduced=False, input_bytes=4, regime="scan"),)
    )[0]
    data = family.to_data()
    report = render_family_report((family,), "Observation families")

    assert data["family_kind"] == "observation"
    assert data["reader_roster"] == ["reader"]
    assert cast(dict[str, object], data["representative"])["source_path"] == "source.parquet"
    assert "## Observation families" in report
    assert 'source_path "source.parquet"' in report
    assert "do not assign fault" in report


def test_report_counts_all_states_and_bounds_hostile_representative_detail() -> None:
    hostile = "x" * 500 + "\n## injected\n```"
    items = tuple(
        replace(
            _occurrence(
                str(index), reduced=False, input_bytes=index + 1, regime="scan", detail=hostile
            ),
            reproduction_state=state,
        )
        for index, state in enumerate(ReproductionState)
    )
    family = group_occurrences(items)[0]
    data = family.to_data()
    detail = cast(dict[str, object], cast(dict[str, object], data["representative"])["detail"])
    report = render_family_report((family,), "Observation families")

    assert data["reproduction_state_counts"] == {
        "REPRODUCED": 1,
        "RELATED_FAILURE": 1,
        "NOT_REPRODUCED": 1,
        "NOT_CHECKED": 1,
    }
    assert len(cast(str, detail["text"])) == 500
    assert detail == {"text": "x" * 500, "sha256": "e" * 64, "truncated": True}
    assert "\n## injected" not in report and "\n```" not in report


@pytest.mark.parametrize(
    "source_path",
    (
        "line\n## injected",
        "`fence`",
        "[label](target)",
        "unicodé/雪.parquet",
        "nested/`name`_[x]\n### hostile 雪.parquet",
    ),
)
def test_report_renders_hostile_references_without_changing_json_or_markdown_structure(
    source_path: str,
) -> None:
    occurrence = _occurrence(
        "f" * 64,
        reduced=False,
        input_bytes=4,
        regime="scan",
        reference_value=source_path,
    )
    family = group_occurrences((occurrence,))[0]
    data = family.to_data()
    report = render_family_report((family,), "Observation families")

    representative = cast(dict[str, object], data["representative"])
    serialized = cast(list[dict[str, object]], data["occurrences"])[0]
    assert representative["source_path"] == source_path
    assert serialized["source_path"] == source_path
    assert markdown_literal(source_path) in report
    assert sum(line.startswith("## ") for line in report.splitlines()) == 1
    assert sum(line.startswith("### ") for line in report.splitlines()) == 1
    assert "\n## injected" not in report and "\n### hostile" not in report


def test_reduction_precedes_size_and_identifier_without_replay_evidence() -> None:
    unreduced = _occurrence("a", reduced=False, input_bytes=1)
    large_reduced = _occurrence("c", reduced=True, input_bytes=30)
    small_reduced = _occurrence("b", reduced=True, input_bytes=20)

    family = group_occurrences((unreduced, large_reduced, small_reduced))[0]

    assert family.representative.finding_id == "b"


def test_replay_representative_and_focus_are_deterministic() -> None:
    reproduced = _occurrence("b", reduced=False, input_bytes=10, regime="scan")
    absent = replace(
        reproduced,
        occurrence_id="a",
        finding_id="a",
        reference_value="a.parquet",
        input_bytes=5,
    )
    states = {
        "a": ReproductionState.NOT_REPRODUCED,
        reproduced.occurrence_id: ReproductionState.REPRODUCED,
    }
    family = group_occurrences((reproduced, absent), states)[0]

    assert family.representative.occurrence_id == reproduced.occurrence_id
    assert focused_families((family,), Focus.EXECUTION) == (family,)
    assert focused_families((family,), Focus.DATA) == ()
    assert focused_families((family,), Focus.SCHEMA) == ()
    assert focused_families((family,), Focus.ALL) == (family,)


def test_unequal_keys_with_one_family_digest_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FixedDigest:
        def hexdigest(self) -> str:
            return "0" * 64

    def fixed_digest(payload: bytes) -> FixedDigest:
        assert payload
        return FixedDigest()

    monkeypatch.setattr(triage_model.hashlib, "sha256", fixed_digest)
    first = _occurrence("a", reduced=False, input_bytes=1)
    second = replace(
        _occurrence("b", reduced=False, input_bytes=1),
        projection={**first.projection, "operation": "different"},
    )

    with pytest.raises(RuntimeError, match="unequal triage projection"):
        group_occurrences((first, second))


def test_grouping_rejects_duplicate_occurrences_and_incomplete_replay() -> None:
    occurrence = _occurrence("same", reduced=False, input_bytes=1)
    with pytest.raises(RuntimeError, match="duplicate"):
        group_occurrences((occurrence, occurrence))
    with pytest.raises(ValueError, match="complete aggregate"):
        group_occurrences((occurrence,), {})


def test_scan_replay_binding_rejects_incomplete_or_contradictory_occurrences() -> None:
    first = _occurrence("bundle", reduced=False, input_bytes=1, regime="scan")
    second = replace(first, occurrence_id="second")
    occurrences = tuple(sorted((first, second), key=lambda item: item.occurrence_id))
    occurrence_results = [
        {"occurrence_id": item.occurrence_id, "classification": "REPRODUCED"}
        for item in occurrences
    ]
    result: dict[str, object] = {
        "finding_id": "bundle",
        "classification": "REPRODUCED",
        "package_version": {"original": "0.1.0", "current": "0.1.0", "drift": False},
        "version_evidence": [{"engine": "reader", "original": "2", "current": "2", "drift": False}],
        "occurrence_results": occurrence_results,
        "new_observations": [],
    }
    states, finding_state = _bind(result, occurrences, ("reader",))
    assert set(states) == {item.occurrence_id for item in occurrences}
    assert finding_state is ReproductionState.REPRODUCED

    def changed(**updates: object) -> dict[str, object]:
        return {**result, **updates}

    invalid = (
        changed(occurrence_results=occurrence_results[:1]),
        changed(occurrence_results=[*occurrence_results, occurrence_results[0]]),
        changed(occurrence_results=list(reversed(occurrence_results))),
        changed(
            occurrence_results=[
                {**occurrence_results[0], "occurrence_id": "foreign"},
                occurrence_results[1],
            ]
        ),
        changed(classification="NOT_REPRODUCED"),
    )
    for value in invalid:
        with pytest.raises(ValueError, match="contradictory"):
            _bind(value, occurrences, ("reader",))


def test_scan_replay_binding_accepts_canonical_new_observation() -> None:
    occurrence = _occurrence("bundle", reduced=False, input_bytes=1, regime="scan")
    roster = ("reader",)

    def current(digest: str) -> tuple[dict[str, object], str]:
        outcome = {
            "engine": "reader",
            "kind": "PROCESS_CRASH",
            "diagnostic_kind": "PROCESS_CRASH",
            "detail": "failure",
        }
        item = symptoms.extract_evidence(
            "bundle", roster, 30, (outcome,), (), (), lambda _: digest
        )[0]
        return item.summary(), item.related_id

    observation, related_id = current("a" * 64)
    result = {
        "finding_id": "bundle",
        "classification": "RELATED_FAILURE",
        "package_version": {"original": "0.1.0", "current": "0.1.0", "drift": False},
        "version_evidence": [{"engine": "reader", "original": "2", "current": "2", "drift": False}],
        "occurrence_results": [
            {"occurrence_id": occurrence.occurrence_id, "classification": "NOT_REPRODUCED"}
        ],
        "new_observations": [observation],
    }
    assert _bind(result, (occurrence,), roster)[1] is ReproductionState.RELATED_FAILURE
    with pytest.raises(ValueError, match="contradictory"):
        _bind(result, (replace(occurrence, related_id=related_id),), roster)
    bad = {**observation, "occurrence_id": "bad"}
    with pytest.raises(ValueError, match="contradictory"):
        _bind({**result, "new_observations": [bad]}, (occurrence,), roster)
    peer, _ = current("b" * 64)
    new = sorted((observation, peer), key=lambda item: str(item["occurrence_id"]))
    with pytest.raises(ValueError, match="contradictory"):
        _bind({**result, "new_observations": new}, (occurrence,), roster)


def test_triage_maps_a_malformed_generated_aggregate(tmp_path: Path) -> None:
    (tmp_path / "run.json").write_text("{}")

    with pytest.raises(TriageError, match="run"):
        triage_run(tmp_path, "all", None)
