from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import NamedTuple, cast

from . import records, symptoms

_BASE_RESULT = frozenset(("occurrence_id", "classification"))
_INVALID = "replay evidence is contradictory"
_OBSERVATION = frozenset(("occurrence_id", "occurrence_format", "signal", "operation")) | {
    "target_reader",
    "normalized_location",
    "reader_roster",
    "evidence",
    "detail_changes",
}
_SUMMARY = _OBSERVATION - {"reader_roster", "detail_changes"}
_DETAIL_CHANGE = frozenset(("evidence_shape", "original_detail", "original_detail_sha256")) | {
    "current_detail",
    "current_detail_sha256",
}


class ReplayComparison(NamedTuple):
    occurrence_results: tuple[Mapping[str, object], ...]
    new_observations: tuple[Mapping[str, object], ...]
    classification: str


def compare(
    original: tuple[symptoms.ScanSymptom, ...],
    current: tuple[symptoms.ScanSymptom, ...],
    normalize: Callable[[str], str],
) -> ReplayComparison:
    remaining = {item.occurrence_id: item for item in current}
    related = {item.related_id: item for item in current}
    if len(related) != len(current):
        raise RuntimeError("scan symptoms have duplicate related shapes")
    results: list[Mapping[str, object]] = []
    for item in sorted(original, key=lambda value: value.occurrence_id):
        matched = remaining.pop(item.occurrence_id, None)
        classification = "REPRODUCED"
        if matched is None:
            matched = related.get(item.related_id)
            classification = "RELATED_FAILURE" if matched is not None else "NOT_REPRODUCED"
            if matched is not None:
                remaining.pop(matched.occurrence_id)
        if matched is not None:
            related.pop(matched.related_id, None)
        result: dict[str, object] = {
            "occurrence_id": item.occurrence_id,
            "classification": classification,
        }
        if classification == "RELATED_FAILURE":
            result["current_observation"] = _observation(
                item, cast(symptoms.ScanSymptom, matched), normalize
            )
        results.append(result)
    new = tuple(
        item.summary() for item in sorted(remaining.values(), key=lambda value: value.occurrence_id)
    )
    states = {cast(str, item["classification"]) for item in results}
    classification = next(iter(states)) if len(states) == 1 and not new else "RELATED_FAILURE"
    return ReplayComparison(tuple(results), new, classification)


def validate_results(
    values: tuple[Mapping[str, object], ...],
    expected_ids: tuple[str, ...],
    originals: Mapping[str, symptoms.ScanSymptom] | None,
    reader_roster: tuple[str, ...],
    normalize: Callable[[str], str],
) -> None:
    actual = tuple(records.text(item, "occurrence_id") for item in values)
    invalid_coverage = actual != expected_ids or len(actual) != len(set(actual))
    records.reject(invalid_coverage, _INVALID)
    for occurrence_id, value in zip(actual, values, strict=True):
        original = None if originals is None else originals.get(occurrence_id)
        classification = records.text(value, "classification")
        unavailable = classification == "RELATED_FAILURE" and original is None
        records.reject(unavailable, _INVALID)
        if original is None:
            records.reject(frozenset(value) != _BASE_RESULT, _INVALID)
        else:
            _validate_result(value, original, reader_roster, normalize)


def validate_new_observations(
    values: tuple[Mapping[str, object], ...],
    finding_id: str,
    original_ids: set[str],
    related_ids: set[str],
    reader_roster: tuple[str, ...],
) -> bool:
    actual = tuple(records.text(item, "occurrence_id") for item in values)
    invalid_order = actual != tuple(sorted(actual)) or len(actual) != len(set(actual))
    records.reject(invalid_order, _INVALID)
    for occurrence_id, value in zip(actual, values, strict=True):
        summary_id, related_id = symptoms.summary_identities(finding_id, value, reader_roster)
        records.reject(
            occurrence_id in original_ids or summary_id != occurrence_id,
            _INVALID,
        )
        records.reject(related_id in related_ids, _INVALID)
        related_ids.add(related_id)
    return bool(values)


def _validate_result(
    value: Mapping[str, object],
    original: symptoms.ScanSymptom,
    reader_roster: tuple[str, ...],
    normalize: Callable[[str], str],
) -> None:
    related = records.text(value, "classification") == "RELATED_FAILURE"
    current_key = frozenset(("current_observation",)) if related else frozenset[str]()
    expected = _BASE_RESULT | current_key
    records.reject(frozenset(value) != expected, _INVALID)
    if not related:
        return
    raw = value["current_observation"]
    records.reject(not isinstance(raw, Mapping), _INVALID)
    observation = cast(Mapping[str, object], raw)
    records.reject(frozenset(observation) != _OBSERVATION, _INVALID)
    raw_roster = observation["reader_roster"]
    records.reject(not isinstance(raw_roster, list), _INVALID)
    roster = records.group_members({"id": "roster", "engines": raw_roster})[1]
    records.reject(roster != tuple(sorted(reader_roster)), _INVALID)
    summary = {key: observation[key] for key in _SUMMARY}
    current_id, related_id = symptoms.summary_identities(original.finding_id, summary, roster)
    invalid_id = current_id != observation["occurrence_id"] or current_id == original.occurrence_id
    records.reject(invalid_id, _INVALID)
    records.reject(related_id != original.related_id, _INVALID)
    evidence = records.mappings(observation["evidence"], "current observation evidence")
    changes = records.mappings(observation["detail_changes"], "detail changes")
    _validate_changes(original, evidence, changes, normalize)


def _observation(
    original: symptoms.ScanSymptom,
    current: symptoms.ScanSymptom,
    normalize: Callable[[str], str],
) -> dict[str, object]:
    records.reject(original.related_id != current.related_id, "related symptom shape changed")
    value = current.summary()
    value["reader_roster"] = list(current.reader_roster)
    value["detail_changes"] = list(_changes(original, current, normalize))
    return value


def _changes(
    original: symptoms.ScanSymptom,
    current: symptoms.ScanSymptom,
    normalize: Callable[[str], str],
) -> tuple[Mapping[str, object], ...]:
    old = _aligned(original.evidence, original.details, original.target_reader)
    new = _aligned(current.evidence, current.details, current.target_reader)
    records.reject(tuple(old) != tuple(new), _INVALID)
    result: list[Mapping[str, object]] = []
    for key in old:
        shape, old_item, old_detail = old[key]
        _, new_item, new_detail = new[key]
        result.append(
            {
                "evidence_shape": shape,
                "original_detail": normalize(old_detail),
                "original_detail_sha256": old_item["detail_sha256"],
                "current_detail": normalize(new_detail),
                "current_detail_sha256": new_item["detail_sha256"],
            }
        )
    return tuple(result)


def _aligned(
    evidence: tuple[Mapping[str, object], ...],
    details: tuple[str, ...],
    target: str | None,
) -> dict[bytes, tuple[object, Mapping[str, object], str]]:
    records.reject(len(evidence) != len(details), _INVALID)
    result: dict[bytes, tuple[object, Mapping[str, object], str]] = {}
    for item, detail in zip(evidence, details, strict=True):
        shape: object
        if "outcome_kind" in item:
            shape = {
                "target_reader": target,
                "outcome_kind": item["outcome_kind"],
                "diagnostic_kind": item["diagnostic_kind"],
            }
        else:
            shape = {"comparison_kind": item["comparison_kind"], "groups": item["groups"]}
        key = records.canonical_bytes(shape)
        records.reject(key in result, _INVALID)
        result[key] = (shape, item, detail)
    return dict(sorted(result.items()))


def _validate_changes(
    original: symptoms.ScanSymptom,
    current: tuple[Mapping[str, object], ...],
    changes: tuple[Mapping[str, object], ...],
    normalize: Callable[[str], str],
) -> None:
    old = _aligned(original.evidence, original.details, original.target_reader)
    new = _aligned(current, tuple("" for _ in current), original.target_reader)
    records.reject(tuple(old) != tuple(new) or len(changes) != len(old), _INVALID)
    for (key, (_, old_item, old_detail)), change in zip(old.items(), changes, strict=True):
        records.reject(
            frozenset(change) != _DETAIL_CHANGE
            or records.canonical_bytes(change["evidence_shape"]) != key,
            _INVALID,
        )
        for prefix in ("original", "current"):
            detail = records.text(change, f"{prefix}_detail")
            digest = records.text(change, f"{prefix}_detail_sha256")
            records.reject(
                normalize(detail) != detail
                or hashlib.sha256(detail.encode()).hexdigest() != digest,
                _INVALID,
            )
        mismatch = change["original_detail"] != normalize(old_detail)
        mismatch |= change["original_detail_sha256"] != old_item["detail_sha256"]
        new_item = new[key][1]
        mismatch |= change["current_detail_sha256"] != new_item["detail_sha256"]
        old_typed = {name: item for name, item in old_item.items() if name != "detail_sha256"}
        new_typed = {name: item for name, item in new_item.items() if name != "detail_sha256"}
        mismatch |= old_typed != new_typed
        records.reject(mismatch, _INVALID)
