from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from typing import NamedTuple, cast

from . import records

OCCURRENCE_FORMAT = "parquity.triage-occurrence.v1"
_INDEX = r"(?:0|[1-9][0-9]*)"
_SCAN_ROW = re.compile(rf"^\$\.rows\[{_INDEX}\](?=\.columns\[)")
_EXECUTION_SIGNALS = frozenset(("PROCESS_CRASH", "TIMEOUT", "PROVIDER_ERROR"))
_summary_fields = frozenset(("occurrence_id", "occurrence_format"))
_summary_fields |= {"signal", "operation", "target_reader"}
_summary_fields |= {"normalized_location", "evidence"}
_SEMANTIC_LOCATIONS = {
    "ROW_COUNT_DIFFERENCE": re.compile(r"\$\.rows"),
    "VALUE_DIFFERENCE": re.compile(rf"\$\.rows\[\*\]\.columns\[{_INDEX}\]"),
    "SCHEMA_DIFFERENCE": re.compile(rf"\$\.schema(?:\.fields\[{_INDEX}\])?"),
}


class ScanSymptom(NamedTuple):
    occurrence_id: str
    finding_id: str
    signal: str
    target_reader: str | None
    normalized_location: str | None
    evidence: tuple[Mapping[str, object], ...]
    evidence_indexes: tuple[int, ...]
    details: tuple[str, ...]
    detail: str
    detail_sha256: str
    reader_roster: tuple[str, ...]
    related_id: str

    def summary(self) -> dict[str, object]:
        value = _identity(
            self.finding_id,
            self.signal,
            self.target_reader,
            self.normalized_location,
            self.evidence,
        )
        del value["evidence_regime"], value["finding_id"]
        value["occurrence_id"] = self.occurrence_id
        return value


def normalize_location(path: str) -> str:
    return _SCAN_ROW.sub("$.rows[*]", path)


def extract(
    record: records.ScanFindingRecord,
    detail_sha256: Callable[[str], str],
) -> tuple[ScanSymptom, ...]:
    data = record.data
    return extract_evidence(
        record.finding_id,
        tuple(item.name for item in record.engines),
        record.timeout_seconds,
        records.mappings(data["outcomes"], "outcomes"),
        records.mappings(data["observation_groups"], "observation groups"),
        records.mappings(data["comparisons"], "comparisons"),
        detail_sha256,
    )


def extract_evidence(
    finding_id: str,
    reader_roster: tuple[str, ...],
    timeout_seconds: int,
    outcomes: Sequence[Mapping[str, object]],
    groups: Sequence[Mapping[str, object]],
    comparisons: Sequence[Mapping[str, object]],
    detail_sha256: Callable[[str], str],
) -> tuple[ScanSymptom, ...]:
    roster = tuple(sorted(reader_roster))
    memberships: dict[str, tuple[str, ...]] = {}
    for group in groups:
        group_id, members = records.group_members(group)
        memberships[group_id] = tuple(sorted(members))
    result = _execution(finding_id, timeout_seconds, outcomes, roster, detail_sha256)
    result.extend(_semantic(finding_id, comparisons, memberships, roster, detail_sha256))
    expected = sum(records.text(item, "kind") != "SUCCESS" for item in outcomes) + len(comparisons)
    if sum(len(item.evidence_indexes) for item in result) != expected or len(
        {item.occurrence_id for item in result}
    ) != len(result):
        raise RuntimeError("scan symptom extraction invariant failed")
    return tuple(sorted(result, key=lambda item: item.occurrence_id))


def summary_occurrence_id(
    finding_id: str, value: Mapping[str, object], reader_roster: tuple[str, ...]
) -> str:
    return summary_identities(finding_id, value, reader_roster)[0]


def summary_identities(
    finding_id: str, value: Mapping[str, object], reader_roster: tuple[str, ...]
) -> tuple[str, str]:
    records.reject(
        frozenset(value) != _summary_fields or value["occurrence_format"] != OCCURRENCE_FORMAT,
        "new observation shape is invalid",
    )
    signal = records.text(value, "signal")
    records.reject(
        signal not in _EXECUTION_SIGNALS and signal not in _SEMANTIC_LOCATIONS,
        "new observation signal is invalid",
    )
    records.reject(value["operation"] != "read", "new observation operation is invalid")
    target = None if value["target_reader"] is None else records.text(value, "target_reader")
    location = (
        None if value["normalized_location"] is None else records.text(value, "normalized_location")
    )
    records.reject(target == "" or location == "", "new observation text is invalid")
    execution = signal in _EXECUTION_SIGNALS
    invalid_target = execution != (target is not None and location is None)
    invalid_location = not execution and (target is not None or location is None)
    records.reject(invalid_target or invalid_location, "new observation location is invalid")
    roster = tuple(sorted(reader_roster))
    records.reject(target is not None and target not in roster, "new observation reader is invalid")
    evidence = records.mappings(value["evidence"], "new observation evidence")
    _validate_summary_evidence(signal, location, evidence, roster)
    identity = _identity(finding_id, signal, target, location, evidence)
    return occurrence_id(identity), _related_id(signal, target, location, roster, evidence)


def occurrence_id(identity: Mapping[str, object]) -> str:
    return hashlib.sha256(records.canonical_bytes(identity)).hexdigest()


def _execution(
    finding_id: str,
    timeout_seconds: int,
    outcomes: Sequence[Mapping[str, object]],
    roster: tuple[str, ...],
    detail_sha256: Callable[[str], str],
) -> list[ScanSymptom]:
    result: list[ScanSymptom] = []
    for index, outcome in enumerate(outcomes):
        kind = records.text(outcome, "kind")
        if kind not in _EXECUTION_SIGNALS:
            continue
        detail = records.text(outcome, "detail")
        item: dict[str, object] = {
            "outcome_kind": kind,
            "diagnostic_kind": records.text(outcome, "diagnostic_kind"),
            "detail_sha256": detail_sha256(detail),
        }
        if kind == "TIMEOUT":
            item["timeout_seconds"] = timeout_seconds
        evidence: tuple[Mapping[str, object], ...] = (item,)
        target = records.text(outcome, "engine")
        result.append(
            ScanSymptom(
                occurrence_id(_identity(finding_id, kind, target, None, evidence)),
                finding_id,
                kind,
                target,
                None,
                evidence,
                (index,),
                (detail,),
                detail,
                records.text(evidence[0], "detail_sha256"),
                roster,
                _related_id(kind, target, None, roster, evidence),
            )
        )
    return result


def _semantic(
    finding_id: str,
    comparisons: Sequence[Mapping[str, object]],
    memberships: Mapping[str, tuple[str, ...]],
    roster: tuple[str, ...],
    detail_sha256: Callable[[str], str],
) -> list[ScanSymptom]:
    grouped: dict[tuple[str, str], list[tuple[Mapping[str, object], int, str]]] = {}
    for index, comparison in enumerate(comparisons):
        path = records.text(comparison, "path")
        kind = records.text(comparison, "kind")
        signal = "ROW_COUNT_DIFFERENCE" if path == "$.rows" else kind
        records.reject(signal not in _SEMANTIC_LOCATIONS, "scan comparison signal is invalid")
        location = normalize_location(path)
        endpoints = sorted(
            memberships[records.text(comparison, key)] for key in ("left_group", "right_group")
        )
        detail = records.text(comparison, "detail")
        evidence = {
            "comparison_kind": signal,
            "groups": [list(item) for item in endpoints],
            "detail_sha256": detail_sha256(detail),
        }
        grouped.setdefault((signal, location), []).append((evidence, index, detail))
    result: list[ScanSymptom] = []
    for (signal, location), values in grouped.items():
        ordered = sorted(values, key=lambda item: records.canonical_bytes(item[0]))
        evidence = tuple(item[0] for item in ordered)
        result.append(
            ScanSymptom(
                occurrence_id(_identity(finding_id, signal, None, location, evidence)),
                finding_id,
                signal,
                None,
                location,
                evidence,
                tuple(item[1] for item in ordered),
                tuple(item[2] for item in ordered),
                ordered[0][2],
                records.text(evidence[0], "detail_sha256"),
                roster,
                _related_id(signal, None, location, roster, evidence),
            )
        )
    return result


def _identity(
    finding_id: str,
    signal: str,
    target: str | None,
    location: str | None,
    evidence: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "occurrence_format": OCCURRENCE_FORMAT,
        "evidence_regime": "scan",
        "finding_id": finding_id,
        "signal": signal,
        "operation": "read",
        "target_reader": target,
        "normalized_location": location,
        "evidence": [dict(item) for item in evidence],
    }


def _related_id(
    signal: str,
    target: str | None,
    location: str | None,
    roster: tuple[str, ...],
    evidence: Sequence[Mapping[str, object]],
) -> str:
    shape: object
    if target is not None:
        shape = (signal, "read", target, evidence[0]["diagnostic_kind"])
    else:
        comparisons = sorted(
            ((item["comparison_kind"], item["groups"]) for item in evidence),
            key=records.canonical_bytes,
        )
        shape = (signal, "read", location, roster, comparisons)
    return hashlib.sha256(records.canonical_bytes(shape)).hexdigest()


def _validate_summary_evidence(
    signal: str,
    location: str | None,
    evidence: tuple[Mapping[str, object], ...],
    roster: tuple[str, ...],
) -> None:
    execution = signal in _EXECUTION_SIGNALS
    keys = [records.canonical_bytes(item) for item in evidence]
    required = {"outcome_kind", "diagnostic_kind", "detail_sha256"}
    required |= {"timeout_seconds"} if signal == "TIMEOUT" else set()
    expected = required if execution else {"comparison_kind", "groups", "detail_sha256"}
    malformed = (
        not evidence
        or keys != sorted(set(keys))
        or any(set(item) != expected for item in evidence)
        or any(not records.valid_digest(records.text(item, "detail_sha256")) for item in evidence)
    )
    records.reject(malformed, "new observation evidence is invalid")
    if execution:
        item, timeout = evidence[0], evidence[0].get("timeout_seconds")
        diagnostic = records.text(item, "diagnostic_kind")
        malformed = len(evidence) != 1 or records.text(item, "outcome_kind") != signal
        malformed |= not diagnostic or (signal != "PROVIDER_ERROR" and diagnostic != signal)
        malformed |= signal == "TIMEOUT" and (
            isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300
        )
    else:
        shapes: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
        for item in evidence:
            raw = item["groups"]
            groups = cast(list[object], raw) if isinstance(raw, list) else []
            records.reject(
                not isinstance(raw, list)
                or len(groups) != 2
                or any(not isinstance(endpoint, list) for endpoint in groups),
                "new observation comparison groups are invalid",
            )
            endpoints = tuple(
                records.group_members({"id": "summary", "engines": endpoint})[1]
                for endpoint in cast(list[list[object]], groups)
            )
            readers = tuple(reader for endpoint in endpoints for reader in endpoint)
            canonical = (
                all(endpoints)
                and endpoints == tuple(sorted(endpoints))
                and all(endpoint == tuple(sorted(endpoint)) for endpoint in endpoints)
                and len(readers) == len(set(readers))
                and set(readers) <= set(roster)
            )
            records.reject(not canonical, "new observation comparison groups are invalid")
            shapes.append((records.text(item, "comparison_kind"), endpoints))
        malformed = (
            location is None
            or _SEMANTIC_LOCATIONS[signal].fullmatch(location) is None
            or any(kind != signal for kind, _ in shapes)
            or len(shapes) != len(set(shapes))
        )
    records.reject(malformed, "new observation typed evidence is invalid")
