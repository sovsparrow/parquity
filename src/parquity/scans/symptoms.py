from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import total_ordering
from typing import NamedTuple, cast

from ..evidence import sha256_hex
from . import records
from .differences import DifferenceKind, ScanDifference
from .observations import ObservationDifference, ObservationGroup

SCAN_SYMPTOM_FORMAT = "parquity.scan-symptom.v1"


class ScanOccurrenceRef(NamedTuple):
    source_bundle_id: str
    occurrence_id: str


class ScanExecutionEvidence(NamedTuple):
    outcome_kind: str
    diagnostic_kind: str
    detail_sha256: str
    timeout_seconds: int | None


class ScanComparisonEdge(NamedTuple):
    groups: tuple[tuple[str, ...], tuple[str, ...]]
    comparison_kind: str
    detail_sha256: str


ScanFindingEvidence = ScanExecutionEvidence | ScanComparisonEdge


@total_ordering
@dataclass(frozen=True, slots=True, init=False)
class ScanFindingKey:
    occurrence_format: str
    evidence_regime: str
    signal: str
    operation: str
    target_reader: str | None
    normalized_location: str | None
    evidence: tuple[ScanFindingEvidence, ...]

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("ScanFindingKey values must be derived with finding_key()")

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ScanFindingKey):
            return NotImplemented
        return self.canonical_bytes() < other.canonical_bytes()

    def canonical_bytes(self) -> bytes:
        return records.canonical_bytes(_finding_key_data(self))


class ScanSymptom(NamedTuple):
    occurrence_id: str
    finding_id: str
    signal: str
    target_reader: str | None
    normalized_location: str | None
    evidence: tuple[Mapping[str, object], ...]
    details: tuple[str, ...]
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


def extract(
    record: records.ScanFindingRecord,
    detail_sha256: Callable[[str], str],
) -> tuple[ScanSymptom, ...]:
    data = record.data
    return extract_observations(
        record.finding_id,
        tuple(item.name for item in record.engines),
        record.timeout_seconds,
        record.outcomes,
        tuple(
            _group_from_data(item)
            for item in records.mappings(data["observation_groups"], "observation groups")
        ),
        tuple(
            _comparison_from_data(item)
            for item in records.mappings(data["comparisons"], "comparisons")
        ),
        detail_sha256,
    )


def extract_evidence(
    finding_id: str,
    reader_roster: tuple[str, ...],
    timeout_seconds: int,
    outcomes: Sequence[records.ReaderOutcomeRecord | Mapping[str, object]],
    groups: Sequence[ObservationGroup | Mapping[str, object]],
    comparisons: Sequence[ObservationDifference | Mapping[str, object]],
    detail_sha256: Callable[[str], str],
) -> tuple[ScanSymptom, ...]:
    return extract_observations(
        finding_id,
        reader_roster,
        timeout_seconds,
        tuple(
            item
            if isinstance(item, records.ReaderOutcomeRecord)
            else records.ReaderOutcomeRecord.from_data(item)
            for item in outcomes
        ),
        tuple(
            item if isinstance(item, ObservationGroup) else _group_from_data(item)
            for item in groups
        ),
        tuple(
            item if isinstance(item, ObservationDifference) else _comparison_from_data(item)
            for item in comparisons
        ),
        detail_sha256,
    )


def extract_observations(
    finding_id: str,
    reader_roster: tuple[str, ...],
    timeout_seconds: int,
    outcomes: Sequence[records.ReaderOutcomeRecord],
    groups: Sequence[ObservationGroup],
    comparisons: Sequence[ObservationDifference],
    detail_sha256: Callable[[str], str],
) -> tuple[ScanSymptom, ...]:
    roster = tuple(sorted(reader_roster))
    memberships = {group.group_id: tuple(sorted(group.engines)) for group in groups}
    result = _execution(finding_id, timeout_seconds, outcomes, roster, detail_sha256)
    result.extend(_semantic(finding_id, comparisons, memberships, roster, detail_sha256))
    expected = sum(item.kind is not records.ReaderOutcomeKind.SUCCESS for item in outcomes)
    expected += len(comparisons)
    if sum(len(item.evidence) for item in result) != expected or len(
        {item.occurrence_id for item in result}
    ) != len(result):
        raise RuntimeError("scan symptom extraction invariant failed")
    return tuple(sorted(result, key=lambda item: item.occurrence_id))


def occurrence_id(identity: Mapping[str, object]) -> str:
    return sha256_hex(records.canonical_bytes(identity))


def finding_key(occurrence: ScanSymptom) -> ScanFindingKey:
    key = object.__new__(ScanFindingKey)
    object.__setattr__(key, "occurrence_format", SCAN_SYMPTOM_FORMAT)
    object.__setattr__(key, "evidence_regime", "scan")
    object.__setattr__(key, "signal", occurrence.signal)
    object.__setattr__(key, "operation", "read")
    object.__setattr__(key, "target_reader", occurrence.target_reader)
    object.__setattr__(key, "normalized_location", occurrence.normalized_location)
    object.__setattr__(key, "evidence", _finding_evidence(occurrence))
    return key


def _execution(
    finding_id: str,
    timeout_seconds: int,
    outcomes: Sequence[records.ReaderOutcomeRecord],
    roster: tuple[str, ...],
    detail_sha256: Callable[[str], str],
) -> list[ScanSymptom]:
    result: list[ScanSymptom] = []
    for outcome in outcomes:
        kind = outcome.kind
        if kind is records.ReaderOutcomeKind.SUCCESS:
            continue
        signal = kind.value
        detail = outcome.detail
        item: dict[str, object] = {
            "outcome_kind": signal,
            "diagnostic_kind": outcome.diagnostic_kind,
            "detail_sha256": detail_sha256(detail),
        }
        if kind is records.ReaderOutcomeKind.TIMEOUT:
            item["timeout_seconds"] = timeout_seconds
        evidence: tuple[Mapping[str, object], ...] = (item,)
        target = outcome.engine
        result.append(
            ScanSymptom(
                occurrence_id(_identity(finding_id, signal, target, None, evidence)),
                finding_id,
                signal,
                target,
                None,
                evidence,
                (detail,),
                roster,
                _related_id(signal, target, None, roster, evidence),
            )
        )
    return result


def _semantic(
    finding_id: str,
    comparisons: Sequence[ObservationDifference],
    memberships: Mapping[str, tuple[str, ...]],
    roster: tuple[str, ...],
    detail_sha256: Callable[[str], str],
) -> list[ScanSymptom]:
    grouped: dict[tuple[str, str], list[tuple[Mapping[str, object], str]]] = {}
    for comparison in comparisons:
        try:
            difference = ScanDifference(comparison.kind, comparison.path).normalized()
        except ValueError as error:
            raise records.ScanRecordError("scan comparison signal is invalid") from error
        signal = difference.kind.value
        location = difference.path
        endpoints = sorted(
            memberships[group_id] for group_id in (comparison.left_group, comparison.right_group)
        )
        detail = comparison.detail
        evidence = {
            "comparison_kind": signal,
            "groups": [list(item) for item in endpoints],
            "detail_sha256": detail_sha256(detail),
        }
        grouped.setdefault((signal, location), []).append((evidence, detail))
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
        "occurrence_format": SCAN_SYMPTOM_FORMAT,
        "evidence_regime": "scan",
        "finding_id": finding_id,
        "signal": signal,
        "operation": "read",
        "target_reader": target,
        "normalized_location": location,
        "evidence": [dict(item) for item in evidence],
    }


def _finding_evidence(occurrence: ScanSymptom) -> tuple[ScanFindingEvidence, ...]:
    if occurrence.target_reader is not None:
        return tuple(_execution_evidence(item) for item in occurrence.evidence)
    edges: tuple[ScanComparisonEdge, ...] = tuple(
        _comparison_edge(item) for item in occurrence.evidence
    )
    return tuple(sorted(edges))


def _execution_evidence(item: Mapping[str, object]) -> ScanExecutionEvidence:
    timeout = item.get("timeout_seconds")
    if timeout is not None and (not isinstance(timeout, int) or isinstance(timeout, bool)):
        raise records.ScanRecordError("scan timeout evidence is invalid")
    return ScanExecutionEvidence(
        records.text(item, "outcome_kind"),
        records.text(item, "diagnostic_kind"),
        records.text(item, "detail_sha256"),
        timeout,
    )


def _comparison_edge(item: Mapping[str, object]) -> ScanComparisonEdge:
    raw_groups = item["groups"]
    if not isinstance(raw_groups, Sequence) or isinstance(raw_groups, str | bytes | bytearray):
        raise records.ScanRecordError("scan comparison groups are invalid")
    groups = tuple(
        sorted(
            tuple(sorted(records.group_members({"id": "edge", "engines": group})[1]))
            for group in cast(Sequence[object], raw_groups)
        )
    )
    if len(groups) != 2:
        raise records.ScanRecordError("scan comparison groups are invalid")
    return ScanComparisonEdge(
        (groups[0], groups[1]),
        records.text(item, "comparison_kind"),
        records.text(item, "detail_sha256"),
    )


def _finding_key_data(key: ScanFindingKey) -> dict[str, object]:
    return {
        "occurrence_format": key.occurrence_format,
        "evidence_regime": key.evidence_regime,
        "signal": key.signal,
        "operation": key.operation,
        "target_reader": key.target_reader,
        "normalized_location": key.normalized_location,
        "evidence": [_finding_evidence_data(item) for item in key.evidence],
    }


def _finding_evidence_data(item: ScanFindingEvidence) -> dict[str, object]:
    if isinstance(item, ScanExecutionEvidence):
        result: dict[str, object] = {
            "outcome_kind": item.outcome_kind,
            "diagnostic_kind": item.diagnostic_kind,
            "detail_sha256": item.detail_sha256,
        }
        if item.timeout_seconds is not None:
            result["timeout_seconds"] = item.timeout_seconds
        return result
    return _comparison_edge_data(item)


def _comparison_edge_data(item: ScanComparisonEdge) -> dict[str, object]:
    return {
        "comparison_kind": item.comparison_kind,
        "groups": [list(group) for group in item.groups],
        "detail_sha256": item.detail_sha256,
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
    return sha256_hex(records.canonical_bytes(shape))


def _group_from_data(data: Mapping[str, object]) -> ObservationGroup:
    group_id, engines = records.group_members(data)
    return ObservationGroup(group_id, engines)


def _comparison_from_data(data: Mapping[str, object]) -> ObservationDifference:
    try:
        kind = DifferenceKind(records.text(data, "kind"))
    except ValueError as error:
        raise records.ScanRecordError("scan comparison signal is invalid") from error
    return ObservationDifference(
        records.text(data, "left_group"),
        records.text(data, "right_group"),
        kind,
        records.text(data, "path"),
        records.text(data, "detail"),
    )
