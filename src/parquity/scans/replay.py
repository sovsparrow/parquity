from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import NamedTuple, cast

from ..engines import ReaderSelection
from ..evidence import ReplayClassification
from ..evidence.normalization import detail_sha256_v1, normalize_detail_v1
from . import bundle, discovery, records, symptoms, workflow
from .supervision import WorkerProtocolError

_INVALID = "scan replay result is contradictory"


class ReplayComparison(NamedTuple):
    occurrence_results: tuple[Mapping[str, object], ...]
    new_observations: tuple[Mapping[str, object], ...]
    classification: ReplayClassification


@dataclass(frozen=True, slots=True)
class ScanFindingReplayOutcome:
    finding_id: str
    classification: ReplayClassification
    package_version: Mapping[str, object]
    version_evidence: tuple[Mapping[str, object], ...]
    occurrence_results: tuple[Mapping[str, object], ...]
    new_observations: tuple[Mapping[str, object], ...]

    @property
    def has_exact_reproduction(self) -> bool:
        return any(
            occurrence_classification(item) is ReplayClassification.REPRODUCED
            for item in self.occurrence_results
        )


@dataclass(frozen=True, slots=True)
class ScanRunReplayOutcome:
    results: tuple[ScanFindingReplayOutcome, ...]
    classification: ReplayClassification
    has_exact_reproduction: bool


def replay_finding(
    validated: bundle.ValidatedScanFinding,
    selection: ReaderSelection,
) -> ScanFindingReplayOutcome:
    record = validated.record
    recorded_roster = tuple(item.name for item in record.engines)
    if selection.reader_names != recorded_roster:
        raise WorkerProtocolError("scan replay requires the exact recorded reader roster")
    with tempfile.TemporaryDirectory(prefix="parquity-scan-replay-") as raw_root:
        root = Path(raw_root)
        try:
            source = discovery.discover_input(validated.directory / "input.parquet").files[0]
            snapshot = discovery.snapshot_file(source, root / "snapshot")
        except discovery.ScanConfigurationError as error:
            if error.kind not in ("INVALID_INPUT", "EMPTY_INPUT"):
                raise
            raise discovery.ScanConfigurationError(
                "INPUT_DRIFT", "validated scan input changed before replay"
            ) from error
        if snapshot.sha256 != record.input_sha256:
            raise discovery.ScanConfigurationError(
                "INPUT_DRIFT", "validated scan input changed before replay"
            )
        evaluation = workflow.evaluate_snapshot(snapshot, selection, record.timeout_seconds, root)
    original = symptoms.extract(record, detail_sha256_v1)
    current = symptoms.extract_observations(
        record.finding_id,
        selection.reader_names,
        record.timeout_seconds,
        evaluation.outcomes,
        evaluation.grouped.groups,
        evaluation.grouped.differences,
        detail_sha256_v1,
    )
    comparison = compare(original, current, normalize_detail_v1)
    current_versions = dict(selection.reader_versions)
    versions = tuple(
        {
            "engine": item.name,
            "original": item.version,
            "current": current_versions[item.name],
            "drift": item.version != current_versions[item.name],
        }
        for item in record.engines
    )
    return ScanFindingReplayOutcome(
        finding_id=record.finding_id,
        classification=comparison.classification,
        package_version={
            "original": record.parquity_version,
            "current": metadata.version("parquity"),
            "drift": record.parquity_version != metadata.version("parquity"),
        },
        version_evidence=versions,
        occurrence_results=comparison.occurrence_results,
        new_observations=comparison.new_observations,
    )


def replay_run(
    validated: bundle.ValidatedScanRun,
    selection: ReaderSelection,
) -> ScanRunReplayOutcome:
    results = tuple(replay_finding(child, selection) for child in validated.children)
    classification = run_status(tuple(item.classification for item in results))
    return ScanRunReplayOutcome(
        results,
        classification,
        any(item.has_exact_reproduction for item in results),
    )


def occurrence_classification(value: Mapping[str, object]) -> ReplayClassification:
    try:
        state = ReplayClassification(records.text(value, "classification"))
    except ValueError as error:
        raise records.ScanRecordError(_INVALID) from error
    return state


def finding_classification(
    states: Sequence[ReplayClassification], *, has_new_observations: bool
) -> ReplayClassification:
    records.reject(not states, _INVALID)
    if not has_new_observations and all(
        state is ReplayClassification.REPRODUCED for state in states
    ):
        return ReplayClassification.REPRODUCED
    if not has_new_observations and all(
        state is ReplayClassification.NOT_REPRODUCED for state in states
    ):
        return ReplayClassification.NOT_REPRODUCED
    return ReplayClassification.RELATED_FAILURE


def run_status(states: Sequence[ReplayClassification]) -> ReplayClassification:
    records.reject(not states, _INVALID)
    distinct = set(states)
    return distinct.pop() if len(distinct) == 1 else ReplayClassification.RELATED_FAILURE


def has_exact_reproduction(results: Sequence[ScanFindingReplayOutcome]) -> bool:
    return any(result.has_exact_reproduction for result in results)


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
    states = tuple(occurrence_classification(item) for item in results)
    classification = finding_classification(states, has_new_observations=bool(new))
    return ReplayComparison(tuple(results), new, classification)


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
