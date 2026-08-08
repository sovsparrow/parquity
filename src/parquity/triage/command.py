from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from ..findings import json_codec as codec
from ..scans import replay_evidence, symptoms
from ..writer_profiles import WriterProfilePlan
from .adapters import generated_occurrences, scan_occurrences
from .generated_replay import classification, generated_replay_states
from .model import (
    FAMILY_FORMAT,
    Focus,
    Occurrence,
    ReproductionState,
    canonical_bytes,
    focused_families,
    group_occurrences,
)
from .normalization import detail_sha256_v1, normalize_detail_v1

if TYPE_CHECKING:
    from ..runs.bundle import ValidatedRun
    from ..scans.bundle import ValidatedScanRun


class _GeneratedBundleModule(Protocol):
    RunBundleValidationError: type[Exception]
    validate_run: Callable[[Path], ValidatedRun]


class _ScanBundleModule(Protocol):
    ScanBundleError: type[Exception]
    validate_run: Callable[[Path], ValidatedScanRun]


class TriageError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class _Target:
    format_name: str
    identity_name: str
    identity_value: str
    occurrences: tuple[Occurrence, ...]
    finding_ids: tuple[str, ...]
    engine_orders: Mapping[str, tuple[str, ...]]
    scan_symptoms: Mapping[str, symptoms.ScanSymptom]
    writer_profiles: WriterProfilePlan | None = None


_TOP: set[str] = {"format", "command", "status"}
_SCAN_TOP = _TOP | {"scan_id", "results"}
_RESULT: set[str] = {"finding_id", "classification", "version_evidence"}
_SCAN_RESULT = _RESULT | {"package_version", "occurrence_results", "new_observations"}


def triage_run(directory: Path, focus_name: str, replay_path: Path | None) -> dict[str, object]:
    focus = Focus(focus_name)
    target = _validated_target(directory)
    replay_states = None if replay_path is None else _replay_states(replay_path, target)
    families = group_occurrences(target.occurrences, replay_states)
    displayed = focused_families(families, focus)
    result: dict[str, object] = {
        "run_format": target.format_name,
        target.identity_name: target.identity_value,
        "projection_version": FAMILY_FORMAT,
        "focus": focus.value,
        "replay_evidence": "NOT_PROVIDED" if replay_path is None else "VALIDATED",
        "finding_bundle_count": len(target.finding_ids),
        "occurrence_count": len(target.occurrences),
        "symptom_family_count": len(families),
        "displayed_symptom_family_count": len(displayed),
        "symptom_families": [family.to_data() for family in displayed],
    }
    if target.writer_profiles is not None:
        result["writer_profiles"] = target.writer_profiles.to_data()
    return result


def _validated_target(directory: Path) -> _Target:
    run_manifest = directory / "run.json"
    scan_manifest = directory / "scan.json"
    if run_manifest.is_file() and not scan_manifest.exists():
        return _generated_target(directory)
    if scan_manifest.is_file() and not run_manifest.exists():
        return _scan_target(directory)
    raise TriageError("INVALID_RUN", "triage requires one complete generated or scan run")


def _generated_target(directory: Path) -> _Target:
    bundle = cast(_GeneratedBundleModule, cast(object, import_module("parquity.runs.bundle")))

    try:
        validated = bundle.validate_run(directory)
    except bundle.RunBundleValidationError as error:
        kind = getattr(error, "kind", "INVALID_RUN")
        detail = getattr(error, "detail", "generated run validation failed")
        raise TriageError(str(kind), str(detail)) from error
    finding_ids = tuple(child.finding.finding_id for child in validated.children)
    return _Target(
        "parquity.run.v1",
        "run_id",
        validated.run.run_id,
        generated_occurrences(validated),
        finding_ids,
        {},
        {},
        validated.run.writer_profiles,
    )


def _scan_target(directory: Path) -> _Target:
    bundle = cast(_ScanBundleModule, cast(object, import_module("parquity.scans.bundle")))

    try:
        validated = bundle.validate_run(directory)
        scan_id = codec.string(validated.record.data["scan_id"], "scan_id")
    except bundle.ScanBundleError as error:
        raise TriageError("INVALID_RUN", "scan run validation failed") from error
    engine_orders = {
        child.record.finding_id: tuple(item.name for item in child.record.engines)
        for child in validated.children
    }
    symptom_items = tuple(
        item
        for child in validated.children
        for item in symptoms.extract(child.record, detail_sha256_v1)
    )
    return _Target(
        "parquity.scan-run.v1",
        "scan_id",
        scan_id,
        scan_occurrences(validated),
        tuple(child.record.finding_id for child in validated.children),
        engine_orders,
        {item.occurrence_id: item for item in symptom_items},
    )


def _replay_states(path: Path, target: _Target) -> dict[str, ReproductionState]:
    try:
        payload = path.read_bytes()
        decoded = cast(object, json.loads(payload, object_pairs_hook=codec.unique_object))
        document = codec.mapping(decoded, "replay evidence")
        _reject(payload != canonical_bytes(document) + b"\n")
        _reject(document.get("format") != "parquity.cli.v1" or document.get("command") != "replay")
        if target.format_name == "parquity.run.v1":
            return generated_replay_states(
                document,
                target.identity_value,
                target.finding_ids,
                target.occurrences,
                target.writer_profiles,
            )
        return _scan_replay(document, target)
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise TriageError("INVALID_REPLAY_EVIDENCE", "replay evidence is invalid") from error


def _scan_replay(document: Mapping[str, object], target: _Target) -> dict[str, ReproductionState]:
    codec.require_exact_keys(document, _SCAN_TOP, "scan replay evidence")
    _reject(codec.string(codec.required(document, "scan_id"), "scan_id") != target.identity_value)
    results = _mappings(codec.required(document, "results"), "scan replay results")
    actual = tuple(codec.string(item["finding_id"], "finding_id") for item in results)
    _reject(actual != target.finding_ids or len(actual) != len(set(actual)))
    states: dict[str, ReproductionState] = {}
    finding_states: list[ReproductionState] = []
    for finding_id, result in zip(actual, results, strict=True):
        occurrences = tuple(item for item in target.occurrences if item.finding_id == finding_id)
        item_states, finding_state = _scan_result_states(
            result,
            occurrences,
            target.engine_orders[finding_id],
            target.scan_symptoms,
        )
        states.update(item_states)
        finding_states.append(finding_state)
    _reject(set(states) != {item.occurrence_id for item in target.occurrences})
    distinct = {state.value for state in finding_states}
    expected = distinct.pop() if len(distinct) == 1 else "RELATED_FAILURE"
    _reject(document.get("status") != expected)
    return states


def _scan_result_states(
    result: Mapping[str, object],
    occurrences: tuple[Occurrence, ...],
    engine_order: tuple[str, ...],
    original_symptoms: Mapping[str, symptoms.ScanSymptom] | None = None,
) -> tuple[dict[str, ReproductionState], ReproductionState]:
    codec.require_exact_keys(result, _SCAN_RESULT, "scan replay result")
    _reject(not occurrences)
    _scan_result_versions(result, occurrences[0], engine_order)
    values = _mappings(result["occurrence_results"], "occurrence results")
    expected_ids = tuple(sorted(item.occurrence_id for item in occurrences))
    replay_evidence.validate_results(
        values, expected_ids, original_symptoms, engine_order, normalize_detail_v1
    )
    states = {
        codec.string(value["occurrence_id"], "occurrence_id"): classification(value)
        for value in values
    }
    new_values = _mappings(result["new_observations"], "new observations")
    has_new = replay_evidence.validate_new_observations(
        new_values,
        occurrences[0].finding_id,
        {item.occurrence_id for item in occurrences},
        {cast(str, item.related_id) for item in occurrences},
        engine_order,
    )
    finding_state = classification(result)
    _reject(finding_state is not _derived_state(tuple(states.values()), has_new))
    return states, finding_state


def _scan_result_versions(
    result: Mapping[str, object], occurrence: Occurrence, engine_order: tuple[str, ...]
) -> None:
    package = codec.mapping(result["package_version"], "package version")
    codec.require_exact_keys(package, {"original", "current", "drift"}, "package version")
    original = codec.string(package["original"], "original package version")
    current = codec.string(package["current"], "current package version")
    drift = codec.boolean(package["drift"], "package version drift")
    _reject(not original or not current or drift != (original != current))
    _reject(dict(occurrence.package_versions).get("parquity") != original)
    versions = tuple(
        _scan_version(item) for item in _mappings(result["version_evidence"], "versions")
    )
    expected = {engine: version for _, engine, version in occurrence.provider_versions}
    conflicting = tuple(item[0] for item in versions) != engine_order or any(
        expected[engine] != recorded for engine, recorded, _, _ in versions
    )
    _reject(conflicting)


def _derived_state(states: tuple[ReproductionState, ...], has_new: bool) -> ReproductionState:
    if not has_new and all(item is ReproductionState.REPRODUCED for item in states):
        return ReproductionState.REPRODUCED
    if not has_new and all(item is ReproductionState.NOT_REPRODUCED for item in states):
        return ReproductionState.NOT_REPRODUCED
    return ReproductionState.RELATED_FAILURE


def _scan_version(value: Mapping[str, object]) -> tuple[str, str, str, bool]:
    codec.require_exact_keys(
        value, {"engine", "original", "current", "drift"}, "scan version evidence"
    )
    result = (
        codec.string(value["engine"], "engine"),
        codec.string(value["original"], "original version"),
        codec.string(value["current"], "current version"),
        codec.boolean(value["drift"], "version drift"),
    )
    _reject(not all(result[:3]) or result[3] != (result[1] != result[2]))
    return result


def _mappings(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    return tuple(codec.mapping(item, label) for item in codec.sequence(value, label))


def _reject(condition: bool) -> None:
    if condition:
        raise ValueError("replay evidence is contradictory")
