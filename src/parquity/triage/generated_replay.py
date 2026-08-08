from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from ..findings import json_codec as codec
from ..findings.evidence import DEPENDENCY_ORDER
from ..writer_profiles import WriterProfileIdentity, WriterProfilePlan
from .model import Occurrence, ReproductionState

_TOP = {"format", "command", "status", "run_id", "exact", "related", "absent", "findings"}
_RESULT = {
    "finding_id",
    "classification",
    "version_evidence",
    "version_drift",
    "dependency_evidence",
    "dependency_drift",
}


def generated_replay_states(
    document: Mapping[str, object],
    run_id: str,
    finding_ids: tuple[str, ...],
    occurrences: tuple[Occurrence, ...],
    writer_profiles: WriterProfilePlan | None,
) -> dict[str, ReproductionState]:
    top = _TOP if writer_profiles is None else _TOP | {"writer_profiles"}
    codec.require_exact_keys(document, top, "generated replay evidence")
    _reject(codec.string(codec.required(document, "run_id"), "run_id") != run_id)
    if writer_profiles is not None:
        recorded = WriterProfilePlan.from_data(
            codec.mapping(document["writer_profiles"], "writer_profiles")
        )
        _reject(recorded != writer_profiles)
    results = _mappings(codec.required(document, "findings"), "generated replay results")
    actual = tuple(codec.string(item["finding_id"], "finding_id") for item in results)
    _reject(actual != finding_ids or len(actual) != len(set(actual)))
    states = {
        occurrence.occurrence_id: _result_state(result, occurrence)
        for result, occurrence in zip(results, occurrences, strict=True)
    }
    counts = {
        state: codec.integer(document[name], name)
        for state, name in (
            (ReproductionState.REPRODUCED, "exact"),
            (ReproductionState.RELATED_FAILURE, "related"),
            (ReproductionState.NOT_REPRODUCED, "absent"),
        )
    }
    _reject(
        any(
            sum(state is key for state in states.values()) != count for key, count in counts.items()
        )
    )
    expected = "REPRODUCED" if counts[ReproductionState.REPRODUCED] else "NOT_REPRODUCED"
    _reject(document.get("status") != expected)
    return states


def classification(result: Mapping[str, object]) -> ReproductionState:
    state = ReproductionState(codec.string(result["classification"], "classification"))
    _reject(state is ReproductionState.NOT_CHECKED)
    return state


def _result_state(result: Mapping[str, object], occurrence: Occurrence) -> ReproductionState:
    keys = _RESULT if occurrence.writer_profile is None else _RESULT | {"writer_profile"}
    codec.require_exact_keys(result, keys, "generated replay result")
    if occurrence.writer_profile is not None:
        profile = WriterProfileIdentity.from_data(
            codec.mapping(result["writer_profile"], "writer_profile")
        )
        _reject(profile != occurrence.writer_profile)
    state = classification(result)
    evidence = tuple(
        _version(item) for item in _mappings(result["version_evidence"], "version evidence")
    )
    roles = _mappings(occurrence.projection["engine_roles"], "engine roles")
    expected_pairs = tuple(
        (role, codec.string(item["engine"], "engine"))
        for role in ("writer", "reader")
        for item in roles
        if codec.string(item["role"], "role") == role
    )
    pairs = tuple((item[0], item[1]) for item in evidence)
    recorded = {(role, engine): version for role, engine, version in occurrence.provider_versions}
    _reject(pairs != expected_pairs or len(pairs) != len(set(pairs)))
    _reject(any(recorded[pair] != item[2] for pair, item in zip(pairs, evidence, strict=True)))
    drift = tuple(_drift(item) for item in _mappings(result["version_drift"], "drift"))
    expected_drift = tuple(item[:4] for item in evidence if item[3] not in (None, item[2]))
    _reject(drift != expected_drift)
    dependencies = tuple(
        _dependency(item)
        for item in _mappings(result["dependency_evidence"], "dependency evidence")
    )
    packages = dict(occurrence.package_versions)
    expected_dependencies = tuple(
        (package, packages[package]) for package in DEPENDENCY_ORDER if package in packages
    )
    _reject(tuple(item[:2] for item in dependencies) != expected_dependencies)
    dependency_drift = tuple(
        _dependency_drift(item)
        for item in _mappings(result["dependency_drift"], "dependency drift")
    )
    expected_dependency_drift = tuple(
        (item[0], item[1], item[2]) for item in dependencies if item[2] not in (None, item[1])
    )
    _reject(dependency_drift != expected_dependency_drift)
    return state


def _version(value: Mapping[str, object]) -> tuple[str, str, str, str | None, bool]:
    codec.require_exact_keys(
        value, {"role", "engine", "original", "current", "available"}, "version evidence"
    )
    current_value = value["current"]
    current = None if current_value is None else codec.string(current_value, "current version")
    result = (
        codec.string(value["role"], "role"),
        codec.string(value["engine"], "engine"),
        codec.string(value["original"], "original version"),
        current,
        codec.boolean(value["available"], "availability"),
    )
    _reject(result[4] != (current is not None) or not all(result[:3]))
    return result


def _drift(value: Mapping[str, object]) -> tuple[str, str, str, str]:
    codec.require_exact_keys(value, {"role", "engine", "original", "current"}, "version drift")
    result = tuple(
        codec.string(value[key], key) for key in ("role", "engine", "original", "current")
    )
    _reject(not all(result) or result[2] == result[3])
    return cast(tuple[str, str, str, str], result)


def _dependency(value: Mapping[str, object]) -> tuple[str, str, str | None, bool]:
    codec.require_exact_keys(
        value, {"package", "original", "current", "available"}, "dependency evidence"
    )
    current_value = value["current"]
    current = None if current_value is None else codec.string(current_value, "current version")
    result = (
        codec.string(value["package"], "dependency package"),
        codec.string(value["original"], "original dependency version"),
        current,
        codec.boolean(value["available"], "dependency availability"),
    )
    _reject(result[0] not in DEPENDENCY_ORDER or not result[1])
    _reject(result[3] != (current is not None))
    return result


def _dependency_drift(value: Mapping[str, object]) -> tuple[str, str, str]:
    codec.require_exact_keys(value, {"package", "original", "current"}, "dependency drift")
    result = tuple(codec.string(value[key], key) for key in ("package", "original", "current"))
    _reject(result[0] not in DEPENDENCY_ORDER or not all(result) or result[1] == result[2])
    return cast(tuple[str, str, str], result)


def _mappings(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    return tuple(codec.mapping(item, label) for item in codec.sequence(value, label))


def _reject(condition: bool) -> None:
    if condition:
        raise ValueError("replay evidence is contradictory")


__all__ = ["classification", "generated_replay_states"]
