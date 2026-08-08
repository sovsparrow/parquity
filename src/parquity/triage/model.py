from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import cast

from ..reporting import markdown_literal
from ..scans.symptoms import OCCURRENCE_FORMAT
from ..writer_profiles import WriterProfileIdentity, WriterProfilePlan
from .versions import observed_versions, version_text

FAMILY_FORMAT = "parquity.triage-family.v1"


class Signal(StrEnum):
    PROCESS_CRASH = "PROCESS_CRASH"
    TIMEOUT = "TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    ROW_COUNT_DIFFERENCE = "ROW_COUNT_DIFFERENCE"
    VALUE_DIFFERENCE = "VALUE_DIFFERENCE"
    SCHEMA_DIFFERENCE = "SCHEMA_DIFFERENCE"


class ReproductionState(StrEnum):
    REPRODUCED = "REPRODUCED"
    RELATED_FAILURE = "RELATED_FAILURE"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_REPRODUCED = "NOT_REPRODUCED"


class Focus(StrEnum):
    ALL = "all"
    EXECUTION = "execution"
    DATA = "data"
    SCHEMA = "schema"


_SIGNAL_ORDER = tuple(Signal)
_REPRODUCTION_ORDER = tuple(ReproductionState)
_FOCUS_SIGNALS = {
    Focus.EXECUTION: frozenset(_SIGNAL_ORDER[:3]),
    Focus.DATA: frozenset(_SIGNAL_ORDER[3:5]),
    Focus.SCHEMA: frozenset(_SIGNAL_ORDER[5:]),
}


@dataclass(frozen=True, slots=True)
class Occurrence:
    occurrence_id: str
    finding_id: str
    regime: str
    signal: Signal
    projection: dict[str, object]
    reference_name: str
    reference_value: str
    input_kind: str
    input_sha256: str
    input_bytes: int
    reduction_completed: bool | None
    package_versions: tuple[tuple[str, str], ...]
    provider_versions: tuple[tuple[str, str, str], ...]
    normalized_location: object | None
    detail: str
    detail_sha256: str
    reproduction_state: ReproductionState = ReproductionState.NOT_CHECKED
    related_id: str | None = None
    writer_profiles: WriterProfilePlan | None = None
    writer_profile: WriterProfileIdentity | None = None

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "occurrence_id": self.occurrence_id,
            "occurrence_format": OCCURRENCE_FORMAT,
            "finding_id": self.finding_id,
            "signal": self.signal.value,
            self.reference_name: self.reference_value,
            "input_kind": self.input_kind,
            "input_sha256": self.input_sha256,
            "input_bytes": self.input_bytes,
            "reproduction_state": self.reproduction_state.value,
            "package_versions": [
                {"package": package, "version": version}
                for package, version in self.package_versions
            ],
            "provider_versions": [
                {"role": role, "engine": engine, "version": version}
                for role, engine, version in self.provider_versions
            ],
            "normalized_location": self.normalized_location,
            "detail_sha256": self.detail_sha256,
        }
        if self.reduction_completed is not None:
            data["reduction_completed"] = self.reduction_completed
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        if self.writer_profile is not None:
            data["writer_profile"] = self.writer_profile.to_data()
        return data


@dataclass(frozen=True, slots=True)
class Family:
    family_id: str
    regime: str
    signal: Signal
    projection: dict[str, object]
    occurrences: tuple[Occurrence, ...]
    representative: Occurrence

    def to_data(self) -> dict[str, object]:
        packages, providers = observed_versions(self.occurrences)
        reference = {self.representative.reference_name: self.representative.reference_value}
        detail = _detail_evidence(self.representative)
        data = {
            "family_id": self.family_id,
            "projection_version": FAMILY_FORMAT,
            "evidence_regime": self.regime,
            "family_kind": "conformance" if self.regime == "generated" else "observation",
            "signal": self.signal.value,
            "operation": self.projection["operation"],
            "occurrence_count": len(self.occurrences),
            "reproduction_state_counts": _state_counts(self.occurrences),
            "representative": {
                "occurrence_id": self.representative.occurrence_id,
                "finding_id": self.representative.finding_id,
                "normalized_location": self.representative.normalized_location,
                "detail": detail,
                **reference,
            },
            "representative_reproduction_state": self.representative.reproduction_state.value,
            "novelty_state": "UNAVAILABLE",
            "member_occurrence_ids": [item.occurrence_id for item in self.occurrences],
            "member_finding_ids": sorted({item.finding_id for item in self.occurrences}),
            "representative_command": _replay_command(self.representative.finding_id),
            "observed_versions": {"packages": packages, "providers": providers},
            "projection": self.projection,
            "occurrences": [item.to_data() for item in self.occurrences],
        }
        if self.regime == "scan":
            data["reader_roster"] = self.projection["reader_roster"]
        if self.representative.writer_profiles is not None:
            data["writer_profiles"] = self.representative.writer_profiles.to_data()
        if self.representative.writer_profile is not None:
            data["writer_profile"] = self.representative.writer_profile.to_data()
        return data


def group_occurrences(
    occurrences: tuple[Occurrence, ...],
    replay_states: dict[str, ReproductionState] | None = None,
) -> tuple[Family, ...]:
    identifiers = [item.occurrence_id for item in occurrences]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError("validated aggregate contains duplicate occurrence identities")
    if replay_states is not None and set(replay_states) != set(identifiers):
        raise ValueError("replay evidence does not cover the complete aggregate")
    grouped: dict[str, tuple[bytes, list[Occurrence]]] = {}
    for original in occurrences:
        item = (
            original
            if replay_states is None
            else replace(original, reproduction_state=replay_states[original.occurrence_id])
        )
        key_bytes = canonical_bytes(item.projection)
        family_id = hashlib.sha256(key_bytes).hexdigest()
        if family_id in grouped and grouped[family_id][0] != key_bytes:
            raise RuntimeError("unequal triage projection keys produced the same family ID")
        grouped.setdefault(family_id, (key_bytes, []))[1].append(item)
    families = tuple(_family(family_id, values) for family_id, (_, values) in grouped.items())
    return tuple(sorted(families, key=lambda item: item.family_id))


def focused_families(families: tuple[Family, ...], focus: Focus) -> tuple[Family, ...]:
    if focus is Focus.ALL:
        return families
    accepted = _FOCUS_SIGNALS[focus]
    return tuple(family for family in families if family.signal in accepted)


def render_family_report(families: tuple[Family, ...], heading: str) -> str:
    occurrence_count = sum(len(family.occurrences) for family in families)
    finding_count = len({item.finding_id for family in families for item in family.occurrences})
    lines = [
        f"## {heading}",
        "",
        "These conservative symptom families retain every occurrence and do not assign fault.",
        "",
        f"- Retained finding bundles: `{finding_count}`",
        f"- Symptom occurrences: `{occurrence_count}`",
        f"- Symptom families: `{len(families)}`",
    ]
    for family in families:
        representative = family.representative
        packages, providers = observed_versions(family.occurrences)
        lines.extend(
            (
                "",
                f"### Symptom family `{family.family_id}`",
                "",
                f"- Projection: `{FAMILY_FORMAT}`",
                f"- Evidence regime: `{family.regime}`",
                f"- Signal: `{family.signal.value}`",
                f"- Operation: `{family.projection['operation']}`",
                _roster_line(family.projection),
                f"- Occurrence count: `{len(family.occurrences)}`",
                f"- Reproduction-state counts: {_state_count_text(family.occurrences)}",
                f"- Representative occurrence: `{representative.occurrence_id}`",
                f"- Representative finding: `{representative.finding_id}`; "
                f"{representative.reference_name} "
                f"{markdown_literal(representative.reference_value)}",
                f"- Representative reproduction state: `{representative.reproduction_state.value}`",
                f"- Representative location: {_location_literal(representative)}",
                f"- Representative detail: {_detail_literal(representative)}",
                "- Novelty state: `UNAVAILABLE`",
                f"- Packages: {markdown_literal(version_text(packages, 'package'))}",
                f"- Providers: {markdown_literal(version_text(providers, 'engine'))}",
                f"- Member occurrence IDs: "
                f"`{', '.join(item.occurrence_id for item in family.occurrences)}`",
                f"- Member finding IDs: "
                f"`{', '.join(sorted({item.finding_id for item in family.occurrences}))}`",
                f"- Inspect or replay: `{_replay_command(representative.finding_id)}`",
            )
        )
    return "\n".join(lines)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _family(family_id: str, values: list[Occurrence]) -> Family:
    occurrences = tuple(sorted(values, key=lambda item: item.occurrence_id))
    representative = min(occurrences, key=_representative_key)
    first = occurrences[0]
    return Family(
        family_id,
        first.regime,
        first.signal,
        first.projection,
        occurrences,
        representative,
    )


def _representative_key(item: Occurrence) -> tuple[int, bool, int, str]:
    return (
        _REPRODUCTION_ORDER.index(item.reproduction_state),
        item.reduction_completed is not True,
        item.input_bytes,
        item.occurrence_id,
    )


def _state_counts(occurrences: tuple[Occurrence, ...]) -> dict[str, int]:
    order = (
        ReproductionState.REPRODUCED,
        ReproductionState.RELATED_FAILURE,
        ReproductionState.NOT_REPRODUCED,
        ReproductionState.NOT_CHECKED,
    )
    return {
        state.value: sum(item.reproduction_state is state for item in occurrences)
        for state in order
    }


def _state_count_text(occurrences: tuple[Occurrence, ...]) -> str:
    return ", ".join(f"`{name}={count}`" for name, count in _state_counts(occurrences).items())


def _detail_evidence(item: Occurrence) -> dict[str, object]:
    displayed = item.detail[:500]
    return {
        "text": displayed,
        "sha256": item.detail_sha256,
        "truncated": len(item.detail) > len(displayed),
    }


def _detail_literal(item: Occurrence) -> str:
    evidence = _detail_evidence(item)
    return (
        f"{markdown_literal(cast(str, evidence['text']))}; "
        f"SHA-256 `{item.detail_sha256}`; truncated `{str(evidence['truncated']).lower()}`"
    )


def _location_literal(item: Occurrence) -> str:
    if item.normalized_location is None:
        return "`UNAVAILABLE`"
    value = json.dumps(item.normalized_location, sort_keys=True, ensure_ascii=False)
    return markdown_literal(value)


def _roster_line(projection: dict[str, object]) -> str:
    roster = cast(list[str] | None, projection.get("reader_roster"))
    value = "UNAVAILABLE" if roster is None else ", ".join(roster)
    return f"- Reader roster: {markdown_literal(value)}"


def _replay_command(finding_id: str) -> str:
    return f"parquity replay RUN_DIR/findings/{finding_id}"


__all__ = [
    "FAMILY_FORMAT",
    "Family",
    "Focus",
    "Occurrence",
    "ReproductionState",
    "Signal",
    "canonical_bytes",
    "focused_families",
    "group_occurrences",
    "markdown_literal",
    "render_family_report",
]
