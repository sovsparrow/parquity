from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

from ..evidence import EnvironmentEvidence

FULL_INLINE_MAX_ROWS = 20
FULL_INLINE_MAX_COLUMNS = 12
FULL_INLINE_MAX_UTF8_BYTES = 16_384
FULL_INLINE_MAX_CELL_CHARS = 512
PREVIEW_ROWS = 8
PREVIEW_COLUMNS = 8
PREVIEW_CELL_CHARS = 160

MAX_SUMMARY_CHARS = 240
MAX_LOCATION_CHARS = 512

_ANCHOR = re.compile(r"[a-z0-9][a-z0-9._:-]*", re.ASCII)
_FINDING_LABEL = re.compile(r"F[1-9][0-9]*", re.ASCII)


class ReportValidationError(ValueError): ...


class EvidenceKind(StrEnum):
    GENERATED = "GENERATED"
    SCAN = "SCAN"


def bounded_text(value: str, limit: int) -> str:
    if isinstance(limit, bool) or limit < 2:
        raise ReportValidationError("text bound must be at least two characters")
    normalized = " ".join(value.split())
    _require_text(normalized, "display text")
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


class ReplayState(StrEnum):
    NOT_RUN = "NOT_RUN"
    REPRODUCED = "REPRODUCED"
    RELATED_FAILURE = "RELATED_FAILURE"
    NOT_REPRODUCED = "NOT_REPRODUCED"

    @property
    def display_label(self) -> str:
        return self.value.replace("_", " ").title()


_REPLAY_ORDER = {state: index for index, state in enumerate(ReplayState)}


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    label: str
    relative_path: str
    anchor: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.label, "artifact label")
        path = PurePosixPath(self.relative_path)
        if (
            not self.relative_path
            or self.relative_path.startswith("/")
            or "\\" in self.relative_path
            or str(path) != self.relative_path
            or any(part in ("", ".", "..") for part in path.parts)
        ):
            raise ReportValidationError("artifact path must be a canonical relative path")
        if self.anchor is not None and _ANCHOR.fullmatch(self.anchor) is None:
            raise ReportValidationError("artifact anchor is malformed")


@dataclass(frozen=True, slots=True)
class DetailView:
    label: str
    value: str

    def __post_init__(self) -> None:
        _require_text(self.label, "detail label")
        _require_text(self.value, "detail value")


def environment_details(environment: EnvironmentEvidence) -> tuple[DetailView, ...]:
    dependencies = ", ".join(f"{item.package} {item.version}" for item in environment.dependencies)
    values = (
        DetailView("Parquity", environment.parquity_version),
        DetailView("Hypothesis", environment.hypothesis_version),
        DetailView("Python", environment.python_version),
        DetailView("Platform", environment.platform),
    )
    return values if not dependencies else (*values, DetailView("Dependencies", dependencies))


@dataclass(frozen=True, slots=True)
class ReplayStateCount:
    state: ReplayState
    count: int

    def __post_init__(self) -> None:
        if isinstance(self.count, bool) or self.count < 1:
            raise ReportValidationError("replay-state count must be positive")


@dataclass(frozen=True, slots=True)
class TableView:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        if not self.headers or any(not value for value in self.headers):
            raise ReportValidationError("table headers must not be empty")
        if len(self.headers) != len(set(self.headers)):
            raise ReportValidationError("table headers must be unique")
        if any(len(row) != len(self.headers) for row in self.rows):
            raise ReportValidationError("table rows must match the header width")


@dataclass(frozen=True, slots=True)
class InputView:
    identity: str
    facts: tuple[DetailView, ...]
    artifacts: tuple[ArtifactRef, ...]
    schema: TableView | None = None
    data: TableView | None = None
    omission_note: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.identity, "input identity")
        _require_unique_details(self.facts, "input facts")
        if not self.artifacts or not _unique_artifact_targets(self.artifacts):
            raise ReportValidationError("input artifact references must be non-empty and unique")
        if self.omission_note is not None:
            _require_text(self.omission_note, "input omission note")


@dataclass(frozen=True, slots=True)
class ReproductionStep:
    label: str
    command: str
    purpose: str

    def __post_init__(self) -> None:
        _require_text(self.label, "reproduction label")
        _require_text(self.command, "reproduction command")
        _require_text(self.purpose, "reproduction purpose")
        if "```" in self.command or "\x00" in self.command:
            raise ReportValidationError("reproduction command cannot break its code fence")


@dataclass(frozen=True, slots=True)
class FindingEvidenceView:
    anchor: str
    summary: str
    facts: tuple[DetailView, ...]

    def __post_init__(self) -> None:
        if _ANCHOR.fullmatch(self.anchor) is None:
            raise ReportValidationError("finding evidence anchor is malformed")
        _require_bounded(self.summary, "finding evidence summary", MAX_SUMMARY_CHARS)
        _require_unique_details(self.facts, "finding evidence facts")


@dataclass(frozen=True, slots=True)
class FindingView:
    label: str
    participants: str
    stage: str
    outcome_kind: str
    summary: str
    evidence_input: str
    exact_location: str
    occurrence_count: int
    distinct_input_count: int
    saved_replay_target_count: int
    evidence_refs: tuple[ArtifactRef, ...]
    replay_state_counts: tuple[ReplayStateCount, ...]

    def __post_init__(self) -> None:
        if _FINDING_LABEL.fullmatch(self.label) is None:
            raise ReportValidationError("Finding label is malformed")
        for value, label, limit in (
            (self.participants, "Finding participants", MAX_SUMMARY_CHARS),
            (self.stage, "Finding stage", MAX_SUMMARY_CHARS),
            (self.outcome_kind, "Finding outcome kind", MAX_SUMMARY_CHARS),
            (self.summary, "Finding summary", MAX_SUMMARY_CHARS),
            (self.evidence_input, "evidence input", MAX_SUMMARY_CHARS),
            (self.exact_location, "exact location", MAX_LOCATION_CHARS),
        ):
            _require_bounded(value, label, limit)
        counts = (self.occurrence_count, self.distinct_input_count)
        if any(isinstance(value, bool) or value < 1 for value in counts):
            raise ReportValidationError("Finding counts must be positive")
        if self.distinct_input_count > self.occurrence_count:
            raise ReportValidationError("distinct input count exceeds occurrence count")
        if (
            isinstance(self.saved_replay_target_count, bool)
            or not 0 <= self.saved_replay_target_count <= self.occurrence_count
        ):
            raise ReportValidationError("saved replay target count is inconsistent")
        if not self.evidence_refs or not _unique_artifact_targets(self.evidence_refs):
            raise ReportValidationError("Finding evidence references must be non-empty and unique")
        if self.saved_replay_target_count:
            _require_replay_counts(self.replay_state_counts)
            if (
                sum(item.count for item in self.replay_state_counts)
                != self.saved_replay_target_count
            ):
                raise ReportValidationError("replay states do not partition saved targets")
        elif self.replay_state_counts:
            raise ReportValidationError("manifest-only Finding cannot contain replay states")


@dataclass(frozen=True, slots=True)
class FailureRowView:
    participants: str
    failure: str
    source: str
    reproduce: str
    reference: ArtifactRef | None

    def __post_init__(self) -> None:
        for value, label in (
            (self.participants, "failure participants"),
            (self.failure, "failure description"),
            (self.source, "failure source"),
            (self.reproduce, "reproduction action"),
        ):
            _require_text(value, label)
        if (self.reproduce == "not saved") != (self.reference is None):
            raise ReportValidationError("reproduction action conflicts with its artifact")


@dataclass(frozen=True, slots=True)
class RunReportView:
    command: str
    evidence_kind: EvidenceKind
    summary: str
    writers: tuple[str, ...]
    readers: tuple[str, ...]
    evaluated_input_count: int
    executed_check_count: int
    affected_input_count: int
    findings: tuple[FindingView, ...]
    saved_evidence_count: int
    evidence_bundle_count: int
    unevaluated_input_count: int
    stop: str
    bounds: tuple[DetailView, ...]
    environment: tuple[DetailView, ...]
    machine_record: ArtifactRef | None
    replay_observations: tuple[DetailView, ...] = ()
    command_line: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.command, "report command"),
            (self.summary, "report summary"),
            (self.stop, "stop reason"),
        ):
            _require_text(value, label)
        if self.command_line is not None:
            _require_text(self.command_line, "report command line")
        _validate_provider_roles(self)
        _validate_run_counts(self)
        _validate_run_findings(self)
        _validate_run_evidence(self)
        _require_unique_details(self.bounds, "run bounds")
        _require_unique_details(self.environment, "run environment")
        _require_unique_details(self.replay_observations, "new replay observations")

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def occurrence_count(self) -> int:
        return sum(finding.occurrence_count for finding in self.findings)


@dataclass(frozen=True, slots=True)
class EvidenceReportView:
    evidence_kind: EvidenceKind
    title: str
    summary: str
    facts: tuple[DetailView, ...]
    reproduce: tuple[ReproductionStep, ...]
    input: InputView
    finding_evidence: tuple[FindingEvidenceView, ...]
    outcomes: TableView
    environment: tuple[DetailView, ...]
    machine_record: ArtifactRef
    replay_observations: tuple[DetailView, ...] = ()

    def __post_init__(self) -> None:
        _require_bounded(self.title, "evidence report title", MAX_SUMMARY_CHARS)
        _require_bounded(self.summary, "evidence report summary", MAX_SUMMARY_CHARS)
        _require_unique_details(self.facts, "evidence report facts")
        _require_unique_details(self.environment, "evidence report environment")
        _require_unique_details(self.replay_observations, "new replay observations")
        if not self.reproduce:
            raise ReportValidationError("reproduction steps must not be empty")
        labels = tuple(item.label for item in self.reproduce)
        if len(labels) != len(set(labels)):
            raise ReportValidationError("reproduction labels must be unique")
        if self.evidence_kind is EvidenceKind.GENERATED and self.finding_evidence:
            raise ReportValidationError("generated evidence cannot contain scan anchors")
        if self.evidence_kind is EvidenceKind.SCAN and not self.finding_evidence:
            raise ReportValidationError("scan evidence must contain anchored Findings")
        anchors = tuple(item.anchor for item in self.finding_evidence)
        if len(anchors) != len(set(anchors)):
            raise ReportValidationError("finding evidence anchors must be unique")


def failure_headers(view: RunReportView) -> tuple[str, str, str, str]:
    if view.evidence_kind is EvidenceKind.SCAN:
        return "Reader(s)", "Failure", "File / location", "Reproduce"
    source = "Example table / location" if view.command == "fuzz" else "Table / location"
    return "Writer → reader", "Failure", source, "Reproduce"


def failure_rows(view: RunReportView) -> tuple[FailureRowView, ...]:
    return tuple(_failure_row(view, finding) for finding in view.findings)


def _failure_row(view: RunReportView, finding: FindingView) -> FailureRowView:
    source = f"{finding.evidence_input} · {finding.exact_location}"
    if repetition := _repetition(view, finding):
        source += f"\n{repetition}"
    reproduce, reference = _reproduction_action(finding)
    return FailureRowView(
        finding.participants,
        f"{finding.stage} · {finding.outcome_kind}\n{finding.summary}",
        source,
        reproduce,
        reference,
    )


def _repetition(view: RunReportView, finding: FindingView) -> str | None:
    seen, sources = finding.occurrence_count, finding.distinct_input_count
    if seen == 1:
        return None
    noun = (
        "file"
        if view.evidence_kind is EvidenceKind.SCAN
        else "generated table"
        if view.command == "fuzz"
        else "supplied table"
    )
    if seen == sources:
        return f"Seen on {_count(sources, noun)}"
    if sources == 1:
        return f"Seen {seen} times on this {noun}"
    return f"Seen {seen} times across {_count(sources, noun)}"


def _reproduction_action(finding: FindingView) -> tuple[str, ArtifactRef | None]:
    if not finding.saved_replay_target_count:
        return "not saved", None
    states = tuple(
        item for item in finding.replay_state_counts if item.state is not ReplayState.NOT_RUN
    )
    if not states:
        return "open", finding.evidence_refs[0]
    status = ", ".join(
        item.state.display_label
        if len(states) == 1 and item.count == finding.saved_replay_target_count
        else f"{item.count} {item.state.display_label.lower()}"
        for item in states
    )
    return f"open · {status}", finding.evidence_refs[0]


def _count(value: int, singular: str) -> str:
    return f"{value} {singular if value == 1 else singular + 's'}"


def _require_text(value: str, label: str) -> None:
    if not value.strip():
        raise ReportValidationError(f"{label} must not be empty")


def _require_bounded(value: str, label: str, limit: int) -> None:
    _require_text(value, label)
    if len(value) > limit:
        raise ReportValidationError(f"{label} exceeds its display bound")


def _validate_run_counts(view: RunReportView) -> None:
    counts = (
        view.evaluated_input_count,
        view.executed_check_count,
        view.affected_input_count,
        view.saved_evidence_count,
        view.evidence_bundle_count,
        view.unevaluated_input_count,
    )
    if any(isinstance(value, bool) or value < 0 for value in counts):
        raise ReportValidationError("run report counts must not be negative")
    if view.affected_input_count > view.evaluated_input_count:
        raise ReportValidationError("affected input count exceeds evaluated input count")
    if view.executed_check_count < view.evaluated_input_count:
        raise ReportValidationError("executed check count is smaller than evaluated input count")


def _validate_provider_roles(view: RunReportView) -> None:
    for values, label in ((view.writers, "writers"), (view.readers, "readers")):
        if any(not value for value in values) or values != tuple(sorted(set(values))):
            raise ReportValidationError(f"report {label} must be canonical and unique")
    if not view.readers:
        raise ReportValidationError("report readers must not be empty")
    if view.evidence_kind is EvidenceKind.GENERATED and not view.writers:
        raise ReportValidationError("generated reporting requires writers")
    if view.evidence_kind is EvidenceKind.SCAN and view.writers:
        raise ReportValidationError("scan reporting cannot declare writers")


def _validate_run_findings(view: RunReportView) -> None:
    labels = tuple(finding.label for finding in view.findings)
    expected = tuple(f"F{index}" for index in range(1, len(labels) + 1))
    if labels != expected:
        raise ReportValidationError("Finding labels must be sequential and ordered")
    if view.occurrence_count == 0:
        if view.affected_input_count != 0 or view.saved_evidence_count != 0:
            raise ReportValidationError("clean report counts are inconsistent")
    elif not 1 <= view.affected_input_count <= view.occurrence_count:
        raise ReportValidationError("affected input count is inconsistent")
    if view.saved_evidence_count > view.finding_count:
        raise ReportValidationError("saved evidence count exceeds Finding count")


def _validate_run_evidence(view: RunReportView) -> None:
    if view.finding_count == 0 and view.evidence_bundle_count != 0:
        raise ReportValidationError("a clean report cannot contain evidence bundles")
    if (view.finding_count == 0) != (view.machine_record is None):
        raise ReportValidationError("machine-record presence conflicts with report evidence")
    if view.evidence_kind is EvidenceKind.GENERATED:
        if view.evidence_bundle_count != view.saved_evidence_count:
            raise ReportValidationError("generated saved evidence and bundle counts differ")
        if view.unevaluated_input_count != 0:
            raise ReportValidationError("generated reports cannot claim unevaluated Inputs")
    elif view.saved_evidence_count != view.finding_count:
        raise ReportValidationError("every observed scan Finding must have saved evidence")
    if view.finding_count and view.evidence_bundle_count < 1:
        raise ReportValidationError("a non-clean report requires an evidence bundle")


def _require_unique_details(values: tuple[DetailView, ...], label: str) -> None:
    names = tuple(item.label for item in values)
    if len(names) != len(set(names)):
        raise ReportValidationError(f"{label} must have unique labels")


def _unique_artifact_targets(values: tuple[ArtifactRef, ...]) -> bool:
    targets = tuple((item.relative_path, item.anchor) for item in values)
    return len(targets) == len(set(targets))


def _require_replay_counts(values: tuple[ReplayStateCount, ...]) -> None:
    if not values:
        raise ReportValidationError("replay-state counts must not be empty")
    states = tuple(item.state for item in values)
    if len(states) != len(set(states)):
        raise ReportValidationError("replay states must be unique")
    if states != tuple(sorted(states, key=_REPLAY_ORDER.__getitem__)):
        raise ReportValidationError("replay states must be canonically ordered")


__all__ = [
    "FULL_INLINE_MAX_CELL_CHARS",
    "FULL_INLINE_MAX_COLUMNS",
    "FULL_INLINE_MAX_ROWS",
    "FULL_INLINE_MAX_UTF8_BYTES",
    "MAX_LOCATION_CHARS",
    "MAX_SUMMARY_CHARS",
    "PREVIEW_CELL_CHARS",
    "PREVIEW_COLUMNS",
    "PREVIEW_ROWS",
    "ArtifactRef",
    "DetailView",
    "EvidenceKind",
    "EvidenceReportView",
    "FailureRowView",
    "FindingEvidenceView",
    "FindingView",
    "InputView",
    "ReplayState",
    "ReplayStateCount",
    "ReportValidationError",
    "ReproductionStep",
    "RunReportView",
    "TableView",
    "bounded_text",
    "environment_details",
    "failure_headers",
    "failure_rows",
]
