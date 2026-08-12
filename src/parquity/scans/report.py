from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ..evidence import EngineVersion, EnvironmentEvidence, ReplayClassification
from ..evidence import json_codec as codec
from ..evidence.normalization import detail_sha256_v1
from ..reporting import (
    MAX_LOCATION_CHARS,
    MAX_SUMMARY_CHARS,
    ArtifactRef,
    DetailView,
    EvidenceKind,
    EvidenceReportView,
    FindingEvidenceView,
    FindingView,
    InputView,
    ReplayState,
    ReplayStateCount,
    ReportValidationError,
    RunReportView,
    TableView,
    bounded_text,
    environment_details,
)
from . import records, summary, symptoms
from .differences import ScanDifference
from .scripts import reproduction_steps

if TYPE_CHECKING:
    from .bundle import ValidatedScanFinding, ValidatedScanRun
    from .workflow import ScanExecution


@dataclass(frozen=True, slots=True)
class _OccurrenceMember:
    reference: symptoms.ScanOccurrenceRef
    source_path: str
    record: records.ScanFindingRecord
    occurrence: symptoms.ScanSymptom


@dataclass(frozen=True, slots=True)
class _FindingGroup:
    key: symptoms.ScanFindingKey
    members: tuple[_OccurrenceMember, ...]


class _ReplayResult(Protocol):
    @property
    def finding_id(self) -> str: ...

    @property
    def occurrence_results(self) -> tuple[Mapping[str, object], ...]: ...

    @property
    def new_observations(self) -> tuple[Mapping[str, object], ...]: ...


@dataclass(frozen=True, slots=True)
class ScanReportOverlay:
    states: tuple[tuple[symptoms.ScanOccurrenceRef, ReplayClassification], ...]
    new_observations: tuple[DetailView, ...]

    def __post_init__(self) -> None:
        references = tuple(item[0] for item in self.states)
        if references != tuple(sorted(references)) or len(references) != len(set(references)):
            raise ReportValidationError("scan replay overlay targets must be unique and ordered")


def build_replay_overlay(results: Iterable[_ReplayResult]) -> ScanReportOverlay:
    states: list[tuple[symptoms.ScanOccurrenceRef, ReplayClassification]] = []
    observations: list[DetailView] = []
    for result in results:
        for item in result.occurrence_results:
            reference = symptoms.ScanOccurrenceRef(
                result.finding_id,
                records.text(item, "occurrence_id"),
            )
            try:
                state = ReplayClassification(records.text(item, "classification"))
            except ValueError as error:
                raise ReportValidationError("scan replay classification is invalid") from error
            states.append((reference, state))
        observations.extend(
            _new_replay_observation(result.finding_id, item) for item in result.new_observations
        )
    return ScanReportOverlay(
        tuple(sorted(states, key=lambda item: item[0])),
        tuple(sorted(observations, key=lambda item: item.label)),
    )


def build_run_report_view(
    validated: ValidatedScanRun,
    replay: ScanReportOverlay | None = None,
    *,
    command_line: str | None = None,
) -> RunReportView:
    groups, references = _partition(validated)
    states = None if replay is None else dict(replay.states)
    if states is not None and frozenset(states) != references:
        raise ReportValidationError("complete scan replay must classify every occurrence")
    ordered = tuple(sorted(groups, key=_finding_order))
    findings = tuple(
        _finding_view(index, group, states) for index, group in enumerate(ordered, start=1)
    )
    data = validated.record.data
    discovery = codec.mapping(data["discovery"], "discovery")
    files = records.mappings(discovery["files"], "files")
    overflow = _overflow(data)
    engines = records.engine_versions(data["engines"])
    evaluated = len(files) - len(overflow)
    affected = {member.reference.source_bundle_id for group in groups for member in group.members}
    return RunReportView(
        command="scan",
        evidence_kind=EvidenceKind.SCAN,
        summary=summary.run_summary(
            tuple(child.record for child in validated.children),
            evaluated,
            len(findings),
            len(overflow),
        ),
        writers=(),
        readers=_provider_labels(engines),
        evaluated_input_count=evaluated,
        executed_check_count=evaluated * len(engines),
        affected_input_count=len(affected),
        findings=findings,
        saved_evidence_count=len(findings),
        evidence_bundle_count=len(validated.children),
        unevaluated_input_count=len(overflow),
        stop=_stop(data),
        bounds=_bounds(data, discovery),
        environment=_scan_environment(validated.record),
        machine_record=ArtifactRef("scan.json", "scan.json"),
        replay_observations=() if replay is None else replay.new_observations,
        command_line=command_line,
    )


def build_clean_run_report_view(
    execution: ScanExecution,
    *,
    timeout_seconds: int,
    max_saved: int,
    command_line: str | None = None,
) -> RunReportView:
    discovery = execution.discovery
    engines = execution.environment.providers
    if execution.run is not None or execution.evaluated_files != len(discovery.files):
        raise ReportValidationError("clean scan evidence is incomplete or contains a run")
    return RunReportView(
        command="scan",
        evidence_kind=EvidenceKind.SCAN,
        summary=summary.clean_summary(execution.evaluated_files, len(engines)),
        writers=(),
        readers=_provider_labels(engines),
        evaluated_input_count=execution.evaluated_files,
        executed_check_count=execution.evaluated_files * len(engines),
        affected_input_count=0,
        findings=(),
        saved_evidence_count=0,
        evidence_bundle_count=0,
        unevaluated_input_count=0,
        stop="All discovered Inputs evaluated",
        bounds=(
            DetailView("Source", discovery.input_kind),
            DetailView("Reproducer limit", str(max_saved)),
            DetailView("Timeout per reader", f"{timeout_seconds} seconds"),
            DetailView("Symlinks skipped", str(discovery.skipped_symlinks)),
            DetailView("Filesystem entries visited", str(discovery.visited_entries)),
        ),
        environment=_environment_details(execution.environment),
        machine_record=None,
        command_line=command_line,
    )


def build_evidence_report_view(
    record: records.ScanFindingRecord,
    replay: ScanReportOverlay | None = None,
) -> EvidenceReportView:
    occurrences = tuple(
        sorted(
            symptoms.extract(record, detail_sha256_v1),
            key=lambda item: _display_order(symptoms.finding_key(item), item.occurrence_id),
        )
    )
    if not occurrences:
        raise ReportValidationError("scan source evidence has no Occurrences")
    replay_states = None if replay is None else dict(replay.states)
    states = _standalone_states(record, occurrences, replay_states)
    return EvidenceReportView(
        evidence_kind=EvidenceKind.SCAN,
        title="Parquity scan evidence",
        summary=summary.file_summary(record, saved=False),
        facts=_report_facts(record),
        reproduce=reproduction_steps(record),
        input=InputView(
            identity=record.input_sha256,
            facts=(
                DetailView("Path", record.source_path),
                DetailView("Bytes", str(record.input_bytes)),
            ),
            artifacts=(ArtifactRef("retained Parquet bytes", "input.parquet"),),
        ),
        finding_evidence=tuple(
            _occurrence_evidence(record, occurrence, states[occurrence.occurrence_id])
            for occurrence in occurrences
        ),
        outcomes=_outcomes(record),
        environment=(
            *_scan_environment(record),
            DetailView(
                "Readers",
                ", ".join(sorted(f"{item.name} {item.version}" for item in record.engines)),
            ),
            DetailView("Timeout per reader", f"{record.timeout_seconds} seconds"),
        ),
        machine_record=ArtifactRef("finding.json", "finding.json"),
        replay_observations=() if replay is None else replay.new_observations,
    )


def build_standalone_report_view(
    validated: ValidatedScanFinding,
    replay: ScanReportOverlay | None = None,
) -> EvidenceReportView:
    return build_evidence_report_view(validated.record, replay)


def _partition(
    validated: ValidatedScanRun,
) -> tuple[tuple[_FindingGroup, ...], frozenset[symptoms.ScanOccurrenceRef]]:
    grouped: defaultdict[symptoms.ScanFindingKey, list[_OccurrenceMember]] = defaultdict(list)
    all_references: list[symptoms.ScanOccurrenceRef] = []
    for child in validated.children:
        source_bundle_id = child.record.finding_id
        for occurrence in symptoms.extract(child.record, detail_sha256_v1):
            reference = symptoms.ScanOccurrenceRef(source_bundle_id, occurrence.occurrence_id)
            all_references.append(reference)
            grouped[symptoms.finding_key(occurrence)].append(
                _OccurrenceMember(
                    reference,
                    child.record.source_path,
                    child.record,
                    occurrence,
                )
            )
    expected = frozenset(all_references)
    if len(expected) != len(all_references):
        raise ReportValidationError("scan occurrence references are not unique")
    groups = tuple(
        _FindingGroup(key, tuple(sorted(members, key=lambda item: item.reference)))
        for key, members in grouped.items()
    )
    _validate_partition(groups, expected)
    return groups, expected


def _validate_partition(
    groups: tuple[_FindingGroup, ...],
    expected: frozenset[symptoms.ScanOccurrenceRef],
) -> None:
    observed: set[symptoms.ScanOccurrenceRef] = set()
    for group in groups:
        references = {member.reference for member in group.members}
        if not references:
            raise ReportValidationError("scan Finding group must not be empty")
        if observed & references:
            raise ReportValidationError("scan Finding groups overlap")
        if any(symptoms.finding_key(member.occurrence) != group.key for member in group.members):
            raise ReportValidationError("scan Finding group conflicts with its key")
        observed.update(references)
    if frozenset(observed) != expected:
        raise ReportValidationError("scan Finding groups do not conserve Occurrences")


def _finding_order(group: _FindingGroup) -> tuple[object, ...]:
    return _display_order(group.key, min(member.reference for member in group.members))


def _display_order(key: symptoms.ScanFindingKey, tie_breaker: object) -> tuple[object, ...]:
    return (
        _participant_groups(key),
        key.operation,
        key.signal,
        _outcome_kind(key),
        key.normalized_location or "",
        key.canonical_bytes(),
        tie_breaker,
    )


def _finding_view(
    index: int,
    group: _FindingGroup,
    replay: Mapping[symptoms.ScanOccurrenceRef, ReplayClassification] | None,
) -> FindingView:
    representative = group.members[0]
    occurrence = representative.occurrence
    exact_location = _exact_location(representative.record, occurrence)
    return FindingView(
        label=f"F{index}",
        participants=bounded_text(_participants(group.key), MAX_SUMMARY_CHARS),
        stage="read" if group.key.target_reader is not None else "compare",
        outcome_kind=bounded_text(_outcome_kind(group.key), MAX_SUMMARY_CHARS),
        summary=bounded_text(_summary(occurrence), MAX_SUMMARY_CHARS),
        evidence_input=bounded_text(representative.source_path, MAX_SUMMARY_CHARS),
        exact_location=bounded_text(exact_location, MAX_LOCATION_CHARS),
        occurrence_count=len(group.members),
        distinct_input_count=len({member.reference.source_bundle_id for member in group.members}),
        saved_replay_target_count=len(group.members),
        evidence_refs=tuple(
            ArtifactRef(
                bounded_text(member.source_path, MAX_SUMMARY_CHARS),
                f"findings/{member.reference.source_bundle_id}/REPORT.md",
                f"occurrence-{member.reference.occurrence_id}",
            )
            for member in group.members
        ),
        replay_state_counts=_replay_counts(group.members, replay),
    )


def _replay_counts(
    members: tuple[_OccurrenceMember, ...],
    replay: Mapping[symptoms.ScanOccurrenceRef, ReplayClassification] | None,
) -> tuple[ReplayStateCount, ...]:
    counts: Counter[ReplayState] = Counter()
    for member in members:
        state = ReplayState.NOT_RUN
        if replay is not None and member.reference in replay:
            state = ReplayState(replay[member.reference].value)
        counts[state] += 1
    return tuple(ReplayStateCount(state, counts[state]) for state in ReplayState if counts[state])


def _occurrence_evidence(
    record: records.ScanFindingRecord,
    occurrence: symptoms.ScanSymptom,
    replay_state: ReplayState,
) -> FindingEvidenceView:
    key = symptoms.finding_key(occurrence)
    facts = [
        DetailView("Location", _exact_location(record, occurrence)),
    ]
    if replay_state is not ReplayState.NOT_RUN:
        facts.append(DetailView("Last replay", replay_state.display_label))
    if key.target_reader is not None:
        evidence = key.evidence[0]
        if not isinstance(evidence, symptoms.ScanExecutionEvidence):
            raise ReportValidationError("scan reader failure evidence is malformed")
        facts.extend(
            (
                DetailView("Observation", "No table was returned"),
                DetailView("Diagnostic kind", evidence.diagnostic_kind),
                DetailView("Captured detail", occurrence.details[0] or "No detail was captured"),
            )
        )
        outcome = _reader_outcome(record, key.target_reader)
        if outcome.stderr:
            suffix = " [capture truncated]" if outcome.stderr_truncated else ""
            facts.append(DetailView("Captured stderr", outcome.stderr + suffix))
        if evidence.timeout_seconds is not None:
            facts.append(DetailView("Timeout", f"{evidence.timeout_seconds} seconds"))
        summary = f"{key.target_reader} · read · {_outcome_kind(key)}"
    else:
        for edge_index, (evidence, detail) in enumerate(
            zip(key.evidence, occurrence.details, strict=True), start=1
        ):
            if not isinstance(evidence, symptoms.ScanComparisonEdge):
                raise ReportValidationError("scan comparison evidence is malformed")
            suffix = f" {edge_index}" if len(key.evidence) > 1 else ""
            facts.extend(
                (
                    DetailView(
                        f"Comparison{suffix}",
                        f"{_group_label(evidence.groups[0])} / "
                        f"{_group_label(evidence.groups[1])} · {evidence.comparison_kind}",
                    ),
                    DetailView(
                        f"Captured detail{suffix}",
                        detail or "No detail was captured",
                    ),
                )
            )
        summary = f"{_participants(key)} · compare · {occurrence.signal}"
    return FindingEvidenceView(
        anchor=f"occurrence-{occurrence.occurrence_id}",
        summary=summary,
        facts=tuple(facts),
    )


def _standalone_states(
    record: records.ScanFindingRecord,
    occurrences: tuple[symptoms.ScanSymptom, ...],
    replay: Mapping[symptoms.ScanOccurrenceRef, ReplayClassification] | None,
) -> dict[str, ReplayState]:
    references = {
        symptoms.ScanOccurrenceRef(record.finding_id, occurrence.occurrence_id)
        for occurrence in occurrences
    }
    if replay is not None and not set(replay) <= references:
        raise ReportValidationError("standalone scan replay contains an unknown occurrence")
    result: dict[str, ReplayState] = {}
    for reference in sorted(references):
        state = ReplayState.NOT_RUN
        if replay is not None and reference in replay:
            state = ReplayState(replay[reference].value)
        result[reference.occurrence_id] = state
    return result


def _report_facts(record: records.ScanFindingRecord) -> tuple[DetailView, ...]:
    successful = tuple(
        outcome for outcome in record.outcomes if outcome.kind is records.ReaderOutcomeKind.SUCCESS
    )
    groups = {outcome.observation_group for outcome in successful}
    if len(groups) > 1:
        return (DetailView("Reference result", "None; readers are compared symmetrically"),)
    return ()


def _new_replay_observation(
    source_bundle_id: str,
    value: Mapping[str, object],
) -> DetailView:
    occurrence_id = records.text(value, "occurrence_id")
    signal = records.text(value, "signal")
    target = value.get("target_reader")
    location = value.get("normalized_location")
    context = (
        target if isinstance(target, str) else location if isinstance(location, str) else "root"
    )
    return DetailView(
        f"{source_bundle_id} / {occurrence_id}",
        bounded_text(f"{signal} · {context}", MAX_SUMMARY_CHARS),
    )


def _outcomes(record: records.ScanFindingRecord) -> TableView:
    return TableView(
        ("Reader", "Version", "Result", "Rows", "Columns", "Observation / diagnostic"),
        tuple(
            (
                outcome.engine,
                outcome.version,
                outcome.kind.value,
                str(outcome.row_count) if outcome.row_count is not None else "—",
                str(outcome.column_count) if outcome.column_count is not None else "—",
                (
                    f"group {outcome.observation_group}"
                    if outcome.kind is records.ReaderOutcomeKind.SUCCESS
                    else outcome.diagnostic_kind
                ),
            )
            for outcome in sorted(record.outcomes, key=lambda item: (item.engine, item.version))
        ),
    )


def _reader_outcome(
    record: records.ScanFindingRecord,
    reader: str,
) -> records.ReaderOutcomeRecord:
    matches = tuple(item for item in record.outcomes if item.engine == reader)
    if len(matches) != 1:
        raise ReportValidationError("scan reader occurrence has no unique outcome")
    return matches[0]


def _participants(key: symptoms.ScanFindingKey) -> str:
    if key.target_reader is not None:
        return key.target_reader
    return " ↔ ".join(_group_label(group) for group in _participant_groups(key))


def _participant_groups(key: symptoms.ScanFindingKey) -> tuple[tuple[str, ...], ...]:
    if key.target_reader is not None:
        return ((key.target_reader,),)
    groups: set[tuple[str, ...]] = set()
    for evidence in key.evidence:
        if not isinstance(evidence, symptoms.ScanComparisonEdge):
            raise ReportValidationError("scan comparison key is malformed")
        groups.update(evidence.groups)
    return tuple(sorted(groups))


def _group_label(group: tuple[str, ...]) -> str:
    return ", ".join(group)


def _outcome_kind(key: symptoms.ScanFindingKey) -> str:
    if key.target_reader is None:
        return key.signal
    evidence = key.evidence[0]
    if not isinstance(evidence, symptoms.ScanExecutionEvidence):
        raise ReportValidationError("scan execution key is malformed")
    return (
        key.signal
        if evidence.diagnostic_kind == key.signal
        else f"{key.signal} · {evidence.diagnostic_kind}"
    )


def _summary(occurrence: symptoms.ScanSymptom) -> str:
    details = " · ".join(value for value in occurrence.details if value.strip())
    return details or occurrence.signal


def _exact_location(record: records.ScanFindingRecord, occurrence: symptoms.ScanSymptom) -> str:
    if occurrence.normalized_location is None:
        return "whole file"
    locations: set[str] = set()
    for item in records.mappings(record.data["comparisons"], "comparisons"):
        difference = ScanDifference.from_persisted(
            records.text(item, "kind"), records.text(item, "path")
        )
        normalized = difference.normalized()
        if (
            normalized.kind.value == occurrence.signal
            and normalized.path == occurrence.normalized_location
        ):
            locations.add(difference.path)
    if not locations:
        raise ReportValidationError("scan occurrence location has no source evidence")
    return " / ".join(sorted(locations))


def _bounds(data: Mapping[str, object], discovery: Mapping[str, object]) -> tuple[DetailView, ...]:
    values = [
        DetailView(
            "Reproducer limit",
            str(records.saved_limit(data)),
        ),
        DetailView(
            "Timeout per reader",
            f"{codec.integer(data['timeout_seconds'], 'timeout')} seconds",
        ),
    ]
    skipped = codec.integer(discovery["skipped_symlinks"], "skipped symlinks")
    if skipped:
        values.append(DetailView("Symlinks skipped", str(skipped)))
    return tuple(values)


def _overflow(data: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        codec.string(item, "overflow path") for item in codec.sequence(data["overflow"], "overflow")
    )


def _stop(data: Mapping[str, object]) -> str:
    status = records.status_from_data(records.text(data, "status"), records.text(data, "format"))
    if status is records.ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED:
        return "Saved-evidence limit reached"
    return "All discovered Inputs evaluated"


def _provider_labels(engines: tuple[EngineVersion, ...]) -> tuple[str, ...]:
    return tuple(sorted(f"{item.name} {item.version}" for item in engines))


def _scan_environment(
    record: records.ScanRunRecord | records.ScanFindingRecord,
) -> tuple[DetailView, ...]:
    if record.environment is None:
        return (DetailView("Parquity", record.parquity_version),)
    return _environment_details(record.environment)


def _environment_details(environment: EnvironmentEvidence) -> tuple[DetailView, ...]:
    return tuple(item for item in environment_details(environment) if item.label != "Hypothesis")
