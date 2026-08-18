from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from ..case import type_label
from ..evidence import EngineVersion, ReplayClassification
from ..generation.evidence import (
    CHECK_COMPLETE,
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    SAVED_EVIDENCE_LIMIT_REACHED,
    STRATEGY_EXHAUSTED,
    DiscoveryEvidence,
)
from ..generation.search.identity import FindingKey, finding_key
from ..model import Case
from ..reporting import (
    MAX_LOCATION_CHARS,
    MAX_SUMMARY_CHARS,
    ArtifactRef,
    DetailView,
    EvidenceKind,
    FindingView,
    ReplayState,
    ReplayStateCount,
    ReportValidationError,
    RunReportView,
    bounded_text,
    environment_details,
)
from ..verdicts import CellResult, FailureFingerprint
from .bundle import ValidatedRun
from .formats import v2
from .source import RunV2Source


@dataclass(frozen=True, slots=True)
class _SavedRepresentative:
    finding_id: str
    case: Case
    fingerprint: FailureFingerprint
    result: CellResult


@dataclass(frozen=True, slots=True)
class _ManifestRepresentative:
    case: Case
    fingerprint: FailureFingerprint
    result: CellResult


def build_run_report_view(
    validated: ValidatedRun,
    replay: Mapping[str, ReplayClassification] | None = None,
    *,
    command_line: str | None = None,
) -> RunReportView:
    run = validated.run
    if not isinstance(run, v2.RunRecord):
        raise ReportValidationError("generated reporting requires a validated run.v2 bundle")
    occurrences = _occurrences_by_key(run)
    saved = _saved_by_key(validated)
    manifest_only = _manifest_only_by_key(run)
    saved_ids = {item.finding_id for item in saved.values()}
    if replay is not None and set(replay) != saved_ids:
        raise ReportValidationError("generated replay overlay does not match all saved targets")
    keys = tuple(sorted(occurrences))
    if set(keys) != set(saved) | set(manifest_only):
        raise ReportValidationError("generated report representatives do not partition evidence")
    findings = tuple(
        _finding_view(
            index,
            key,
            occurrences[key],
            saved.get(key),
            manifest_only.get(key),
            replay,
        )
        for index, key in enumerate(keys, start=1)
    )
    # Only a DISCOVERY occurrence names an input that was evaluated. A MINIMIZATION occurrence
    # names the reduced Case a sibling failure was first seen in, which reduction derived rather
    # than the caller supplying or the generator producing — counting it made a `check` run, whose
    # evaluated input is one Case, claim two affected inputs and fail its own count invariant.
    affected_inputs = {
        item.case_id
        for values in occurrences.values()
        for item in values
        if item.origin == DISCOVERY_OVERFLOW
    }
    return RunReportView(
        command=run.command,
        evidence_kind=EvidenceKind.GENERATED,
        summary=_run_summary(
            run.command,
            run.evaluated_inputs,
            run.executed_checks,
            len(findings),
            sum(len(items) for items in occurrences.values()),
            len(saved),
            run.discovery.stop_reason,
        ),
        writers=_provider_labels(run.writers),
        readers=_provider_labels(run.readers),
        evaluated_input_count=run.evaluated_inputs,
        executed_check_count=run.executed_checks,
        affected_input_count=len(affected_inputs),
        findings=findings,
        saved_evidence_count=len(saved),
        evidence_bundle_count=len(validated.children),
        unevaluated_input_count=0,
        stop=_stop_label(run.discovery.stop_reason),
        bounds=_bounds(run),
        environment=_environment(run),
        machine_record=ArtifactRef("run.json", "run.json"),
        command_line=command_line,
    )


def build_clean_run_report_view(
    source: RunV2Source,
    *,
    command_line: str | None = None,
) -> RunReportView:
    if source.findings or source.overflow or source.occurrences:
        raise ReportValidationError("clean generated reporting requires empty evidence")
    return RunReportView(
        command=source.command,
        evidence_kind=EvidenceKind.GENERATED,
        summary=_run_summary(
            source.command,
            source.evaluated_inputs,
            source.executed_checks,
            0,
            0,
            0,
            source.discovery.stop_reason,
        ),
        writers=_provider_labels(source.writers),
        readers=_provider_labels(source.readers),
        evaluated_input_count=source.evaluated_inputs,
        executed_check_count=source.executed_checks,
        affected_input_count=0,
        findings=(),
        saved_evidence_count=0,
        evidence_bundle_count=0,
        unevaluated_input_count=0,
        stop=_stop_label(source.discovery.stop_reason),
        bounds=_discovery_bounds(source.command, source.discovery),
        environment=environment_details(source.environment),
        machine_record=None,
        command_line=command_line,
    )


def _occurrences_by_key(
    run: v2.RunRecord,
) -> dict[FindingKey, tuple[v2.OccurrenceRecord, ...]]:
    grouped: defaultdict[FindingKey, list[v2.OccurrenceRecord]] = defaultdict(list)
    for occurrence in run.occurrences:
        grouped[occurrence.key].append(occurrence)
    return {
        key: tuple(sorted(values, key=lambda item: item.occurrence_id))
        for key, values in grouped.items()
    }


def _saved_by_key(validated: ValidatedRun) -> dict[FindingKey, _SavedRepresentative]:
    result: dict[FindingKey, _SavedRepresentative] = {}
    for index, child in zip(validated.run.findings, validated.children, strict=True):
        key = finding_key(index.fingerprint)
        if key in result:
            raise ReportValidationError("generated saved Finding keys are not unique")
        result[key] = _SavedRepresentative(
            index.finding_id,
            child.case,
            index.fingerprint,
            child.finding.result,
        )
    return result


def _manifest_only_by_key(run: v2.RunRecord) -> dict[FindingKey, _ManifestRepresentative]:
    result: dict[FindingKey, _ManifestRepresentative] = {}
    for item in run.manifest_only_evidence:
        key = finding_key(item.fingerprint)
        if key in result:
            raise ReportValidationError("generated manifest-only Finding keys are not unique")
        result[key] = _ManifestRepresentative(
            item.case,
            item.fingerprint,
            item.result,
        )
    return result


def _finding_view(
    index: int,
    key: FindingKey,
    occurrences: tuple[v2.OccurrenceRecord, ...],
    saved: _SavedRepresentative | None,
    manifest_only: _ManifestRepresentative | None,
    replay: Mapping[str, ReplayClassification] | None,
) -> FindingView:
    representative = saved if saved is not None else manifest_only
    if representative is None or finding_key(representative.fingerprint) != key:
        raise ReportValidationError("generated Finding representative conflicts with its key")
    result = representative.result
    if result.fingerprint != representative.fingerprint:
        raise ReportValidationError("generated Finding result conflicts with its fingerprint")
    evidence, states = _evidence(saved, replay)
    return FindingView(
        label=f"F{index}",
        participants=bounded_text(
            _participants(representative.fingerprint),
            MAX_SUMMARY_CHARS,
        ),
        stage=result.operation,
        outcome_kind=bounded_text(
            (
                result.verdict.value
                if result.diagnostic_kind == result.verdict.value
                else f"{result.verdict.value} · {result.diagnostic_kind}"
            ),
            MAX_SUMMARY_CHARS,
        ),
        summary=bounded_text(result.detail.strip() or result.diagnostic_kind, MAX_SUMMARY_CHARS),
        evidence_input=_input_summary(representative.case),
        exact_location=bounded_text(result.schema_path, MAX_LOCATION_CHARS),
        occurrence_count=len(occurrences),
        distinct_input_count=len({item.case_id for item in occurrences}),
        saved_replay_target_count=0 if saved is None else 1,
        evidence_refs=evidence,
        replay_state_counts=states,
    )


def _evidence(
    saved: _SavedRepresentative | None,
    replay: Mapping[str, ReplayClassification] | None,
) -> tuple[tuple[ArtifactRef, ...], tuple[ReplayStateCount, ...]]:
    if saved is None:
        return (
            (ArtifactRef("run.json", "run.json"),),
            (),
        )
    state = ReplayState.NOT_RUN
    if replay is not None and saved.finding_id in replay:
        state = ReplayState(replay[saved.finding_id].value)
    return (
        (
            ArtifactRef(
                "saved report",
                f"findings/{saved.finding_id}/REPORT.md",
            ),
        ),
        (ReplayStateCount(state, 1),),
    )


def _participants(fingerprint: FailureFingerprint) -> str:
    writer = fingerprint.writer
    if fingerprint.writer_profile is not None:
        writer += f" [{fingerprint.writer_profile.name}]"
    return f"{writer} (write)" if fingerprint.reader == "*" else f"{writer} → {fingerprint.reader}"


def _bounds(run: v2.RunRecord) -> tuple[DetailView, ...]:
    return _discovery_bounds(run.command, run.discovery)


def _discovery_bounds(
    command: str,
    discovery: DiscoveryEvidence,
) -> tuple[DetailView, ...]:
    if command == "check":
        return ()
    return (
        DetailView("Examples", str(discovery.examples)),
        DetailView("Seed", str(discovery.seed)),
        DetailView("Reproducer limit", str(discovery.max_saved)),
    )


def _environment(run: v2.RunRecord) -> tuple[DetailView, ...]:
    return environment_details(run.environment)


def _provider_labels(providers: tuple[EngineVersion, ...]) -> tuple[str, ...]:
    return tuple(sorted(f"{item.name} {item.version}" for item in providers))


def _run_summary(
    command: str,
    evaluated: int,
    executed: int,
    failures: int,
    failed_paths: int,
    saved: int,
    stop_reason: str,
) -> str:
    if command == "check":
        if not failures:
            return f"The supplied table passed all {_count(executed, 'engine path')}."
        base = f"{failed_paths} of {executed} engine paths failed on the supplied table."
        return f"{base} {_saved_reproducers(failures, saved)}"
    if not failures:
        base = f"Parquity tested {_count(evaluated, 'generated table')} and found no failures."
        return _with_exhaustion_note(base, stop_reason)
    base = (
        f"Parquity tested {_count(evaluated, 'generated table')} and found "
        f"{_count(failures, 'distinct failure')}."
    )
    remaining = failures - saved
    if remaining and stop_reason == SAVED_EVIDENCE_LIMIT_REACHED:
        return (
            f"{base} It stopped after saving {_count(saved, 'reproducer')}; "
            f"{_remaining(remaining)} in run.json."
        )
    return _with_exhaustion_note(f"{base} {_saved_reproducers(failures, saved)}", stop_reason)


def _with_exhaustion_note(summary: str, stop_reason: str) -> str:
    if stop_reason == STRATEGY_EXHAUSTED:
        return f"{summary} Generation stopped because the schema produced no more distinct tables."
    return summary


def _saved_reproducers(failures: int, saved: int) -> str:
    if saved == failures:
        return "A reproducer was saved for each."
    remaining = failures - saved
    return (
        f"{_count(saved, 'reproducer').capitalize()} "
        f"{'was' if saved == 1 else 'were'} saved; {_remaining(remaining)} in run.json."
    )


def _remaining(value: int) -> str:
    return f"the other {'remains' if value == 1 else f'{value} remain'}"


def _count(value: int, singular: str) -> str:
    return f"{value} {singular if value == 1 else singular + 's'}"


def _input_summary(case: Case) -> str:
    schema = "; ".join(
        f"{type_label(field.type_spec)}{'?' if field.nullable else ''}" for field in case.fields
    )
    rows = f"{len(case.rows)} {'row' if len(case.rows) == 1 else 'rows'}"
    columns = f"{len(case.fields)} {'column' if len(case.fields) == 1 else 'columns'}"
    return bounded_text(f"{rows} · {columns} · {schema}", MAX_SUMMARY_CHARS)


def _stop_label(value: str) -> str:
    labels = {
        CHECK_COMPLETE: "Supplied Input evaluated",
        EXAMPLE_BOUND_REACHED: "Example bound reached",
        STRATEGY_EXHAUSTED: "Input strategy exhausted",
        SAVED_EVIDENCE_LIMIT_REACHED: "Saved-evidence limit reached",
    }
    try:
        return labels[value]
    except KeyError as error:
        raise ReportValidationError("generated stop reason is not recognized") from error


__all__ = ["build_clean_run_report_view", "build_run_report_view"]
