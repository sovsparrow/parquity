from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from ..engines import EngineSelection, EngineSelectionError
from ..evidence import EngineVersion
from ..findings.bundle import (
    BundlePublicationError,
    BundleValidationError,
    load_case,
    validate_bundle,
)
from ..findings.replay import ReplayOutcome, replay_validated_bundle
from ..findings.report import build_standalone_report_view
from ..generation import workflow
from ..generation.evidence import (
    EXAMPLE_BOUND_REACHED,
    STRATEGY_EXHAUSTED,
    DiscoveryEvidence,
    stop_reason_to_v1,
)
from ..generation.progress import ProgressCallback
from ..generation.schema import SchemaPlan
from ..generation.search.identity import finding_key
from ..profiles import WriterProfileError, WriterProfilePlan
from ..profiles.contracts import admit_writer_profile_plan
from ..profiles.selection import build_writer_profile_plan, parse_requested_profiles
from ..reporting import RunReportView
from ..runs.bundle import (
    RunBundleValidationError,
    RunPublicationError,
    ValidatedRun,
    ensure_destination_absent,
    validate_run,
)
from ..runs.formats import v2
from ..runs.replay import RunReplayOutcome, replay_validated_run
from ..runs.report import build_clean_run_report_view, build_run_report_view
from . import parser
from .output import configuration, emit, unavailable

SelectionResolver = Callable[
    [str | Sequence[str] | None, str | Sequence[str] | None], EngineSelection
]


def run_check(
    arguments: parser.CheckArguments,
    resolver: SelectionResolver,
    *,
    command_line: str,
) -> int:
    try:
        case = load_case(arguments.case_path, arguments.destination)
    except BundlePublicationError as error:
        return configuration("check", error.kind, error.detail)
    resolved = _selection(
        "check", arguments.writers, arguments.readers, arguments.writer_profiles, resolver
    )
    if isinstance(resolved, int):
        return resolved
    selection, plan = resolved
    try:
        result = workflow.capture_check(
            case,
            arguments.destination,
            selection,
            plan,
            report_command=command_line,
        )
    except (BundlePublicationError, RunPublicationError) as error:
        return configuration("check", error.kind, error.detail)
    additive = _plan_data(plan)
    run = result.published_run
    if run is None:
        emit(
            {
                "command": "check",
                "status": "NO_FINDING",
                "case_id": case.case_id,
                **_selection_data(selection),
                **additive,
            },
            build_clean_run_report_view(result.source, command_line=command_line),
        )
        return 0
    _emit_published("check", run, additive, command_line=command_line)
    return 1


def run_fuzz(
    arguments: parser.FuzzArguments,
    schema: SchemaPlan | None,
    resolver: SelectionResolver,
    progress: ProgressCallback | None = None,
    *,
    command_line: str,
) -> int:
    try:
        ensure_destination_absent(arguments.destination)
    except RunPublicationError as error:
        return configuration("fuzz", error.kind, error.detail)
    resolved = _selection(
        "fuzz", arguments.writers, arguments.readers, arguments.writer_profiles, resolver
    )
    if isinstance(resolved, int):
        return resolved
    selection, plan = resolved
    try:
        result = workflow.capture_fuzz(
            arguments.destination,
            examples=arguments.examples,
            seed=arguments.seed,
            max_saved=arguments.max_saved,
            selection=selection,
            schema=schema,
            writer_profiles=plan,
            progress=progress,
            report_command=command_line,
        )
    except (BundlePublicationError, RunPublicationError) as error:
        return configuration("fuzz", error.kind, error.detail)
    additive = _plan_data(plan)
    if schema is not None:
        additive.update(generation_profile="schema", schema_case_id=schema.schema_case_id)
    run = result.published_run
    if run is None:
        emit(
            {
                "command": "fuzz",
                "status": "NO_FINDING",
                "discovery_bound": arguments.examples,
                "seed": arguments.seed,
                "max_findings": arguments.max_saved,
                **_selection_data(selection),
                **additive,
            },
            build_clean_run_report_view(result.source, command_line=command_line),
        )
        return 0
    _emit_published("fuzz", run, additive, command_line=command_line)
    return 1


def run_replay(
    directory: Path,
    resolver: SelectionResolver,
    *,
    aggregate: bool,
) -> int:
    try:
        if aggregate:
            run = validate_run(directory)
            resolved = _recorded_selection(
                run.run.writers, run.run.readers, run.run.writer_profiles, resolver
            )
            if isinstance(resolved, int):
                return resolved
            selection, plan = resolved
            outcome = replay_validated_run(run, workflow.SelectedEvaluator(selection, plan))
            status = "REPRODUCED" if outcome.reproduced else "NOT_REPRODUCED"
            report = None
            if isinstance(run.run, v2.RunRecord):
                report = build_run_report_view(
                    run,
                    {item.finding.finding_id: item.classification for item in outcome.outcomes},
                )
            emit(
                {
                    "command": "replay",
                    "status": status,
                    **_run_replay_data(outcome),
                    "run_id": run.run.run_id,
                },
                report,
            )
            return 1 if outcome.reproduced else 0
        finding = validate_bundle(directory)
        resolved = _recorded_selection(
            finding.finding.writers,
            finding.finding.readers,
            finding.finding.writer_profiles,
            resolver,
        )
        if isinstance(resolved, int):
            return resolved
        selection, plan = resolved
        outcome = replay_validated_bundle(finding, workflow.SelectedEvaluator(selection, plan))
    except (BundleValidationError, RunBundleValidationError) as error:
        return configuration("replay", error.kind, error.detail)
    payload: dict[str, object] = {
        "command": "replay",
        "status": outcome.classification.value,
        "finding_id": outcome.finding.finding_id,
        "case_id": outcome.finding.case_id,
        "target": outcome.finding.replay_signature.to_data(),
        "version_evidence": [item.to_data() for item in outcome.version_evidence],
        "version_drift": [item.to_data() for item in outcome.version_drift],
        "dependency_evidence": [item.to_data() for item in outcome.dependency_evidence],
        "dependency_drift": [item.to_data() for item in outcome.dependency_drift],
        **_plan_data(outcome.finding.writer_profiles),
    }
    emit(payload, build_standalone_report_view(finding, outcome.classification))
    return 1 if outcome.reproduced else 0


def _run_replay_data(outcome: RunReplayOutcome) -> dict[str, object]:
    data: dict[str, object] = {
        "exact": outcome.exact_count,
        "related": outcome.related_count,
        "absent": outcome.absent_count,
        "findings": [_finding_replay_data(item) for item in outcome.outcomes],
    }
    if outcome.writer_profiles is not None:
        data["writer_profiles"] = outcome.writer_profiles.to_data()
    return data


def _finding_replay_data(outcome: ReplayOutcome) -> dict[str, object]:
    data: dict[str, object] = {
        "finding_id": outcome.finding.finding_id,
        "classification": outcome.classification.value,
        "version_evidence": [item.to_data() for item in outcome.version_evidence],
        "version_drift": [item.to_data() for item in outcome.version_drift],
        "dependency_evidence": [item.to_data() for item in outcome.dependency_evidence],
        "dependency_drift": [item.to_data() for item in outcome.dependency_drift],
    }
    profile = outcome.finding.fingerprint.writer_profile
    if profile is not None:
        data["writer_profile"] = profile.to_data()
    return data


def _selection(
    command: str,
    writers: str | Sequence[str] | None,
    readers: str | Sequence[str] | None,
    writer_profiles: str | Sequence[str] | None,
    resolver: SelectionResolver,
) -> tuple[EngineSelection, WriterProfilePlan | None] | int:
    try:
        return _resolve_selection(writers, readers, writer_profiles, resolver)
    except WriterProfileError as error:
        return configuration(command, error.kind, error.detail)
    except EngineSelectionError as error:
        if error.unavailable:
            return unavailable(command, error.unavailable)
        return configuration(command, error.kind, error.detail)


def _recorded_selection(
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    recorded_plan: WriterProfilePlan | None,
    resolver: SelectionResolver,
) -> tuple[EngineSelection, WriterProfilePlan | None] | int:
    writer_names = tuple(item.name for item in writers)
    reader_names = tuple(item.name for item in readers)
    requested = None if recorded_plan is None else recorded_plan.requested_profiles
    try:
        selection, current_plan = _resolve_selection(
            writer_names, reader_names, requested, resolver
        )
    except WriterProfileError as error:
        if recorded_plan is not None:
            return configuration(
                "replay",
                "WRITER_PROFILE_NOT_EVALUABLE",
                "recorded writer profile plan cannot be evaluated",
            )
        return configuration("replay", error.kind, error.detail)
    except EngineSelectionError as error:
        if recorded_plan is not None:
            return configuration(
                "replay",
                "WRITER_PROFILE_NOT_EVALUABLE",
                "recorded writer profile plan cannot be evaluated",
            )
        if error.unavailable:
            return unavailable("replay", error.unavailable)
        return configuration("replay", error.kind, error.detail)
    order_changed = selection.writer_names != writer_names or selection.reader_names != reader_names
    if order_changed:
        return configuration("replay", "INVALID_BUNDLE", "recorded engine order is not canonical")
    if recorded_plan is not None and (
        current_plan is None or not recorded_plan.replay_equivalent(current_plan)
    ):
        return configuration(
            "replay",
            "WRITER_PROFILE_NOT_EVALUABLE",
            "recorded writer profile plan cannot be evaluated",
        )
    return selection, current_plan


def _resolve_selection(
    writers: str | Sequence[str] | None,
    readers: str | Sequence[str] | None,
    writer_profiles: str | Sequence[str] | None,
    resolver: SelectionResolver,
) -> tuple[EngineSelection, WriterProfilePlan | None]:
    requested = parse_requested_profiles(writer_profiles)
    selection = resolver(writers, readers)
    declared = build_writer_profile_plan(requested, selection.writers)
    if declared is None:
        return selection, None
    return selection, admit_writer_profile_plan(declared, selection.writers)


def _emit_published(
    command: str,
    validated: ValidatedRun,
    additive: dict[str, object],
    *,
    command_line: str,
) -> None:
    run = validated.run
    report: RunReportView | None = None
    if isinstance(run, v2.RunRecord):
        report = build_run_report_view(validated, command_line=command_line)
    emit(
        {
            "command": command,
            "status": "RUN_PUBLISHED",
            "run_status": stop_reason_to_v1(run.status),
            "run_id": run.run_id,
            "finding_count": len(run.findings),
            "overflow_count": len(run.overflow),
            "discovery": _cli_discovery_data(run.discovery),
            "findings": _finding_summaries(validated),
            "output": str(validated.directory),
            **additive,
        },
        report,
    )


def _cli_discovery_data(discovery: DiscoveryEvidence) -> dict[str, object]:
    if discovery.stop_reason == STRATEGY_EXHAUSTED:
        discovery = replace(discovery, stop_reason=EXAMPLE_BOUND_REACHED)
    return discovery.to_data()


def _finding_summaries(validated: ValidatedRun) -> list[dict[str, object]]:
    pairs = sorted(
        zip(validated.run.findings, validated.children, strict=True),
        key=lambda pair: finding_key(pair[0].fingerprint),
    )
    return [
        {
            "finding_id": item.finding_id,
            "case_id": item.case_id,
            **item.fingerprint.to_data(),
            "detail": child.finding.result.detail,
        }
        for item, child in pairs
    ]


def _plan_data(plan: WriterProfilePlan | None) -> dict[str, object]:
    return {} if plan is None else {"writer_profiles": plan.to_data()}


def _selection_data(selection: EngineSelection) -> dict[str, object]:
    return {"writers": list(selection.writer_names), "readers": list(selection.reader_names)}


__all__ = ["run_check", "run_fuzz", "run_replay"]
