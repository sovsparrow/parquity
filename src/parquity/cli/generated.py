from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from pathlib import Path

from ..engines import EngineSelection, EngineSelectionError
from ..findings.bundle import (
    BundlePublicationError,
    BundleValidationError,
    ensure_destination_absent,
    load_case,
    validate_bundle,
)
from ..findings.model import FindingRecord
from ..findings.replay import replay_validated_bundle
from ..generation import workflow
from ..generation.schema import SchemaPlan
from ..runs.bundle import (
    RunBundleValidationError,
    RunPublicationError,
    validate_run,
)
from ..runs.model import RunRecord
from ..runs.replay import replay_validated_run
from ..verdicts import EngineVersion
from ..writer_profile_contracts import admit_writer_profile_plan
from ..writer_profiles import (
    WriterProfileError,
    WriterProfilePlan,
    build_writer_profile_plan,
    parse_requested_profiles,
)
from . import parser
from .output import configuration, emit, unavailable

SelectionResolver = Callable[
    [str | Sequence[str] | None, str | Sequence[str] | None], EngineSelection
]


def run_check(arguments: parser.CheckArguments, resolver: SelectionResolver) -> int:
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
        run = workflow.execute_check(case, arguments.destination, selection, plan)
    except (BundlePublicationError, RunPublicationError) as error:
        return configuration("check", error.kind, error.detail)
    additive = _plan_data(plan)
    if run is None:
        emit(
            {
                "command": "check",
                "status": "NO_FINDING",
                "case_id": case.case_id,
                **selection.to_data(),
                **additive,
            }
        )
        return 0
    _emit_published("check", arguments.destination, run, additive)
    return 1


def run_fuzz(
    arguments: parser.FuzzArguments,
    schema: SchemaPlan | None,
    resolver: SelectionResolver,
) -> int:
    try:
        ensure_destination_absent(arguments.destination)
    except BundlePublicationError as error:
        return configuration("fuzz", error.kind, error.detail)
    resolved = _selection(
        "fuzz", arguments.writers, arguments.readers, arguments.writer_profiles, resolver
    )
    if isinstance(resolved, int):
        return resolved
    selection, plan = resolved
    try:
        run = workflow.execute_fuzz(
            arguments.destination,
            examples=arguments.examples,
            seed=arguments.seed,
            max_findings=arguments.max_findings,
            selection=selection,
            schema=schema,
            writer_profiles=plan,
        )
    except (BundlePublicationError, RunPublicationError) as error:
        return configuration("fuzz", error.kind, error.detail)
    additive = _plan_data(plan)
    if schema is not None:
        additive.update(generation_profile="schema", schema_case_id=schema.schema_case_id)
    if run is None:
        emit(
            {
                "command": "fuzz",
                "status": "NO_FINDING",
                "discovery_bound": arguments.examples,
                "seed": arguments.seed,
                "max_findings": arguments.max_findings,
                **selection.to_data(),
                **additive,
            }
        )
        return 0
    _emit_published("fuzz", arguments.destination, run, additive)
    return 1


def run_replay(directory: Path, resolver: SelectionResolver) -> int:
    try:
        if (directory / "run.json").is_file():
            run = validate_run(directory)
            resolved = _recorded_selection(
                run.run.writers, run.run.readers, run.run.writer_profiles, resolver
            )
            if isinstance(resolved, int):
                return resolved
            selection, plan = resolved
            outcome = replay_validated_run(run, workflow.SelectedEvaluator(selection, plan))
            status = "REPRODUCED" if outcome.reproduced else "NOT_REPRODUCED"
            emit(
                {
                    "command": "replay",
                    "status": status,
                    **outcome.to_data(),
                    "run_id": run.run.run_id,
                }
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
    emit(payload)
    return 1 if outcome.reproduced else 0


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
    destination: Path,
    run: object,
    additive: dict[str, object],
) -> None:
    if not isinstance(run, RunRecord):
        raise TypeError("published run evidence is malformed")
    emit(
        {
            "command": command,
            "status": "RUN_PUBLISHED",
            "run_status": run.status,
            "run_id": run.run_id,
            "finding_count": len(run.findings),
            "overflow_count": len(run.overflow),
            "discovery": run.discovery.to_data(),
            "findings": _finding_summaries(destination, run),
            "output": str(destination),
            **additive,
        }
    )


def _finding_summaries(destination: Path, run: RunRecord) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for item in run.findings:
        payload = (destination / item.manifest_path).read_bytes()
        if hashlib.sha256(payload).hexdigest() != item.sha256:
            raise TypeError("published finding evidence changed before presentation")
        finding = FindingRecord.from_json(payload)
        if finding.finding_id != item.finding_id:
            raise TypeError("published finding evidence conflicts with its run index")
        summaries.append(
            {
                "finding_id": item.finding_id,
                "case_id": item.case_id,
                **item.fingerprint.to_data(),
                "detail": finding.result.detail,
            }
        )
    return summaries


def _plan_data(plan: WriterProfilePlan | None) -> dict[str, object]:
    return {} if plan is None else {"writer_profiles": plan.to_data()}


__all__ = ["run_check", "run_fuzz", "run_replay"]
