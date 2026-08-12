from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..engines import ENGINE_DESCRIPTORS, EngineSelection
from ..evidence import EngineVersion, capture_environment
from ..matrix import run_matrix
from ..model import Case
from ..profiles import WriterProfilePlan
from ..runs.bundle import ValidatedRun, ensure_destination_absent, publish_run
from ..runs.progress import (
    RunPublicationPhase,
    RunPublicationProgress,
)
from ..runs.source import RunV2Source
from ..verdicts import MatrixRun
from .evidence import (
    CHECK_COMPLETE,
    DiscoveryEvidence,
    GenerationEvidence,
)
from .progress import FuzzPhase, FuzzProgress, ProgressCallback, resilient_progress
from .schema import SchemaPlan
from .search.campaign import find_case_evidence, search_cases
from .search.evaluation import EvaluationContext
from .search.records import (
    GeneratedOccurrence,
    OverflowObservation,
    SearchCampaign,
    SearchFinding,
)
from .strategies import bounded_cases


@dataclass(frozen=True, slots=True)
class SelectedEvaluator:
    selection: EngineSelection
    writer_profiles: WriterProfilePlan | None = None

    @property
    def context(self) -> EvaluationContext:
        return EvaluationContext(
            tuple(item.identity for item in self.selection.writers),
            tuple(item.identity for item in self.selection.readers),
            self.writer_profiles,
        )

    def __call__(self, case: Case, directory: Path, /) -> MatrixRun:
        return run_matrix(
            case,
            directory,
            self.selection.writers,
            self.selection.readers,
            self.writer_profiles,
        )


@dataclass(frozen=True, slots=True)
class GeneratedWorkflowResult:
    source: RunV2Source
    evaluated_input_count: int
    executed_check_count: int
    published_run: ValidatedRun | None

    def __post_init__(self) -> None:
        source_counts = self.source.evaluated_inputs, self.source.executed_checks
        if source_counts != (self.evaluated_input_count, self.executed_check_count):
            raise ValueError("generated workflow counts conflict with its run source")
        if self.evaluated_input_count < 1:
            raise ValueError("generated workflow must evaluate at least one input")
        if self.executed_check_count < self.evaluated_input_count:
            raise ValueError("generated workflow check count is smaller than its input count")


def execute_check(
    case: Case,
    destination: Path,
    selection: EngineSelection,
    writer_profiles: WriterProfilePlan | None = None,
) -> ValidatedRun | None:
    return capture_check(case, destination, selection, writer_profiles).published_run


def capture_check(
    case: Case,
    destination: Path,
    selection: EngineSelection,
    writer_profiles: WriterProfilePlan | None = None,
    *,
    report_command: str | None = None,
) -> GeneratedWorkflowResult:
    ensure_destination_absent(destination)
    evaluator = SelectedEvaluator(selection, writer_profiles)
    evidence = find_case_evidence(
        case,
        evaluator,
        evaluation_context=evaluator.context,
    )
    discovery = DiscoveryEvidence(None, None, None, CHECK_COMPLETE)
    source = _v2_source(
        "check",
        evidence.findings,
        (),
        evidence.occurrences,
        evidence.evaluated_cases,
        evidence.evaluated_cells,
        discovery,
        selection,
        writer_profiles=writer_profiles,
    )
    return GeneratedWorkflowResult(
        source,
        evidence.evaluated_cases,
        evidence.evaluated_cells,
        publish_run(source, destination, evaluator, report_command=report_command),
    )


def execute_fuzz(
    destination: Path,
    *,
    examples: int,
    seed: int,
    max_saved: int,
    selection: EngineSelection,
    schema: SchemaPlan | None = None,
    writer_profiles: WriterProfilePlan | None = None,
    progress: ProgressCallback | None = None,
) -> ValidatedRun | None:
    return capture_fuzz(
        destination,
        examples=examples,
        seed=seed,
        max_saved=max_saved,
        selection=selection,
        schema=schema,
        writer_profiles=writer_profiles,
        progress=progress,
    ).published_run


def capture_fuzz(
    destination: Path,
    *,
    examples: int,
    seed: int,
    max_saved: int,
    selection: EngineSelection,
    schema: SchemaPlan | None = None,
    writer_profiles: WriterProfilePlan | None = None,
    progress: ProgressCallback | None = None,
    report_command: str | None = None,
) -> GeneratedWorkflowResult:
    ensure_destination_absent(destination)
    selected_evaluator = SelectedEvaluator(selection, writer_profiles)
    evaluator = selected_evaluator if schema is None else schema.bind(selected_evaluator)
    strategy = bounded_cases() if schema is None else schema.cases()
    notifier = resilient_progress(progress)
    campaign = search_cases(
        strategy,
        examples=examples,
        seed=seed,
        max_saved=max_saved,
        evaluator=evaluator,
        candidate_admission=(lambda case: True) if schema is None else schema.admits,
        progress=notifier,
        evaluation_context=selected_evaluator.context,
    )
    discovery = DiscoveryEvidence(
        campaign.discovery_bound,
        campaign.seed,
        campaign.max_saved,
        campaign.stop_reason,
        campaign.evaluated_cases,
        campaign.evaluated_cells,
    )
    generation = None if schema is None else GenerationEvidence("schema", schema.schema_case_id)
    source = _v2_source(
        "fuzz",
        campaign.findings,
        campaign.overflow,
        campaign.occurrences,
        campaign.evaluated_cases,
        campaign.evaluated_cells,
        discovery,
        selection,
        generation=generation,
        writer_profiles=writer_profiles,
    )
    return GeneratedWorkflowResult(
        source,
        campaign.evaluated_cases,
        campaign.evaluated_cells,
        publish_run(
            source,
            destination,
            evaluator,
            lambda value: notifier(_publication_progress(campaign, value)),
            report_command=report_command,
        ),
    )


def _publication_progress(
    campaign: SearchCampaign,
    value: RunPublicationProgress,
) -> FuzzProgress:
    phase = (
        FuzzPhase.EVIDENCE_WRITING
        if value.phase is RunPublicationPhase.WRITING
        else FuzzPhase.FINALIZATION
    )
    return FuzzProgress(
        phase,
        campaign.evaluated_cases,
        campaign.evaluated_cells,
        len(campaign.findings),
        len(campaign.overflow),
        value.completed_findings,
        value.total_findings,
    )


def _v2_source(
    command: str,
    findings: tuple[SearchFinding, ...],
    overflow: tuple[OverflowObservation, ...],
    occurrences: tuple[GeneratedOccurrence, ...],
    evaluated_inputs: int,
    executed_checks: int,
    discovery: DiscoveryEvidence,
    selection: EngineSelection,
    generation: GenerationEvidence | None = None,
    writer_profiles: WriterProfilePlan | None = None,
) -> RunV2Source:
    writers, readers, providers = _engine_evidence(selection)
    return RunV2Source(
        command=command,
        findings=findings,
        overflow=overflow,
        writers=writers,
        readers=readers,
        discovery=discovery,
        environment=capture_environment(providers),
        generation=generation,
        writer_profiles=writer_profiles,
        occurrences=occurrences,
        evaluated_inputs=evaluated_inputs,
        executed_checks=executed_checks,
    )


def _engine_evidence(
    selection: EngineSelection,
) -> tuple[
    tuple[EngineVersion, ...],
    tuple[EngineVersion, ...],
    tuple[EngineVersion, ...],
]:
    writers = tuple(writer.identity for writer in selection.writers)
    readers = tuple(reader.identity for reader in selection.readers)
    versions = {engine.name: engine.version for engine in (*writers, *readers)}
    providers = tuple(
        EngineVersion(descriptor.name, versions[descriptor.name])
        for descriptor in ENGINE_DESCRIPTORS
        if descriptor.name in versions
    )
    return writers, readers, providers


__all__ = [
    "GeneratedWorkflowResult",
    "SelectedEvaluator",
    "capture_check",
    "capture_fuzz",
    "execute_check",
    "execute_fuzz",
]
