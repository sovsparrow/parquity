from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..engines import ENGINE_DESCRIPTORS, EngineSelection
from ..findings.bundle import ensure_destination_absent
from ..findings.evidence import (
    CHECK_COMPLETE,
    DiscoveryEvidence,
    GenerationEvidence,
    capture_environment,
)
from ..model import Case
from ..runs.bundle import RunSource, publish_run
from ..runs.model import RunRecord
from ..verdicts import EngineVersion, MatrixRun
from ..writer_profiles import WriterProfilePlan
from .schema import SchemaPlan
from .search import (
    OverflowObservation,
    SearchFinding,
    evaluate_selected_case,
    find_case_observations,
    search_cases,
)
from .strategies import bounded_cases


@dataclass(frozen=True, slots=True)
class SelectedEvaluator:
    selection: EngineSelection
    writer_profiles: WriterProfilePlan | None = None

    def __call__(self, case: Case, directory: Path, /) -> MatrixRun:
        if self.writer_profiles is None:
            return evaluate_selected_case(case, directory, self.selection)
        return evaluate_selected_case(case, directory, self.selection, self.writer_profiles)


def execute_check(
    case: Case,
    destination: Path,
    selection: EngineSelection,
    writer_profiles: WriterProfilePlan | None = None,
) -> RunRecord | None:
    ensure_destination_absent(destination)
    evaluator = SelectedEvaluator(selection, writer_profiles)
    findings = find_case_observations(case, evaluator)
    discovery = DiscoveryEvidence(None, None, None, CHECK_COMPLETE)
    source = _source("check", findings, (), discovery, selection, writer_profiles=writer_profiles)
    return publish_run(source, destination, evaluator)


def execute_fuzz(
    destination: Path,
    *,
    examples: int,
    seed: int,
    max_findings: int,
    selection: EngineSelection,
    schema: SchemaPlan | None = None,
    writer_profiles: WriterProfilePlan | None = None,
) -> RunRecord | None:
    ensure_destination_absent(destination)
    selected_evaluator = SelectedEvaluator(selection, writer_profiles)
    evaluator = selected_evaluator if schema is None else schema.bind(selected_evaluator)
    strategy = bounded_cases() if schema is None else schema.cases()
    campaign = search_cases(
        strategy,
        examples=examples,
        seed=seed,
        max_findings=max_findings,
        evaluator=evaluator,
        candidate_admission=(lambda case: True) if schema is None else schema.admits,
    )
    if campaign is None:
        return None
    discovery = DiscoveryEvidence(
        campaign.discovery_bound,
        campaign.seed,
        campaign.max_findings,
        campaign.stop_reason,
        campaign.evaluated_cases,
        campaign.evaluated_cells,
    )
    generation = None if schema is None else GenerationEvidence("schema", schema.schema_case_id)
    source = _source(
        "fuzz",
        campaign.findings,
        campaign.overflow,
        discovery,
        selection,
        generation,
        writer_profiles,
    )
    return publish_run(source, destination, evaluator)


def _source(
    command: str,
    findings: tuple[SearchFinding, ...],
    overflow: tuple[OverflowObservation, ...],
    discovery: DiscoveryEvidence,
    selection: EngineSelection,
    generation: GenerationEvidence | None = None,
    writer_profiles: WriterProfilePlan | None = None,
) -> RunSource:
    writers, readers, providers = _engine_evidence(selection)
    return RunSource(
        command=command,
        findings=findings,
        overflow=overflow,
        writers=writers,
        readers=readers,
        discovery=discovery,
        environment=capture_environment(providers),
        generation=generation,
        writer_profiles=writer_profiles,
    )


def _engine_evidence(
    selection: EngineSelection,
) -> tuple[
    tuple[EngineVersion, ...],
    tuple[EngineVersion, ...],
    tuple[EngineVersion, ...],
]:
    writers = tuple(EngineVersion(name, version) for name, version in selection.writer_versions)
    readers = tuple(EngineVersion(name, version) for name, version in selection.reader_versions)
    versions = {engine.name: engine.version for engine in (*writers, *readers)}
    providers = tuple(
        EngineVersion(descriptor.name, versions[descriptor.name])
        for descriptor in ENGINE_DESCRIPTORS
        if descriptor.name in versions
    )
    return writers, readers, providers


__all__ = ["SelectedEvaluator", "execute_check", "execute_fuzz"]
