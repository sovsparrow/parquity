from __future__ import annotations

import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import overload

from ..evidence import digest_matches, sha256_hex
from ..evidence import json_codec as codec
from ..evidence.storage import (
    DestinationExistsError,
    StagingError,
    atomic_publish_directory,
    require_destination_absent,
    staging_directory,
)
from ..findings.bundle import (
    BundleValidationError,
    FindingSource,
    ValidatedBundle,
    build_bundle,
    validate_bundle,
)
from ..findings.model import ReductionEvidence, finding_id_for
from ..findings.report import FindingReportContext
from ..generation.evidence import EXAMPLE_BOUND_REACHED, STRATEGY_EXHAUSTED, DiscoveryEvidence
from ..generation.search.identity import finding_key
from ..generation.search.records import SearchFinding
from ..verdicts import CaseEvaluator
from .formats import (
    RunDigest,
    RunFindingIndex,
    RunRecord,
    parse_run_record,
    v1,
    v2,
)
from .progress import (
    RunProgressCallback,
    RunPublicationPhase,
    RunPublicationProgress,
    notify,
)
from .source import RunSource, RunV2Source, planned_finding_keys


class RunBundleError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


class RunPublicationError(RunBundleError):
    pass


class RunBundleValidationError(RunBundleError):
    pass


@dataclass(frozen=True, slots=True)
class ValidatedRun:
    run: RunRecord
    children: tuple[ValidatedBundle, ...]
    directory: Path


class ValidatedRunV1(ValidatedRun):
    run: v1.RunRecord


class ValidatedRunV2(ValidatedRun):
    run: v2.RunRecord


@overload
def publish_run(
    source: RunV2Source,
    destination: Path,
    evaluator: CaseEvaluator,
    progress: RunProgressCallback | None = None,
    *,
    report_command: str | None = None,
) -> ValidatedRunV2 | None: ...


@overload
def publish_run(
    source: RunSource,
    destination: Path,
    evaluator: CaseEvaluator,
    progress: RunProgressCallback | None = None,
    *,
    report_command: str | None = None,
) -> ValidatedRunV1 | None: ...


def publish_run(
    source: RunSource | RunV2Source,
    destination: Path,
    evaluator: CaseEvaluator,
    progress: RunProgressCallback | None = None,
    *,
    report_command: str | None = None,
) -> ValidatedRun | None:
    ensure_destination_absent(destination)
    if not source.findings:
        return None
    try:
        with staging_directory(destination) as staging:
            validated = _build_run(
                source,
                staging,
                evaluator,
                progress,
                report_command=report_command,
            )
            ensure_destination_absent(destination)
            try:
                atomic_publish_directory(staging, destination)
            except DestinationExistsError as error:
                raise RunPublicationError("OUTPUT_EXISTS", "output path already exists") from error
            except OSError as error:
                raise _output_error() from error
    except StagingError as error:
        raise _output_error() from error
    return replace(
        validated,
        children=tuple(
            replace(child, directory=destination / "findings" / child.directory.name)
            for child in validated.children
        ),
        directory=destination,
    )


def validate_run(directory: Path) -> ValidatedRun:
    try:
        _validate_root_entries(directory)
        payload = (directory / "run.json").read_bytes()
        run = parse_run_record(payload)
        if not codec.is_canonical_json(payload):
            raise RunBundleValidationError("INVALID_BUNDLE", "run.json is not canonical")
        children = _validate_children(directory, run)
        _validate_report(directory, run)
        validated_type = ValidatedRunV2 if isinstance(run, v2.RunRecord) else ValidatedRunV1
        return validated_type(run, children, directory)
    except RunBundleValidationError:
        raise
    except (BundleValidationError, OSError, ValueError) as error:
        raise RunBundleValidationError(
            "INVALID_BUNDLE", f"run validation failed: {error}"
        ) from error


def _build_run(
    source: RunSource | RunV2Source,
    staging: Path,
    evaluator: CaseEvaluator,
    progress: RunProgressCallback | None,
    *,
    report_command: str | None,
) -> ValidatedRun:
    findings_directory = staging / "findings"
    try:
        findings_directory.mkdir()
    except OSError as error:
        raise _output_error() from error
    ordered = sorted(
        source.findings,
        key=(
            (lambda item: item.key)
            if isinstance(source, RunV2Source)
            else (lambda item: item.fingerprint.canonical_bytes())
        ),
    )
    total_findings = len(ordered)
    notify(progress, RunPublicationProgress(RunPublicationPhase.WRITING, 0, total_findings))
    indexes: list[RunFindingIndex] = []
    validated_children: list[ValidatedBundle] = []
    for completed_findings, finding in enumerate(ordered, start=1):
        finding_id = finding_id_for(finding.case.case_id, finding.fingerprint)
        child = findings_directory / finding_id
        validated = build_bundle(
            _finding_source(source, finding),
            child,
            evaluator,
            _finding_report_context(source, finding),
        )
        record = validated.finding
        validated_children.append(validated)
        if _has_unplanned_result(source, validated):
            raise RunPublicationError(
                "OUTPUT_ERROR", "final evaluation produced an unplanned finding"
            )
        manifest = (child / "finding.json").read_bytes()
        indexes.append(
            RunFindingIndex(
                finding_id=record.finding_id,
                case_id=record.case_id,
                fingerprint=record.fingerprint,
                manifest_path=f"findings/{record.finding_id}/finding.json",
                sha256=sha256_hex(manifest),
                byte_count=len(manifest),
            )
        )
        notify(
            progress,
            RunPublicationProgress(
                RunPublicationPhase.WRITING,
                completed_findings,
                total_findings,
            ),
        )
    finding_indexes = tuple(indexes)
    notify(
        progress,
        RunPublicationProgress(
            RunPublicationPhase.FINALIZING,
            total_findings,
            total_findings,
        ),
    )
    run, report_payload = _record_and_report(
        source,
        finding_indexes,
        tuple(validated_children),
        staging,
        report_command=report_command,
    )
    try:
        (staging / "REPORT.md").write_bytes(report_payload)
        (staging / "run.json").write_bytes(run.canonical_bytes())
    except OSError as error:
        raise _output_error() from error
    return validate_run(staging)


def _record_and_report(
    source: RunSource | RunV2Source,
    finding_indexes: tuple[RunFindingIndex, ...],
    children: tuple[ValidatedBundle, ...],
    staging: Path,
    *,
    report_command: str | None,
) -> tuple[RunRecord, bytes]:
    empty = b""
    provisional_digest = RunDigest("REPORT.md", sha256_hex(empty), len(empty))
    if not isinstance(source, RunV2Source):
        return v1.build_run_record(source, finding_indexes, provisional_digest), empty
    provisional = v2.build_run_record(source, finding_indexes, provisional_digest)
    from ..reporting.markdown import render_run_report  # noqa: PLC0415
    from .report import build_run_report_view  # noqa: PLC0415

    payload = render_run_report(
        build_run_report_view(
            ValidatedRunV2(provisional, children, staging),
            command_line=report_command,
        )
    )
    report = RunDigest("REPORT.md", sha256_hex(payload), len(payload))
    return v2.build_run_record(source, finding_indexes, report), payload


def _finding_source(source: RunSource | RunV2Source, finding: SearchFinding) -> FindingSource:
    counts = finding.reductions
    reduction = ReductionEvidence(
        discovered_case_id=finding.discovered_case.case_id,
        minimized_case_id=finding.case.case_id,
        hypothesis_reduced=finding.hypothesis_reduced,
        fields=counts.fields,
        rows=counts.rows,
        nullability=counts.nullability,
        containers=counts.containers,
        scalars=counts.scalars,
    )
    return FindingSource(
        case=finding.case,
        discovered_case=finding.discovered_case,
        fingerprint=finding.fingerprint,
        command=source.command,
        writers=source.writers,
        readers=source.readers,
        discovery=_finding_discovery(source),
        environment=source.environment,
        reduction=reduction,
        generation=source.generation,
        writer_profiles=source.writer_profiles,
    )


def _finding_report_context(
    source: RunSource | RunV2Source,
    finding: SearchFinding,
) -> FindingReportContext | None:
    if not isinstance(source, RunV2Source):
        return None
    occurrences = tuple(item for item in source.occurrences if item.key == finding.key)
    if not occurrences:
        raise RunPublicationError(
            "OUTPUT_ERROR",
            "saved Finding has no generated occurrence evidence",
        )
    return FindingReportContext(
        tuple(
            sorted(
                (item.target for item in occurrences),
                key=lambda target: (target[0], target[1].canonical_bytes()),
            )
        )
    )


def _finding_discovery(source: RunSource | RunV2Source) -> DiscoveryEvidence:
    discovery = source.discovery
    if not isinstance(source, RunV2Source) or discovery.stop_reason != STRATEGY_EXHAUSTED:
        return discovery
    return replace(discovery, stop_reason=EXAMPLE_BOUND_REACHED)


def _has_unplanned_result(source: RunSource | RunV2Source, validated: ValidatedBundle) -> bool:
    planned = planned_finding_keys(source)
    return any(
        finding_key(fingerprint) not in planned for fingerprint in validated.matrix.selection_order
    )


def _validate_root_entries(directory: Path) -> None:
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise RunBundleValidationError("INVALID_BUNDLE", "run must be a directory")
    entries = {path.name: path for path in directory.iterdir()}
    if set(entries) != {"run.json", "REPORT.md", "findings"}:
        raise RunBundleValidationError("INVALID_BUNDLE", "run inventory is not exact")
    if any(stat.S_ISLNK(path.lstat().st_mode) for path in entries.values()):
        raise RunBundleValidationError("INVALID_BUNDLE", "run entries must not be symlinks")
    if not stat.S_ISREG(entries["run.json"].lstat().st_mode) or not stat.S_ISREG(
        entries["REPORT.md"].lstat().st_mode
    ):
        raise RunBundleValidationError("INVALID_BUNDLE", "run manifests must be files")
    if not stat.S_ISDIR(entries["findings"].lstat().st_mode):
        raise RunBundleValidationError("INVALID_BUNDLE", "findings must be a directory")


def _validate_report(directory: Path, run: RunRecord) -> None:
    report = run.report
    payload = (directory / report.path).read_bytes()
    if not digest_matches(payload, report.sha256, report.byte_count):
        raise RunBundleValidationError("INVALID_BUNDLE", "run report digest does not match")


def _validate_children(directory: Path, run: RunRecord) -> tuple[ValidatedBundle, ...]:
    findings_directory = directory / "findings"
    entries = tuple(findings_directory.iterdir())
    expected = {item.finding_id for item in run.findings}
    if {path.name for path in entries} != expected:
        raise RunBundleValidationError("INVALID_BUNDLE", "child inventory does not match run.json")
    if any(stat.S_ISLNK(path.lstat().st_mode) for path in entries):
        raise RunBundleValidationError("INVALID_BUNDLE", "child directories must not be symlinks")
    children: list[ValidatedBundle] = []
    for item in run.findings:
        child = findings_directory / item.finding_id
        payload = (child / "finding.json").read_bytes()
        if not digest_matches(payload, item.sha256, item.byte_count):
            raise RunBundleValidationError("INVALID_BUNDLE", "child manifest digest does not match")
        validated = validate_bundle(child)
        _validate_child(run, item, validated)
        children.append(validated)
    if len({child.finding.generation for child in children}) != 1:
        raise RunBundleValidationError(
            "INVALID_BUNDLE", "child generation evidence is inconsistent"
        )
    if isinstance(run, v2.RunRecord):
        _validate_saved_occurrences(run, tuple(children))
    return tuple(children)


def _validate_saved_occurrences(
    run: v2.RunRecord,
    children: tuple[ValidatedBundle, ...],
) -> None:
    occurrences = {item.target: item for item in run.occurrences}
    for index, child in zip(run.saved_evidence, children, strict=True):
        target = child.finding.reduction.discovered_case_id, child.finding.fingerprint
        occurrence = occurrences.get(target)
        if occurrence is None:
            raise RunBundleValidationError(
                "INVALID_BUNDLE",
                "saved representative discovered target is absent from occurrences",
            )
        if occurrence.key != finding_key(index.fingerprint):
            raise RunBundleValidationError(
                "INVALID_BUNDLE",
                "saved representative occurrence has a conflicting finding key",
            )


def _validate_child(run: RunRecord, index: RunFindingIndex, child: ValidatedBundle) -> None:
    finding = child.finding
    conflicts = (
        finding.finding_id != index.finding_id
        or finding.case_id != index.case_id
        or finding.fingerprint != index.fingerprint
        or finding.command != run.command
        or finding.writers != run.writers
        or finding.readers != run.readers
        or finding.discovery != _run_finding_discovery(run)
        or finding.environment != run.environment
        or finding.writer_profiles != run.writer_profiles
    )
    if conflicts:
        raise RunBundleValidationError("INVALID_BUNDLE", "child evidence conflicts with run.json")


def _run_finding_discovery(run: RunRecord) -> DiscoveryEvidence:
    discovery = run.discovery
    if isinstance(run, v2.RunRecord) and discovery.stop_reason == STRATEGY_EXHAUSTED:
        return replace(discovery, stop_reason=EXAMPLE_BOUND_REACHED)
    return discovery


def ensure_destination_absent(destination: Path) -> None:
    try:
        require_destination_absent(destination)
    except DestinationExistsError as error:
        raise RunPublicationError("OUTPUT_EXISTS", "output path already exists") from error
    except OSError as error:
        raise _output_error() from error


def _output_error() -> RunPublicationError:
    return RunPublicationError("OUTPUT_ERROR", "output path could not be published")


__all__ = [
    "RunBundleError",
    "RunBundleValidationError",
    "RunProgressCallback",
    "RunPublicationError",
    "RunPublicationPhase",
    "RunPublicationProgress",
    "RunSource",
    "ValidatedRun",
    "ensure_destination_absent",
    "publish_run",
    "validate_run",
]
