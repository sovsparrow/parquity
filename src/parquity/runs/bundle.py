from __future__ import annotations

import hashlib
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..findings import evidence
from ..findings import json_codec as codec
from ..findings.bundle import (
    BundlePublicationError,
    BundleValidationError,
    FindingSource,
    ValidatedBundle,
    build_bundle,
    ensure_destination_absent,
    validate_bundle,
)
from ..findings.model import finding_id_for
from ..generation import CaseEvaluator
from ..generation.search import OverflowObservation, SearchFinding
from ..verdicts import EngineVersion
from ..writer_profiles import WriterProfilePlan
from . import RUN_STATUS_CAP, RUN_STATUS_FINDINGS
from .model import (
    OverflowEvidence,
    RunDigest,
    RunFindingIndex,
    RunRecord,
    calculate_run_id,
)
from .report import render_run_report


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
class RunSource:
    command: str
    findings: tuple[SearchFinding, ...]
    overflow: tuple[OverflowObservation, ...]
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: evidence.DiscoveryEvidence
    environment: evidence.EnvironmentEvidence
    generation: evidence.GenerationEvidence | None = None
    writer_profiles: WriterProfilePlan | None = None


@dataclass(frozen=True, slots=True)
class ValidatedRun:
    run: RunRecord
    children: tuple[ValidatedBundle, ...]
    directory: Path


def publish_run(
    source: RunSource,
    destination: Path,
    evaluator: CaseEvaluator,
) -> RunRecord | None:
    _ensure_absent(destination)
    if not source.findings:
        return None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.parquity-", dir=destination.parent)
        )
    except OSError as error:
        raise _output_error() from error
    published = False
    try:
        record = _build_run(source, staging, evaluator)
        _ensure_absent(destination)
        try:
            staging.rename(destination)
        except OSError as error:
            _raise_publish_error(destination, error)
        published = True
        return record
    finally:
        if not published:
            _remove_tree(staging, preserve_active_error=sys.exc_info()[0] is not None)


def validate_run(directory: Path) -> ValidatedRun:
    try:
        _validate_root_entries(directory)
        payload = (directory / "run.json").read_bytes()
        run = RunRecord.from_json(payload)
        if not codec.is_canonical_json(payload):
            raise RunBundleValidationError("INVALID_BUNDLE", "run.json is not canonical")
        children = _validate_children(directory, run)
        _validate_report(directory, run, children)
        return ValidatedRun(run, children, directory)
    except RunBundleValidationError:
        raise
    except (BundleValidationError, OSError, ValueError) as error:
        raise RunBundleValidationError("INVALID_BUNDLE", "run validation failed") from error


def _build_run(source: RunSource, staging: Path, evaluator: CaseEvaluator) -> RunRecord:
    findings_directory = staging / "findings"
    try:
        findings_directory.mkdir()
    except OSError as error:
        raise _output_error() from error
    ordered = sorted(
        source.findings,
        key=lambda item: item.fingerprint.canonical_bytes(),
    )
    planned = {item.fingerprint for item in (*source.findings, *source.overflow)}
    indexes: list[RunFindingIndex] = []
    validated_children: list[ValidatedBundle] = []
    for finding in ordered:
        finding_id = finding_id_for(finding.case.case_id, finding.fingerprint)
        child = findings_directory / finding_id
        record = build_bundle(_finding_source(source, finding), child, evaluator)
        validated = validate_bundle(child)
        validated_children.append(validated)
        if any(fingerprint not in planned for fingerprint in validated.matrix.selection_order):
            raise RunPublicationError(
                "OUTPUT_ERROR", "final evaluation produced an unindexed fingerprint"
            )
        manifest = (child / "finding.json").read_bytes()
        indexes.append(
            RunFindingIndex(
                finding_id=record.finding_id,
                case_id=record.case_id,
                fingerprint=record.fingerprint,
                manifest_path=f"findings/{record.finding_id}/finding.json",
                sha256=hashlib.sha256(manifest).hexdigest(),
                byte_count=len(manifest),
            )
        )
    finding_indexes = tuple(indexes)
    overflow = tuple(
        sorted(
            (
                OverflowEvidence(item.case, item.result, item.stop_reason, item.origin)
                for item in source.overflow
            ),
            key=lambda item: item.fingerprint.canonical_bytes(),
        )
    )
    status = RUN_STATUS_CAP if overflow else RUN_STATUS_FINDINGS
    run_id = calculate_run_id(
        source.command,
        status,
        source.writers,
        source.readers,
        source.discovery,
        source.environment,
        finding_indexes,
        overflow,
        source.writer_profiles,
    )
    provisional = RunRecord(
        run_id=run_id,
        command=source.command,
        status=status,
        writers=source.writers,
        readers=source.readers,
        discovery=source.discovery,
        environment=source.environment,
        findings=finding_indexes,
        overflow=overflow,
        report=RunDigest("REPORT.md", "0" * 64, 0),
        writer_profiles=source.writer_profiles,
    )
    report_payload = render_run_report(provisional, tuple(validated_children))
    report = RunDigest("REPORT.md", hashlib.sha256(report_payload).hexdigest(), len(report_payload))
    run = RunRecord(
        run_id=run_id,
        command=source.command,
        status=status,
        writers=source.writers,
        readers=source.readers,
        discovery=source.discovery,
        environment=source.environment,
        findings=finding_indexes,
        overflow=overflow,
        report=report,
        writer_profiles=source.writer_profiles,
    )
    try:
        (staging / "REPORT.md").write_bytes(report_payload)
        (staging / "run.json").write_bytes(run.canonical_bytes())
    except OSError as error:
        raise _output_error() from error
    validate_run(staging)
    return run


def _finding_source(source: RunSource, finding: SearchFinding) -> FindingSource:
    counts = finding.reductions
    reduction = evidence.ReductionEvidence(
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
        discovery=source.discovery,
        environment=source.environment,
        reduction=reduction,
        generation=source.generation,
        writer_profiles=source.writer_profiles,
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


def _validate_report(
    directory: Path, run: RunRecord, children: tuple[ValidatedBundle, ...]
) -> None:
    report = run.report
    payload = (directory / report.path).read_bytes()
    if len(payload) != report.byte_count or hashlib.sha256(payload).hexdigest() != report.sha256:
        raise RunBundleValidationError("INVALID_BUNDLE", "run report digest does not match")
    if payload != render_run_report(run, children):
        raise RunBundleValidationError("INVALID_BUNDLE", "run report does not match")


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
        if len(payload) != item.byte_count or hashlib.sha256(payload).hexdigest() != item.sha256:
            raise RunBundleValidationError("INVALID_BUNDLE", "child manifest digest does not match")
        validated = validate_bundle(child)
        _validate_child(run, item, validated)
        children.append(validated)
    if len({child.finding.generation for child in children}) != 1:
        raise RunBundleValidationError(
            "INVALID_BUNDLE", "child generation evidence is inconsistent"
        )
    return tuple(children)


def _validate_child(
    run: RunRecord,
    index: RunFindingIndex,
    child: ValidatedBundle,
) -> None:
    finding = child.finding
    conflicts = (
        finding.finding_id != index.finding_id
        or finding.case_id != index.case_id
        or finding.fingerprint != index.fingerprint
        or finding.command != run.command
        or finding.writers != run.writers
        or finding.readers != run.readers
        or finding.discovery != run.discovery
        or finding.environment != run.environment
        or finding.writer_profiles != run.writer_profiles
    )
    if conflicts:
        raise RunBundleValidationError("INVALID_BUNDLE", "child evidence conflicts with run.json")


def _ensure_absent(destination: Path) -> None:
    try:
        ensure_destination_absent(destination)
    except BundlePublicationError as error:
        raise RunPublicationError(error.kind, error.detail) from error


def _raise_publish_error(destination: Path, error: OSError) -> None:
    try:
        _ensure_absent(destination)
    except RunPublicationError as destination_error:
        raise destination_error from error
    raise _output_error() from error


def _remove_tree(path: Path, *, preserve_active_error: bool = False) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as error:
        if not preserve_active_error:
            raise _output_error() from error


def _output_error() -> RunPublicationError:
    return RunPublicationError("OUTPUT_ERROR", "output path could not be published")


__all__ = [
    "RunBundleError",
    "RunBundleValidationError",
    "RunPublicationError",
    "RunSource",
    "ValidatedRun",
    "publish_run",
    "validate_run",
]
