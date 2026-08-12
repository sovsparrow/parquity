from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path

from ..evidence import EngineVersion, EnvironmentEvidence, sha256_hex
from ..evidence import json_codec as codec
from ..evidence.storage import (
    DestinationExistsError,
    remove_tree,
    require_destination_absent,
)
from ..generation.evidence import DiscoveryEvidence, GenerationEvidence
from ..model import Case
from ..profiles import WriterProfilePlan
from ..reporting.markdown import render_evidence_report
from ..verdicts import CaseEvaluator, CellResult, FailureFingerprint, MatrixRun
from . import OPTIONAL_DISCOVERED_CASE, OPTIONAL_INPUT
from .matrix import MatrixRecord
from .model import (
    ArtifactDigest,
    FindingRecord,
    ReductionEvidence,
    ReplaySignature,
    finding_id_for,
)
from .report import FindingReportContext, build_evidence_report_view
from .scripts import render_reproduce
from .upstream_script import render_upstream_repro


class BundleError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


class BundlePublicationError(BundleError):
    pass


class BundleValidationError(BundleError):
    pass


@dataclass(frozen=True, slots=True)
class FindingSource:
    case: Case
    discovered_case: Case
    fingerprint: FailureFingerprint
    command: str
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    discovery: DiscoveryEvidence
    environment: EnvironmentEvidence
    reduction: ReductionEvidence
    generation: GenerationEvidence | None = None
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        if self.case.case_id != self.reduction.minimized_case_id:
            raise ValueError("final Case conflicts with reduction evidence")
        if self.discovered_case.case_id != self.reduction.discovered_case_id:
            raise ValueError("discovered Case conflicts with reduction evidence")


@dataclass(frozen=True, slots=True)
class ValidatedBundle:
    finding: FindingRecord
    case: Case
    discovered_case: Case
    matrix: MatrixRecord
    directory: Path


def load_case(path: Path, destination: Path) -> Case:
    ensure_destination_absent(destination)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise BundlePublicationError(
            "CASE_UNREADABLE", f"cannot read case file: {error}"
        ) from error
    try:
        return Case.from_json(payload)
    except RecursionError as error:
        raise BundlePublicationError(
            "INVALID_CASE", "case input nesting exceeds parser limits"
        ) from error
    except (TypeError, ValueError) as error:
        raise BundlePublicationError("INVALID_CASE", f"case input is not valid: {error}") from error


def ensure_destination_absent(destination: Path) -> None:
    try:
        require_destination_absent(destination)
    except DestinationExistsError as error:
        raise BundlePublicationError("OUTPUT_EXISTS", "output path already exists") from error
    except OSError as error:
        raise _output_error() from error


def build_bundle(
    source: FindingSource,
    directory: Path,
    evaluator: CaseEvaluator,
    report_context: FindingReportContext | None = None,
) -> ValidatedBundle:
    ensure_destination_absent(directory)
    try:
        directory.mkdir(parents=True)
    except OSError as error:
        raise _output_error() from error
    evaluation_directory = directory / ".evaluation"
    run = evaluator(source.case, evaluation_directory).normalized((directory,))
    if run.case_id != source.case.case_id:
        raise RuntimeError("final evaluation returned a conflicting Case identity")
    if run.writer_profiles != source.writer_profiles:
        raise RuntimeError("final evaluation returned a conflicting writer profile plan")
    selected = _matching_result(run, source.fingerprint)
    if selected is None:
        raise RuntimeError("selected fingerprint is absent from final evaluation")
    matrix = MatrixRecord.from_run(run, source.writers, source.readers, source.fingerprint)
    input_payload = _input_payload(selected, run, evaluation_directory)
    _remove_tree(evaluation_directory)
    finding_id = finding_id_for(source.case.case_id, source.fingerprint)
    payloads = _artifact_payloads(source, matrix, selected, input_payload)
    report_payload = b""
    if report_context is not None:
        report_payload = render_evidence_report(
            build_evidence_report_view(
                source,
                finding_id,
                matrix,
                selected,
                report_context,
            )
        )
    payloads["REPORT.md"] = report_payload
    artifacts = tuple(
        ArtifactDigest(name, sha256_hex(payload), len(payload))
        for name, payload in sorted(payloads.items())
    )
    finding = FindingRecord(
        finding_id=finding_id,
        case_id=source.case.case_id,
        command=source.command,
        writers=source.writers,
        readers=source.readers,
        discovery=source.discovery,
        environment=source.environment,
        reduction=source.reduction,
        fingerprint=source.fingerprint,
        replay_signature=ReplaySignature.from_fingerprint(source.fingerprint),
        result=selected,
        input_parquet=input_payload is not None,
        artifacts=artifacts,
        generation=source.generation,
        writer_profiles=source.writer_profiles,
    )
    try:
        for name, payload in sorted(payloads.items()):
            (directory / name).write_bytes(payload)
        (directory / "finding.json").write_bytes(finding.canonical_bytes())
    except OSError as error:
        raise _output_error() from error
    return validate_bundle(directory)


def validate_bundle(directory: Path) -> ValidatedBundle:
    try:
        entries = _bundle_entries(directory)
        finding_payload = (directory / "finding.json").read_bytes()
        finding = FindingRecord.from_json(finding_payload)
        if not codec.is_canonical_json(finding_payload):
            raise BundleValidationError("INVALID_BUNDLE", "finding.json is not canonical")
        declared = {"finding.json", *(artifact.name for artifact in finding.artifacts)}
        if {path.name for path in entries} != declared:
            raise BundleValidationError(
                "INVALID_BUNDLE", "finding inventory does not match finding.json"
            )
        _validate_artifacts(directory, finding)
        case = _canonical_case(directory / "case.json")
        if case.case_id != finding.case_id:
            raise BundleValidationError("INVALID_BUNDLE", "final Case identity does not match")
        discovered = _discovered_case(directory, finding, case)
        if finding.generation is not None and not finding.generation.binds(case, discovered):
            raise BundleValidationError("INVALID_BUNDLE", "generation evidence conflicts with Case")
        matrix_payload = (directory / "matrix.json").read_bytes()
        matrix = MatrixRecord.from_json(matrix_payload)
        if not codec.is_canonical_json(matrix_payload):
            raise BundleValidationError("INVALID_BUNDLE", "matrix.json is not canonical")
        _validate_matrix(finding, matrix)
        return ValidatedBundle(finding, case, discovered, matrix, directory)
    except BundleValidationError:
        raise
    except (OSError, ValueError) as error:
        raise BundleValidationError(
            "INVALID_BUNDLE", f"finding validation failed: {error}"
        ) from error


def _artifact_payloads(
    source: FindingSource,
    matrix: MatrixRecord,
    selected: CellResult,
    input_payload: bytes | None,
) -> dict[str, bytes]:
    payloads = {
        "case.json": source.case.canonical_bytes(),
        "matrix.json": matrix.canonical_bytes(),
        "reproduce.py": render_reproduce(),
        "upstream_repro.py": render_upstream_repro(source.case, selected),
    }
    if source.discovered_case.case_id != source.case.case_id:
        payloads[OPTIONAL_DISCOVERED_CASE] = source.discovered_case.canonical_bytes()
    if input_payload is not None:
        payloads[OPTIONAL_INPUT] = input_payload
    return payloads


def _input_payload(
    result: CellResult,
    run: MatrixRun,
    evaluation_directory: Path,
) -> bytes | None:
    if result.operation == "write":
        return None
    source = run.file_for(result.writer, result.writer_profile)
    if source is None:
        raise RuntimeError("selected writer output is unavailable")
    try:
        if not stat.S_ISREG(source.lstat().st_mode):
            raise RuntimeError("selected writer output is unavailable")
        resolved_root = evaluation_directory.resolve(strict=True)
        resolved_source = source.resolve(strict=True)
        resolved_source.relative_to(resolved_root)
        return resolved_source.read_bytes()
    except ValueError as error:
        raise RuntimeError("selected writer output is outside the evaluation directory") from error
    except OSError as error:
        raise _output_error() from error


def _bundle_entries(directory: Path) -> tuple[Path, ...]:
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise BundleValidationError("INVALID_BUNDLE", "finding must be a directory")
    entries = tuple(directory.iterdir())
    modes = tuple(path.lstat().st_mode for path in entries)
    if any(stat.S_ISLNK(mode) for mode in modes):
        raise BundleValidationError("INVALID_BUNDLE", "finding payloads must not be symlinks")
    if any(not stat.S_ISREG(mode) for mode in modes):
        raise BundleValidationError("INVALID_BUNDLE", "finding payloads must be files")
    if "finding.json" not in {path.name for path in entries}:
        raise BundleValidationError("INVALID_BUNDLE", "finding.json is missing")
    return entries


def _validate_artifacts(directory: Path, finding: FindingRecord) -> None:
    for artifact in finding.artifacts:
        payload = (directory / artifact.name).read_bytes()
        if not artifact.matches(payload):
            raise BundleValidationError("INVALID_BUNDLE", "artifact evidence does not match")


def _canonical_case(path: Path) -> Case:
    payload = path.read_bytes()
    case = Case.from_json(payload)
    if not codec.canonical_bytes_match(payload, case.to_data()):
        raise BundleValidationError("INVALID_BUNDLE", f"{path.name} is not canonical")
    return case


def _discovered_case(directory: Path, finding: FindingRecord, case: Case) -> Case:
    path = directory / OPTIONAL_DISCOVERED_CASE
    discovered = _canonical_case(path) if path.exists() else case
    if discovered.case_id != finding.reduction.discovered_case_id:
        raise BundleValidationError("INVALID_BUNDLE", "discovered Case identity does not match")
    return discovered


def _validate_matrix(finding: FindingRecord, matrix: MatrixRecord) -> None:
    conflicts = (
        matrix.case_id != finding.case_id
        or matrix.writers != finding.writers
        or matrix.readers != finding.readers
        or matrix.target != finding.fingerprint
        or finding.result not in matrix.results
        or matrix.writer_profiles != finding.writer_profiles
    )
    if conflicts:
        raise BundleValidationError("INVALID_BUNDLE", "matrix evidence conflicts with finding.json")


def _matching_result(run: MatrixRun, fingerprint: FailureFingerprint) -> CellResult | None:
    return next((result for result in run.failures if result.fingerprint == fingerprint), None)


def _remove_tree(path: Path, *, preserve_active_error: bool = False) -> None:
    try:
        remove_tree(path, preserve_active_error=preserve_active_error)
    except OSError as error:
        raise _output_error() from error


def _output_error() -> BundlePublicationError:
    return BundlePublicationError("OUTPUT_ERROR", "output path could not be published")
