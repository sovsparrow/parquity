from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from typing import NamedTuple

from ..configuration import scan_saved_limit_is_valid, scan_timeout_is_valid
from ..engines import ReaderSelection
from ..evidence import EngineVersion, EnvironmentEvidence, capture_environment
from ..evidence.storage import (
    DestinationExistsError,
    StagingError,
    atomic_publish_directory,
    require_destination_absent,
    staging_directory,
)
from . import bundle, discovery, observations, records
from .supervision import (
    WorkerLimitError,
    WorkerOutcome,
    WorkerProtocolError,
    WorkerUnavailableError,
    run_worker_process,
)


class FileEvaluation(NamedTuple):
    outcomes: tuple[records.ReaderOutcomeRecord, ...]
    grouped: observations.GroupedObservations


class ScanExecution(NamedTuple):
    run: bundle.ValidatedScanRun | None
    discovery: discovery.Discovery
    evaluated_files: int
    environment: EnvironmentEvidence


def evaluate_snapshot(
    snapshot: discovery.Snapshot,
    selection: ReaderSelection,
    timeout_seconds: int,
    private_root: Path,
) -> FileEvaluation:
    raw: list[WorkerOutcome] = []
    successful: list[observations.Observation] = []
    for index, reader in enumerate(selection.readers):
        identity = reader.identity
        worker_directory = private_root / f"worker-{index}"
        argv = [sys.executable, "-m", "parquity.scans.worker"]
        argv += ["--engine", identity.name, "--version", identity.version]
        argv += ["--input", str(snapshot.path), "--out", str(worker_directory)]
        try:
            outcome = run_worker_process(
                argv,
                worker_directory,
                expected_engine=identity.name,
                expected_version=identity.version,
                timeout_seconds=timeout_seconds,
                owned_root=private_root,
            )
        except WorkerLimitError as error:
            raise discovery.ScanConfigurationError("SCAN_LIMIT_EXCEEDED", str(error)) from error
        except WorkerUnavailableError as error:
            raise discovery.ScanConfigurationError("SCAN_UNAVAILABLE", str(error)) from error
        raw.append(outcome)
        if outcome.kind is records.ReaderOutcomeKind.SUCCESS:
            if outcome.artifact is None or outcome.metadata is None:
                raise WorkerProtocolError("successful worker omitted its observation")
            try:
                successful.append(
                    observations.decode_observation(
                        identity.name, outcome.artifact, outcome.metadata
                    )
                )
            except observations.ObservationError as error:
                raise WorkerProtocolError("worker observation artifact is invalid") from error
    grouped = observations.group_observations(tuple(successful))
    assignments = {engine: group.group_id for group in grouped.groups for engine in group.engines}
    outcomes = tuple(_outcome_record(item, assignments.get(item.engine)) for item in raw)
    return FileEvaluation(outcomes, grouped)


def execute_scan(
    source: Path,
    destination: Path,
    selection: ReaderSelection,
    *,
    timeout_seconds: int,
    max_saved: int,
    report_command: str | None = None,
) -> ScanExecution:
    _validate_limits(timeout_seconds, max_saved)
    _ensure_absent(destination)
    inputs = discovery.discover_input(source)
    versions = tuple(EngineVersion(name, version) for name, version in selection.reader_versions)
    environment = capture_environment(versions)
    with tempfile.TemporaryDirectory(prefix="parquity-scan-") as raw_private, ExitStack() as stack:
        private_root = Path(raw_private)
        public_root: Path | None = None
        indexes: list[Mapping[str, object]] = []
        evaluated = 0
        for file_index, discovered in enumerate(inputs.files):
            snapshot = discovery.snapshot_file(discovered, private_root / "snapshot")
            evaluation = evaluate_snapshot(snapshot, selection, timeout_seconds, private_root)
            evaluated += 1
            if (
                any(
                    item.kind is not records.ReaderOutcomeKind.SUCCESS
                    for item in evaluation.outcomes
                )
                or len(evaluation.grouped.groups) > 1
            ):
                if public_root is None:
                    public_root = _open_scan_staging(stack, destination)
                indexes.append(
                    _materialize_finding(
                        public_root,
                        file_index,
                        snapshot,
                        environment,
                        versions,
                        timeout_seconds,
                        evaluation,
                    )
                )
            shutil.rmtree(snapshot.path.parent)
            if len(indexes) >= max_saved:
                break
        if not indexes:
            return ScanExecution(None, inputs, evaluated, environment)
        overflow = tuple(item.relative_path for item in inputs.files[evaluated:])
        if public_root is None:
            raise RuntimeError("scan finding staging was not initialized")
        public = public_root / "public"
        validated = bundle.build_run(
            public,
            environment=environment,
            input_kind=inputs.input_kind,
            files=tuple((item.relative_path, item.byte_count) for item in inputs.files),
            skipped_symlinks=inputs.skipped_symlinks,
            visited_entries=inputs.visited_entries,
            engines=versions,
            timeout_seconds=timeout_seconds,
            max_saved=max_saved,
            findings=tuple(indexes),
            overflow=overflow,
            report_command=report_command,
        )
        _ensure_absent(destination)
        try:
            atomic_publish_directory(public, destination)
        except DestinationExistsError as error:
            raise discovery.ScanConfigurationError(
                "OUTPUT_EXISTS", "output path already exists"
            ) from error
        except OSError as error:
            raise discovery.ScanConfigurationError(
                "OUTPUT_ERROR", "scan output could not be published"
            ) from error
        published = bundle.ValidatedScanRun(
            validated.record,
            tuple(
                bundle.ValidatedScanFinding(
                    child.record,
                    destination / "findings" / child.record.finding_id,
                )
                for child in validated.children
            ),
            destination,
        )
        return ScanExecution(published, inputs, evaluated, environment)


def _validate_limits(timeout_seconds: object, max_saved: object) -> None:
    if not scan_timeout_is_valid(timeout_seconds):
        raise ValueError("worker timeout must be in [1, 300]")
    if not scan_saved_limit_is_valid(max_saved):
        raise ValueError("scan saved-evidence limit must be in [1, 64]")


def _materialize_finding(
    root: Path,
    index: int,
    snapshot: discovery.Snapshot,
    environment: EnvironmentEvidence,
    versions: tuple[EngineVersion, ...],
    timeout: int,
    evaluation: FileEvaluation,
) -> Mapping[str, object]:
    children = root / "public" / "findings"
    pending = children / f".pending-{index}"
    record = bundle.build_finding(
        pending,
        environment=environment,
        source_path=snapshot.relative_path,
        input_payload=snapshot.path.read_bytes(),
        engines=versions,
        timeout_seconds=timeout,
        outcomes=evaluation.outcomes,
        groups=evaluation.grouped.groups,
        comparisons=evaluation.grouped.differences,
    )
    destination = children / record.finding_id
    pending.rename(destination)
    manifest = (destination / "finding.json").read_bytes()
    return {
        "finding_id": record.finding_id,
        "source_path": record.source_path,
        "manifest": bundle.digest_data(f"findings/{record.finding_id}/finding.json", manifest),
    }


def _outcome_record(outcome: WorkerOutcome, group_id: str | None) -> records.ReaderOutcomeRecord:
    value = outcome.metadata
    return records.ReaderOutcomeRecord(
        outcome.engine,
        outcome.engine_version,
        outcome.kind,
        outcome.diagnostic_kind,
        outcome.detail,
        outcome.stderr,
        outcome.stderr_truncated,
        None if value is None else value.row_count,
        None if value is None else value.column_count,
        None if value is None else value.schema_sha256,
        None if value is None else value.sha256,
        None if value is None else value.byte_count,
        group_id,
    )


def _ensure_absent(destination: Path) -> None:
    try:
        require_destination_absent(destination)
    except DestinationExistsError as error:
        raise discovery.ScanConfigurationError(
            "OUTPUT_EXISTS", "output path already exists"
        ) from error
    except OSError as error:
        raise discovery.ScanConfigurationError(
            "OUTPUT_ERROR", "output path could not be inspected"
        ) from error


def _open_scan_staging(stack: ExitStack, destination: Path) -> Path:
    try:
        return stack.enter_context(staging_directory(destination, suffix="-scan"))
    except StagingError as error:
        raise discovery.ScanConfigurationError(
            "OUTPUT_ERROR", "output path could not be prepared"
        ) from error
