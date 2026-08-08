from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Mapping
from contextlib import ExitStack
from importlib import metadata
from pathlib import Path
from typing import NamedTuple, cast

from ..engines import ReaderSelection
from ..process import (
    WorkerLimitError,
    WorkerOutcome,
    WorkerProtocolError,
    WorkerUnavailableError,
    run_worker_process,
)
from ..triage.normalization import detail_sha256_v1, normalize_detail_v1
from ..verdicts import EngineVersion
from . import bundle, discovery, observations, records, replay_evidence, symptoms


class FileEvaluation(NamedTuple):
    outcomes: tuple[records.ReaderOutcomeRecord, ...]
    grouped: observations.GroupedObservations


class ScanExecution(NamedTuple):
    run: records.ScanRunRecord | None
    discovery: discovery.Discovery
    evaluated_files: int

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "status": "AGREEMENT",
            "discovered_files": len(self.discovery.files),
            "evaluated_files": self.evaluated_files,
            "skipped_symlinks": self.discovery.skipped_symlinks,
            "visited_entries": self.discovery.visited_entries,
        }
        if self.run is None:
            return data
        record = self.run.data
        data.update(
            status="RUN_PUBLISHED",
            run_status=record["status"],
            scan_id=record["scan_id"],
            finding_count=len(cast(list[object], record["findings"])),
            overflow_count=len(cast(list[object], record["overflow"])),
        )
        return data


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
        argv = [sys.executable, "-m", "parquity.worker"]
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
        if outcome.kind == "SUCCESS":
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
    max_findings: int,
) -> ScanExecution:
    _ensure_absent(destination)
    inputs = discovery.discover_input(source)
    versions = tuple(EngineVersion(name, version) for name, version in selection.reader_versions)
    parquity_version = metadata.version("parquity")
    with tempfile.TemporaryDirectory(prefix="parquity-scan-") as raw_private, ExitStack() as stack:
        private_root = Path(raw_private)
        public_root: Path | None = None
        indexes: list[Mapping[str, object]] = []
        retained_bytes = 0
        evaluated = 0
        for file_index, discovered in enumerate(inputs.files):
            snapshot = discovery.snapshot_file(discovered, private_root / "snapshot")
            evaluation = evaluate_snapshot(snapshot, selection, timeout_seconds, private_root)
            evaluated += 1
            if (
                any(item.kind != "SUCCESS" for item in evaluation.outcomes)
                or len(evaluation.grouped.groups) > 1
            ):
                retained_bytes += snapshot.byte_count
                if retained_bytes > records.MAX_RETAINED_INPUT_BYTES:
                    raise discovery.ScanConfigurationError(
                        "SCAN_LIMIT_EXCEEDED", "retained scan inputs exceed 512 MiB"
                    )
                if public_root is None:
                    public_root = Path(stack.enter_context(_staging(destination)))
                indexes.append(
                    _materialize_finding(
                        public_root,
                        file_index,
                        snapshot,
                        parquity_version,
                        versions,
                        timeout_seconds,
                        evaluation,
                    )
                )
            shutil.rmtree(snapshot.path.parent)
            if len(indexes) >= max_findings:
                break
        if not indexes:
            return ScanExecution(None, inputs, evaluated)
        overflow = tuple(item.relative_path for item in inputs.files[evaluated:])
        if public_root is None:
            raise RuntimeError("scan finding staging was not initialized")
        public = public_root / "public"
        run = bundle.build_run(
            public,
            parquity_version=parquity_version,
            input_kind=inputs.input_kind,
            files=tuple((item.relative_path, item.byte_count) for item in inputs.files),
            skipped_symlinks=inputs.skipped_symlinks,
            visited_entries=inputs.visited_entries,
            engines=versions,
            timeout_seconds=timeout_seconds,
            max_findings=max_findings,
            findings=tuple(indexes),
            overflow=overflow,
        )
        _ensure_absent(destination)
        try:
            public.rename(destination)
        except OSError as error:
            raise discovery.ScanConfigurationError(
                "OUTPUT_ERROR", "scan output could not be published"
            ) from error
        return ScanExecution(run, inputs, evaluated)


def replay_finding(
    validated: bundle.ValidatedScanFinding,
    selection: ReaderSelection,
) -> Mapping[str, object]:
    record = validated.record
    recorded_roster = tuple(item.name for item in record.engines)
    if selection.reader_names != recorded_roster:
        raise WorkerProtocolError("scan replay requires the exact recorded reader roster")
    with tempfile.TemporaryDirectory(prefix="parquity-scan-replay-") as raw_root:
        root = Path(raw_root)
        try:
            source = discovery.discover_input(validated.directory / "input.parquet").files[0]
            snapshot = discovery.snapshot_file(source, root / "snapshot")
        except discovery.ScanConfigurationError as error:
            if error.kind not in ("INVALID_INPUT", "EMPTY_INPUT"):
                raise
            raise discovery.ScanConfigurationError(
                "INPUT_DRIFT", "validated scan input changed before replay"
            ) from error
        if snapshot.sha256 != record.input_sha256:
            raise discovery.ScanConfigurationError(
                "INPUT_DRIFT", "validated scan input changed before replay"
            )
        evaluation = evaluate_snapshot(snapshot, selection, record.timeout_seconds, root)
    original = symptoms.extract(record, detail_sha256_v1)
    group_data = tuple(
        {"id": item.group_id, "engines": list(item.engines)} for item in evaluation.grouped.groups
    )
    current = symptoms.extract_evidence(
        record.finding_id,
        selection.reader_names,
        record.timeout_seconds,
        tuple(item.to_data() for item in evaluation.outcomes),
        group_data,
        tuple(item.to_data() for item in evaluation.grouped.differences),
        detail_sha256_v1,
    )
    comparison = replay_evidence.compare(original, current, normalize_detail_v1)
    current_versions = dict(selection.reader_versions)
    versions = tuple(
        {
            "engine": item.name,
            "original": item.version,
            "current": current_versions[item.name],
            "drift": item.version != current_versions[item.name],
        }
        for item in record.engines
    )
    return {
        "finding_id": record.finding_id,
        "classification": comparison.classification,
        "package_version": {
            "original": record.parquity_version,
            "current": metadata.version("parquity"),
            "drift": record.parquity_version != metadata.version("parquity"),
        },
        "version_evidence": list(versions),
        "occurrence_results": list(comparison.occurrence_results),
        "new_observations": list(comparison.new_observations),
    }


def replay_run(
    validated: bundle.ValidatedScanRun,
    selection: ReaderSelection,
) -> tuple[Mapping[str, object], ...]:
    return tuple(replay_finding(child, selection) for child in validated.children)


def _materialize_finding(
    root: Path,
    index: int,
    snapshot: discovery.Snapshot,
    parquity_version: str,
    versions: tuple[EngineVersion, ...],
    timeout: int,
    evaluation: FileEvaluation,
) -> Mapping[str, object]:
    children = root / "public" / "findings"
    pending = children / f".pending-{index}"
    record = bundle.build_finding(
        pending,
        parquity_version=parquity_version,
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
        destination.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise discovery.ScanConfigurationError(
            "OUTPUT_ERROR", "output path could not be inspected"
        ) from error
    raise discovery.ScanConfigurationError("OUTPUT_EXISTS", "output path already exists")


def _staging(destination: Path) -> tempfile.TemporaryDirectory[str]:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(
            prefix=f".{destination.name}.parquity-scan-", dir=destination.parent
        )
    except OSError as error:
        raise discovery.ScanConfigurationError(
            "OUTPUT_ERROR", "output path could not be prepared"
        ) from error
