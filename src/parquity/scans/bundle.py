from __future__ import annotations

import stat
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from ..evidence import EngineVersion, EnvironmentEvidence, digest_matches, sha256_hex
from ..evidence import json_codec as codec
from ..reporting.markdown import render_evidence_report, render_run_report
from . import records, report
from .limits import SCAN_LIMITS
from .observations import (
    ObservationDifference,
    ObservationGroup,
)
from .scripts import render_reproduce, render_upstream_repro


class ScanBundleError(ValueError): ...


class ValidatedScanFinding(NamedTuple):
    record: records.ScanFindingRecord
    directory: Path


class ValidatedScanRun(NamedTuple):
    record: records.ScanRunRecord
    children: tuple[ValidatedScanFinding, ...]
    directory: Path


def digest_data(path: str, payload: bytes) -> Mapping[str, object]:
    return {"path": path, "sha256": sha256_hex(payload), "bytes": len(payload)}


def build_finding(
    directory: Path,
    *,
    environment: EnvironmentEvidence,
    source_path: str,
    input_payload: bytes,
    engines: tuple[EngineVersion, ...],
    timeout_seconds: int,
    outcomes: tuple[records.ReaderOutcomeRecord, ...],
    groups: tuple[ObservationGroup, ...],
    comparisons: tuple[ObservationDifference, ...],
) -> records.ScanFindingRecord:
    outcome_data = tuple(item.to_data() for item in outcomes)
    group_data = tuple({"id": item.group_id, "engines": list(item.engines)} for item in groups)
    comparison_data = tuple(item.to_data() for item in comparisons)
    digest = sha256_hex(input_payload)
    identity = records.signature(
        source_path,
        digest,
        len(input_payload),
        tuple(item.name for item in engines),
        timeout_seconds,
        outcome_data,
        group_data,
        comparison_data,
    )
    payloads = {
        "REPORT.md": b"",
        "input.parquet": input_payload,
        "reproduce.py": render_reproduce(),
        "upstream_repro.py": render_upstream_repro(engines),
    }
    artifacts = tuple(digest_data(name, payloads[name]) for name in records.SCAN_ARTIFACTS)
    data = {
        "format": records.SCAN_FINDING_FORMAT,
        "finding_id": records.finding_id(identity),
        "parquity_version": environment.parquity_version,
        "environment": environment.to_data(),
        "source": {"path": source_path, "sha256": digest, "bytes": len(input_payload)},
        "engines": [item.to_data() for item in engines],
        "timeout_seconds": timeout_seconds,
        "scan_status": "FINDING",
        "outcomes": list(outcome_data),
        "observation_groups": list(group_data),
        "comparisons": list(comparison_data),
        "signature_sha256": identity,
        "artifacts": list(artifacts),
    }
    provisional = records.ScanFindingRecord.from_json(records.canonical_bytes(data))
    report_payload = render_evidence_report(report.build_evidence_report_view(provisional))
    payloads["REPORT.md"] = report_payload
    data["artifacts"] = [digest_data(name, payloads[name]) for name in records.SCAN_ARTIFACTS]
    records.validate_finding(data)
    try:
        directory.mkdir(parents=True)
        for name, payload in payloads.items():
            (directory / name).write_bytes(payload)
        (directory / "finding.json").write_bytes(records.canonical_bytes(data))
    except OSError as error:
        raise ScanBundleError("scan finding could not be written") from error
    return validate_finding(directory).record


def build_run(
    directory: Path,
    *,
    environment: EnvironmentEvidence,
    input_kind: str,
    files: tuple[tuple[str, int], ...],
    skipped_symlinks: int,
    engines: tuple[EngineVersion, ...],
    timeout_seconds: int,
    max_saved: int,
    findings: tuple[Mapping[str, object], ...],
    overflow: tuple[str, ...],
    visited_entries: int,
    report_command: str | None = None,
) -> ValidatedScanRun:
    status = records.status_for_overflow(overflow).value
    findings_root = directory / "findings"
    children = tuple(
        validate_finding(findings_root / records.text(item, "finding_id")) for item in findings
    )
    data: dict[str, object] = {
        "format": records.SCAN_RUN_FORMAT,
        "scan_id": "",
        "parquity_version": environment.parquity_version,
        "environment": environment.to_data(),
        "status": status,
        "input_kind": input_kind,
        "discovery": {
            "files": [{"path": path, "bytes": size} for path, size in files],
            "skipped_symlinks": skipped_symlinks,
            "total_bytes": sum(size for _, size in files),
            "visited_entries": visited_entries,
        },
        "limits": SCAN_LIMITS,
        "engines": [item.to_data() for item in engines],
        "timeout_seconds": timeout_seconds,
        "max_saved": max_saved,
        "stop_reason": status,
        "findings": list(findings),
        "overflow": list(overflow),
        "report": digest_data("REPORT.md", b""),
    }
    data["scan_id"] = records.scan_id(data)
    provisional_record = records.ScanRunRecord.from_json(records.canonical_bytes(data))
    provisional = ValidatedScanRun(provisional_record, children, directory)
    report_payload = render_run_report(
        report.build_run_report_view(provisional, command_line=report_command)
    )
    data["report"] = digest_data("REPORT.md", report_payload)
    data["scan_id"] = ""
    data["scan_id"] = records.scan_id(data)
    try:
        (directory / "REPORT.md").write_bytes(report_payload)
        (directory / "scan.json").write_bytes(records.canonical_bytes(data))
    except OSError as error:
        raise ScanBundleError("scan run could not be written") from error
    return validate_run(directory)


def validate_finding(directory: Path) -> ValidatedScanFinding:
    try:
        _exact_directory(directory, {"finding.json", *records.SCAN_ARTIFACTS}, set())
        record = records.ScanFindingRecord.from_json((directory / "finding.json").read_bytes())
        artifacts = codec.sequence(record.data["artifacts"], "artifacts")
        for artifact in artifacts:
            digest = codec.mapping(artifact, "artifact")
            _check_digest((directory / codec.string(digest["path"], "path")).read_bytes(), digest)
        input_payload = (directory / "input.parquet").read_bytes()
        if not digest_matches(input_payload, record.input_sha256, record.input_bytes):
            raise ScanBundleError("scan input identity does not match")
        return ValidatedScanFinding(record, directory)
    except (OSError, ValueError) as error:
        raise ScanBundleError(f"scan finding validation failed: {error}") from error


def validate_run(directory: Path) -> ValidatedScanRun:
    try:
        _exact_directory(directory, {"scan.json", "REPORT.md", "findings"}, {"findings"})
        record = records.ScanRunRecord.from_json((directory / "scan.json").read_bytes())
        findings = records.mappings(record.data["findings"], "findings")
        discovery = codec.mapping(record.data["discovery"], "discovery")
        files = records.mappings(discovery["files"], "files")
        file_sizes = {
            records.text(item, "path"): codec.integer(item["bytes"], "bytes") for item in files
        }
        engines = records.engine_versions(record.data["engines"])
        timeout = codec.integer(record.data["timeout_seconds"], "timeout")
        version = codec.string(record.data["parquity_version"], "version")
        expected_child_format = (
            records.SCAN_FINDING_FORMAT_V1
            if record.format_name == records.SCAN_RUN_FORMAT_V1
            else records.SCAN_FINDING_FORMAT_V2
        )
        ids = tuple(codec.string(item["finding_id"], "finding_id") for item in findings)
        findings_root = directory / "findings"
        _exact_directory(findings_root, set(ids), set(ids))
        children = tuple(validate_finding(findings_root / finding_id) for finding_id in ids)
        for index, child in zip(findings, children, strict=True):
            manifest = codec.mapping(index["manifest"], "manifest")
            _check_digest((child.directory / "finding.json").read_bytes(), manifest)
            finding = child.record
            if (
                finding.finding_id != codec.string(index["finding_id"], "finding_id")
                or finding.source_path != codec.string(index["source_path"], "source_path")
                or finding.engines != engines
                or finding.timeout_seconds != timeout
                or finding.parquity_version != version
                or finding.format_name != expected_child_format
                or finding.environment != record.environment
                or finding.input_bytes != file_sizes[finding.source_path]
            ):
                raise ScanBundleError("scan child conflicts with its parent")
        report_payload = (directory / "REPORT.md").read_bytes()
        _check_digest(report_payload, codec.mapping(record.data["report"], "report"))
        return ValidatedScanRun(record, children, directory)
    except (OSError, ValueError) as error:
        raise ScanBundleError(f"scan run validation failed: {error}") from error


def _exact_directory(directory: Path, expected: set[str], directories: set[str]) -> None:
    status = directory.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise ScanBundleError("scan bundle directory is malformed")
    entries = {path.name: path for path in directory.iterdir()}
    if set(entries) != expected:
        raise ScanBundleError("scan bundle inventory is not exact")
    for name, path in entries.items():
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or stat.S_ISDIR(mode) != (name in directories):
            raise ScanBundleError("scan bundle entry type is malformed")


def _check_digest(payload: bytes, digest: Mapping[str, object]) -> None:
    byte_count = codec.integer(digest["bytes"], "bytes")
    sha256 = codec.string(digest["sha256"], "SHA-256")
    if not digest_matches(payload, sha256, byte_count):
        raise ScanBundleError("scan artifact digest does not match")
