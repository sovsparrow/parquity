from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import NamedTuple

from ...configuration import scan_saved_limit_is_valid, scan_timeout_is_valid
from ...evidence import EngineVersion, EnvironmentEvidence, sha256_hex
from ...evidence import json_codec as codec
from ..discovery import portable_path
from ..limits import MAX_FILE_BYTES, MAX_FILES, MAX_SOURCE_BYTES, SCAN_LIMITS
from .support import digest_path, document, engine_versions, reject, text

SCAN_RUN_FORMAT_V1 = "parquity.scan-run.v1"
SCAN_RUN_FORMAT_V2 = "parquity.scan-run.v2"
SCAN_RUN_FORMAT = SCAN_RUN_FORMAT_V2
SCAN_RUN_FORMATS = (SCAN_RUN_FORMAT_V1, SCAN_RUN_FORMAT_V2)
_RUN_FIELDS = "format scan_id parquity_version status input_kind discovery limits engines timeout_seconds stop_reason findings overflow report"


class ScanRunStatus(StrEnum):
    FINDINGS_FOUND = "FINDINGS_FOUND"
    SAVED_EVIDENCE_LIMIT_REACHED = "SAVED_EVIDENCE_LIMIT_REACHED"


_V1_SAVED_EVIDENCE_LIMIT = "FINDING_CAP_REACHED"


class ScanRunRecord(NamedTuple):
    data: Mapping[str, object]
    environment: EnvironmentEvidence | None

    @property
    def format_name(self) -> str:
        return text(self.data, "format")

    @property
    def max_saved(self) -> int:
        return saved_limit(self.data)

    @property
    def parquity_version(self) -> str:
        return text(self.data, "parquity_version")

    @classmethod
    def from_json(cls, payload: bytes) -> ScanRunRecord:
        data = document(payload, SCAN_RUN_FORMATS)
        validate_run(data)
        engines = engine_versions(data["engines"])
        return cls(data, _environment(data, engines))


def validate_run(data: Mapping[str, object]) -> None:
    format_name = codec.string(codec.required(data, "format"), "format")
    reject(format_name not in SCAN_RUN_FORMATS, "scan run format is not recognized")
    fields = set(_RUN_FIELDS.split())
    fields.add("max_findings" if format_name == SCAN_RUN_FORMAT_V1 else "max_saved")
    if format_name == SCAN_RUN_FORMAT_V2:
        fields.add("environment")
    codec.require_exact_keys(data, fields, "scan run")
    discovery = codec.mapping(data["discovery"], "discovery")
    discovery_fields = {"files", "skipped_symlinks", "total_bytes", "visited_entries"}
    codec.require_exact_keys(discovery, discovery_fields, "discovery")
    files = codec.mappings(discovery["files"], "files")
    for item in files:
        codec.require_exact_keys(item, {"path", "bytes"}, "discovered file")
    paths = tuple(text(item, "path") for item in files)
    sizes = tuple(codec.integer(item["bytes"], "bytes") for item in files)
    total_bytes = codec.integer(discovery["total_bytes"], "total bytes")
    engines = engine_versions(data["engines"])
    _environment(data, engines)
    findings = codec.mappings(data["findings"], "findings")
    for item in findings:
        codec.require_exact_keys(item, {"finding_id", "source_path", "manifest"}, "finding index")
        expected = f"findings/{text(item, 'finding_id')}/finding.json"
        reject(
            digest_path(codec.mapping(item["manifest"], "manifest")) != expected,
            "scan child reference is malformed",
        )
    status = status_from_data(text(data, "status"), format_name)
    stop_reason = status_from_data(text(data, "stop_reason"), format_name)
    input_kind = text(data, "input_kind")
    max_saved = saved_limit(data)
    finding_paths = tuple(text(item, "source_path") for item in findings)
    overflow = tuple(
        codec.string(item, "overflow path") for item in codec.sequence(data["overflow"], "overflow")
    )
    expected_status = status_for_overflow(overflow)
    ordered_findings = tuple(path for path in paths if path in finding_paths)
    reject(not findings or finding_paths != ordered_findings, "scan finding index is malformed")
    cutoff = paths.index(finding_paths[-1]) + 1
    skipped = codec.integer(discovery["skipped_symlinks"], "symlink count")
    visited = codec.integer(discovery["visited_entries"], "visited entries")
    malformed = (
        not files,
        len(files) > MAX_FILES,
        len(paths) != len(set(paths)),
        paths != tuple(sorted(paths, key=str.encode)),
        any(not portable_path(path) for path in paths),
        any(not 0 <= size <= MAX_FILE_BYTES for size in sizes),
        sum(sizes) > MAX_SOURCE_BYTES or sum(sizes) != total_bytes,
        skipped < 0,
        not scan_timeout_is_valid(codec.integer(data["timeout_seconds"], "timeout")),
        not 1 <= visited <= SCAN_LIMITS["max_visited_entries"],
        status != expected_status or stop_reason != expected_status,
        not scan_saved_limit_is_valid(max_saved) or len(findings) > max_saved,
        bool(overflow) and len(findings) != max_saved,
        overflow != (paths[cutoff:] if overflow or len(findings) == max_saved else ()),
        input_kind not in ("file", "directory"),
        input_kind == "file"
        and (len(files) != 1 or skipped != 0 or visited != 1 or "/" in paths[0]),
        input_kind == "directory" and visited < len(files) + skipped + 1,
        not text(data, "parquity_version"),
        data["limits"] != SCAN_LIMITS or data["scan_id"] != scan_id(data),
        digest_path(codec.mapping(data["report"], "report")) != "REPORT.md",
    )
    reject(any(malformed), "scan run evidence is malformed")


def scan_id(data: Mapping[str, object]) -> str:
    identity = dict(data)
    identity["scan_id"] = ""
    return sha256_hex(codec.canonical_bytes(identity))


def status_for_overflow(overflow: Sequence[object]) -> ScanRunStatus:
    return ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED if overflow else ScanRunStatus.FINDINGS_FOUND


def status_to_v1(value: ScanRunStatus) -> str:
    if value is ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED:
        return _V1_SAVED_EVIDENCE_LIMIT
    return value.value


def status_from_v1(value: str) -> ScanRunStatus:
    if value == _V1_SAVED_EVIDENCE_LIMIT:
        return ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED
    if value == ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED:
        reject(True, "scan run status is not recognized")
    try:
        return ScanRunStatus(value)
    except ValueError as error:
        raise codec.FindingValidationError("scan run status is not recognized") from error


def status_from_data(value: str, format_name: str) -> ScanRunStatus:
    if format_name == SCAN_RUN_FORMAT_V1:
        return status_from_v1(value)
    try:
        return ScanRunStatus(value)
    except ValueError as error:
        raise codec.FindingValidationError("scan run status is not recognized") from error


def saved_limit(data: Mapping[str, object]) -> int:
    key = "max_findings" if text(data, "format") == SCAN_RUN_FORMAT_V1 else "max_saved"
    return codec.integer(codec.required(data, key), "saved-evidence limit")


def _environment(
    data: Mapping[str, object], engines: tuple[EngineVersion, ...]
) -> EnvironmentEvidence | None:
    if text(data, "format") == SCAN_RUN_FORMAT_V1:
        return None
    environment = EnvironmentEvidence.from_data(
        codec.mapping(codec.required(data, "environment"), "environment")
    )
    mismatch = (
        environment.parquity_version != text(data, "parquity_version")
        or environment.providers != engines
    )
    reject(mismatch, "scan run environment conflicts with its evidence")
    return environment


__all__ = [
    "SCAN_RUN_FORMAT",
    "SCAN_RUN_FORMATS",
    "SCAN_RUN_FORMAT_V1",
    "SCAN_RUN_FORMAT_V2",
    "ScanRunRecord",
    "ScanRunStatus",
    "saved_limit",
    "scan_id",
    "status_for_overflow",
    "status_from_data",
    "status_from_v1",
    "status_to_v1",
    "validate_run",
]
