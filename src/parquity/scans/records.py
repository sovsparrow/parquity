from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import NamedTuple, cast

from ..findings import json_codec as codec
from ..verdicts import EngineVersion
from . import discovery as discovery_rules
from .discovery import MAX_FILE_BYTES, MAX_FILES, MAX_SOURCE_BYTES, portable_path

SCAN_FINDING_FORMAT = "parquity.scan-finding.v1"
SCAN_RUN_FORMAT = "parquity.scan-run.v1"
SCAN_ARTIFACTS = ("REPORT.md", "input.parquet", "reproduce.py", "upstream_repro.py")
MAX_RETAINED_INPUT_BYTES = 512 * 1024 * 1024
MAX_OBSERVATION_BYTES = 256 * 1024 * 1024
SCAN_LIMITS = {
    "max_files": MAX_FILES,
    "max_file_bytes": MAX_FILE_BYTES,
    "max_source_bytes": MAX_SOURCE_BYTES,
    "max_visited_entries": discovery_rules.MAX_VISITED_ENTRIES,
    "max_observation_bytes": MAX_OBSERVATION_BYTES,
    "max_retained_input_bytes": MAX_RETAINED_INPUT_BYTES,
    "max_stdout_bytes": 16 * 1024,
    "max_stderr_bytes": 64 * 1024,
}
ScanRecordError = codec.FindingValidationError
_FINDING_FIELDS = "format finding_id parquity_version source engines timeout_seconds scan_status outcomes observation_groups comparisons signature_sha256 artifacts"
_OUTCOME_FIELDS = "engine version kind diagnostic_kind detail stderr stderr_truncated row_count column_count schema_sha256 ipc_sha256 ipc_bytes observation_group"
_RUN_FIELDS = "format scan_id parquity_version status input_kind discovery limits engines timeout_seconds max_findings stop_reason findings overflow report"
_INDEX = r"(?:0|[1-9][0-9]*)"
_COMPARISON_PATHS = {
    "SCHEMA_DIFFERENCE": re.compile(rf"\$\.schema(?:\.fields\[{_INDEX}\])?"),
    "ROW_COUNT_DIFFERENCE": re.compile(r"\$\.rows"),
    "VALUE_DIFFERENCE": re.compile(rf"\$\.rows(?:\[{_INDEX}\]\.columns\[{_INDEX}\])?"),
}


class ReaderOutcomeRecord(NamedTuple):
    engine: str
    version: str
    kind: str
    diagnostic_kind: str
    detail: str
    stderr: str
    stderr_truncated: bool
    row_count: int | None = None
    column_count: int | None = None
    schema_sha256: str | None = None
    ipc_sha256: str | None = None
    ipc_bytes: int | None = None
    observation_group: str | None = None

    def to_data(self) -> dict[str, object]:
        return cast(dict[str, object], self._asdict())


class ScanFindingRecord(NamedTuple):
    data: Mapping[str, object]
    finding_id: str
    source_path: str
    input_sha256: str
    input_bytes: int
    engines: tuple[EngineVersion, ...]
    timeout_seconds: int
    signature_sha256: str
    parquity_version: str

    @classmethod
    def from_json(cls, payload: bytes) -> ScanFindingRecord:
        data = document(payload, SCAN_FINDING_FORMAT)
        validate_finding(data)
        source = codec.mapping(data["source"], "source")
        return cls(
            data,
            text(data, "finding_id"),
            text(source, "path"),
            text(source, "sha256"),
            codec.integer(source["bytes"], "input bytes"),
            engine_versions(data["engines"]),
            codec.integer(data["timeout_seconds"], "timeout"),
            text(data, "signature_sha256"),
            text(data, "parquity_version"),
        )


class ScanRunRecord(NamedTuple):
    data: Mapping[str, object]


def validate_finding(data: Mapping[str, object]) -> None:
    codec.require_exact_keys(data, set(_FINDING_FIELDS.split()), "scan finding")
    source = codec.mapping(data["source"], "source")
    codec.require_exact_keys(source, {"path", "sha256", "bytes"}, "source")
    path, digest = text(source, "path"), text(source, "sha256")
    size = codec.integer(source["bytes"], "input bytes")
    engines = engine_versions(data["engines"])
    outcomes = mappings(data["outcomes"], "outcomes")
    groups = mappings(data["observation_groups"], "groups")
    comparisons = mappings(data["comparisons"], "comparisons")
    _validate_outcomes(outcomes, engines, groups)
    _validate_comparisons(groups, comparisons)
    artifacts = tuple(digest_path(item) for item in mappings(data["artifacts"], "artifacts"))
    reject(artifacts != SCAN_ARTIFACTS, "scan artifact inventory is not exact")
    timeout = codec.integer(data["timeout_seconds"], "timeout")
    identity = signature(
        path, digest, size, tuple(x.name for x in engines), timeout, outcomes, groups, comparisons
    )
    finding_id = hashlib.sha256(canonical_bytes({"signature": identity})).hexdigest()
    bad_identity = data["signature_sha256"] != identity or data["finding_id"] != finding_id
    bad_source = not text(data, "parquity_version") or not portable_path(path)
    bad_source = bad_source or not valid_digest(digest) or not 0 <= size <= MAX_FILE_BYTES
    malformed = data["scan_status"] != "FINDING" or bad_identity or bad_source
    reject(malformed or not 1 <= timeout <= 300, "scan finding identity or bounds are malformed")


def validate_run(data: Mapping[str, object]) -> None:
    codec.require_exact_keys(data, set(_RUN_FIELDS.split()), "scan run")
    discovery = codec.mapping(data["discovery"], "discovery")
    discovery_fields = {"files", "skipped_symlinks", "total_bytes", "visited_entries"}
    codec.require_exact_keys(discovery, discovery_fields, "discovery")
    files = mappings(discovery["files"], "files")
    for item in files:
        codec.require_exact_keys(item, {"path", "bytes"}, "discovered file")
    paths = tuple(text(item, "path") for item in files)
    sizes = tuple(codec.integer(item["bytes"], "bytes") for item in files)
    total_bytes = codec.integer(discovery["total_bytes"], "total bytes")
    engine_versions(data["engines"])
    findings = mappings(data["findings"], "findings")
    for item in findings:
        codec.require_exact_keys(item, {"finding_id", "source_path", "manifest"}, "finding index")
        expected = f"findings/{text(item, 'finding_id')}/finding.json"
        reject(
            digest_path(codec.mapping(item["manifest"], "manifest")) != expected,
            "scan child reference is malformed",
        )
    status, input_kind = text(data, "status"), text(data, "input_kind")
    cap = codec.integer(data["max_findings"], "finding cap")
    finding_paths = tuple(text(item, "source_path") for item in findings)
    overflow = tuple(
        codec.string(item, "overflow path") for item in codec.sequence(data["overflow"], "overflow")
    )
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
        not 1 <= codec.integer(data["timeout_seconds"], "timeout") <= 300,
        not 1 <= visited <= discovery_rules.MAX_VISITED_ENTRIES,
        status not in ("FINDINGS_FOUND", "FINDING_CAP_REACHED") or status != data["stop_reason"],
        not 1 <= cap <= 64 or len(findings) > cap,
        (status == "FINDING_CAP_REACHED") != bool(overflow)
        or (bool(overflow) and len(findings) != cap),
        overflow != (paths[cutoff:] if overflow or len(findings) == cap else ()),
        input_kind not in ("file", "directory"),
        input_kind == "file"
        and (len(files) != 1 or skipped != 0 or visited != 1 or "/" in paths[0]),
        input_kind == "directory" and visited < len(files) + skipped + 1,
        not text(data, "parquity_version"),
        data["limits"] != SCAN_LIMITS or data["scan_id"] != scan_id(data),
        digest_path(codec.mapping(data["report"], "report")) != "REPORT.md",
    )
    reject(any(malformed), "scan run evidence is malformed")


def _validate_outcomes(
    outcomes: tuple[Mapping[str, object], ...],
    engines: tuple[EngineVersion, ...],
    groups: tuple[Mapping[str, object], ...],
) -> None:
    expected = tuple((item.name, item.version) for item in engines)
    actual_order = tuple((text(item, "engine"), text(item, "version")) for item in outcomes)
    reject(actual_order != expected, "reader outcome order is malformed")
    memberships: dict[str, list[str]] = {}
    failures = 0
    for outcome in outcomes:
        codec.require_exact_keys(outcome, set(_OUTCOME_FIELDS.split()), "reader outcome")
        kind = text(outcome, "kind")
        evidence = tuple(outcome[key] for key in _OUTCOME_FIELDS.split()[-6:])
        success = kind == "SUCCESS" and all(value is not None for value in evidence)
        malformed = not success and (
            kind == "SUCCESS" or any(value is not None for value in evidence)
        )
        reject(malformed, "reader outcome evidence is malformed")
        reject(
            kind not in ("SUCCESS", "PROVIDER_ERROR", "TIMEOUT", "PROCESS_CRASH"),
            "reader outcome kind is malformed",
        )
        diagnostic = text(outcome, "diagnostic_kind")
        detail, stderr = text(outcome, "detail"), text(outcome, "stderr")
        bad_diagnostic = (
            not diagnostic
            or (success and (diagnostic, detail) != ("SUCCESS", ""))
            or (kind in ("TIMEOUT", "PROCESS_CRASH") and (diagnostic, detail) != (kind, stderr))
            or not isinstance(outcome["stderr_truncated"], bool)
            or len(stderr.encode()) > 64 * 1024
        )
        reject(bad_diagnostic, "reader outcome diagnostics are malformed")
        if success:
            counts = (
                codec.integer(outcome["ipc_bytes"], "IPC bytes"),
                codec.integer(outcome["row_count"], "row count"),
                codec.integer(outcome["column_count"], "column count"),
            )
            digests = (text(outcome, "ipc_sha256"), text(outcome, "schema_sha256"))
            bad_counts = any(value < 0 for value in counts) or counts[0] > MAX_OBSERVATION_BYTES
            reject(bad_counts, "observation metadata counts are invalid")
            reject(
                any(not valid_digest(value) for value in digests),
                "observation metadata digests are invalid",
            )
            group_id = text(outcome, "observation_group")
            _add_group(memberships, group_id, text(outcome, "engine"))
        else:
            failures += 1
    actual = tuple(group_members(group) for group in groups)
    expected_groups = tuple((key, tuple(value)) for key, value in memberships.items())
    incomplete = actual != expected_groups or not outcomes or (not failures and len(groups) <= 1)
    reject(incomplete, "scan record does not contain complete finding outcomes")


def _add_group(memberships: dict[str, list[str]], group_id: str, engine: str) -> None:
    if group_id not in memberships:
        reject(group_id != f"group-{len(memberships) + 1}", "observation groups are not canonical")
        memberships[group_id] = []
    memberships[group_id].append(engine)


def group_members(group: Mapping[str, object]) -> tuple[str, tuple[str, ...]]:
    codec.require_exact_keys(group, {"id", "engines"}, "observation group")
    engines = codec.sequence(group["engines"], "group engines")
    return text(group, "id"), tuple(codec.string(name, "group engine") for name in engines)


def _validate_comparisons(
    groups: tuple[Mapping[str, object], ...], comparisons: tuple[Mapping[str, object], ...]
) -> None:
    ids = tuple(text(item, "id") for item in groups)
    expected = tuple(combinations(ids, 2))
    actual: list[tuple[str, str]] = []
    for item in comparisons:
        codec.require_exact_keys(
            item, {"left_group", "right_group", "kind", "path", "detail"}, "comparison"
        )
        actual.append((text(item, "left_group"), text(item, "right_group")))
        kind, path = text(item, "kind"), text(item, "path")
        pattern = _COMPARISON_PATHS.get(kind)
        reject(
            pattern is None or pattern.fullmatch(path) is None,
            "scan comparison kind or path is malformed",
        )
        reject(len(text(item, "detail")) > 500, "comparison detail exceeds its bound")
    reject(tuple(actual) != expected, "scan comparisons are not complete")


def signature(
    path: str,
    digest: str,
    size: int,
    engines: tuple[str, ...],
    timeout: int,
    outcomes: Sequence[Mapping[str, object]],
    groups: Sequence[Mapping[str, object]],
    comparisons: Sequence[Mapping[str, object]],
) -> str:
    normalized: list[dict[str, object]] = []
    for outcome in outcomes:
        value = dict(outcome)
        value.pop("version")
        normalized.append(value)
    identity = {
        "source": {"path": path, "sha256": digest, "bytes": size},
        "engines": list(engines),
        "timeout_seconds": timeout,
        "outcomes": normalized,
        "observation_groups": list(groups),
        "comparisons": list(comparisons),
    }
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()


def scan_id(data: Mapping[str, object]) -> str:
    identity = dict(data)
    identity["scan_id"] = ""
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()


def digest_path(data: Mapping[str, object]) -> str:
    codec.require_exact_keys(data, {"path", "sha256", "bytes"}, "digest")
    malformed = not valid_digest(text(data, "sha256")) or codec.integer(data["bytes"], "bytes") < 0
    reject(malformed, "artifact digest is malformed")
    path = text(data, "path")
    reject(not portable_path(path), "artifact path is malformed")
    return path


def engine_versions(value: object) -> tuple[EngineVersion, ...]:
    data = mappings(value, "engines")
    for item in data:
        codec.require_exact_keys(item, {"name", "version"}, "engine version")
    result = tuple(EngineVersion(text(item, "name"), text(item, "version")) for item in data)
    reject(
        not result or len({item.name for item in result}) != len(result),
        "engine selection is malformed",
    )
    return result


def document(payload: bytes, format_name: str) -> Mapping[str, object]:
    try:
        data = codec.mapping(codec.decode(payload), "scan manifest")
    except (TypeError, ValueError) as error:
        raise ScanRecordError("scan manifest is malformed") from error
    malformed = data.get("format") != format_name or canonical_bytes(data) != payload
    reject(malformed, "scan manifest format or canonical bytes are invalid")
    return data


def mappings(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    return tuple(codec.mapping(item, label) for item in codec.sequence(value, label))


def text(data: Mapping[str, object], key: str) -> str:
    return codec.string(data[key], key)


def canonical_bytes(value: object) -> bytes:
    return codec.canonical_bytes(value)


def valid_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def reject(condition: bool, detail: str) -> None:
    if condition:
        raise ScanRecordError(detail)
