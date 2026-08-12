from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import NamedTuple

from ...configuration import scan_timeout_is_valid
from ...evidence import EngineVersion, EnvironmentEvidence, is_sha256, sha256_hex
from ...evidence import json_codec as codec
from ..differences import ScanDifference
from ..discovery import portable_path
from ..limits import MAX_FILE_BYTES
from .outcomes import ReaderOutcomeKind, ReaderOutcomeRecord, reader_outcomes
from .support import ScanRecordError, digest_path, document, engine_versions, reject, text

SCAN_FINDING_FORMAT_V1 = "parquity.scan-finding.v1"
SCAN_FINDING_FORMAT_V2 = "parquity.scan-finding.v2"
SCAN_FINDING_FORMAT = SCAN_FINDING_FORMAT_V2
SCAN_FINDING_FORMATS = (SCAN_FINDING_FORMAT_V1, SCAN_FINDING_FORMAT_V2)
SCAN_ARTIFACTS = ("REPORT.md", "input.parquet", "reproduce.py", "upstream_repro.py")
_FINDING_FIELDS = "format finding_id parquity_version source engines timeout_seconds scan_status outcomes observation_groups comparisons signature_sha256 artifacts"


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
    environment: EnvironmentEvidence | None

    @property
    def format_name(self) -> str:
        return text(self.data, "format")

    @property
    def outcomes(self) -> tuple[ReaderOutcomeRecord, ...]:
        return reader_outcomes(self.data["outcomes"])

    @classmethod
    def from_json(cls, payload: bytes) -> ScanFindingRecord:
        data = document(payload, SCAN_FINDING_FORMATS)
        validate_finding(data)
        source = codec.mapping(data["source"], "source")
        engines = engine_versions(data["engines"])
        return cls(
            data,
            text(data, "finding_id"),
            text(source, "path"),
            text(source, "sha256"),
            codec.integer(source["bytes"], "input bytes"),
            engines,
            codec.integer(data["timeout_seconds"], "timeout"),
            text(data, "signature_sha256"),
            text(data, "parquity_version"),
            _environment(data, engines),
        )


def validate_finding(data: Mapping[str, object]) -> None:
    format_name = codec.string(codec.required(data, "format"), "format")
    reject(format_name not in SCAN_FINDING_FORMATS, "scan finding format is not recognized")
    fields = set(_FINDING_FIELDS.split())
    if format_name == SCAN_FINDING_FORMAT_V2:
        fields.add("environment")
    codec.require_exact_keys(data, fields, "scan finding")
    source = codec.mapping(data["source"], "source")
    codec.require_exact_keys(source, {"path", "sha256", "bytes"}, "source")
    path, digest = text(source, "path"), text(source, "sha256")
    size = codec.integer(source["bytes"], "input bytes")
    engines = engine_versions(data["engines"])
    _environment(data, engines)
    outcome_data = codec.mappings(data["outcomes"], "outcomes")
    outcomes = tuple(ReaderOutcomeRecord.from_data(item) for item in outcome_data)
    groups = codec.mappings(data["observation_groups"], "groups")
    comparisons = codec.mappings(data["comparisons"], "comparisons")
    _validate_outcomes(outcomes, engines, groups)
    _validate_comparisons(groups, comparisons)
    artifacts = tuple(digest_path(item) for item in codec.mappings(data["artifacts"], "artifacts"))
    reject(artifacts != SCAN_ARTIFACTS, "scan artifact inventory is not exact")
    timeout = codec.integer(data["timeout_seconds"], "timeout")
    identity = signature(
        path,
        digest,
        size,
        tuple(item.name for item in engines),
        timeout,
        outcome_data,
        groups,
        comparisons,
    )
    projected_id = finding_id(identity)
    bad_identity = data["signature_sha256"] != identity or data["finding_id"] != projected_id
    bad_source = not text(data, "parquity_version") or not portable_path(path)
    bad_source = bad_source or not is_sha256(digest) or not 0 <= size <= MAX_FILE_BYTES
    malformed = data["scan_status"] != "FINDING" or bad_identity or bad_source
    reject(
        malformed or not scan_timeout_is_valid(timeout),
        "scan finding identity or bounds are malformed",
    )


def _environment(
    data: Mapping[str, object], engines: tuple[EngineVersion, ...]
) -> EnvironmentEvidence | None:
    if text(data, "format") == SCAN_FINDING_FORMAT_V1:
        return None
    environment = EnvironmentEvidence.from_data(
        codec.mapping(codec.required(data, "environment"), "environment")
    )
    mismatch = (
        environment.parquity_version != text(data, "parquity_version")
        or environment.providers != engines
    )
    reject(mismatch, "scan finding environment conflicts with its evidence")
    return environment


def _validate_outcomes(
    outcomes: tuple[ReaderOutcomeRecord, ...],
    engines: tuple[EngineVersion, ...],
    groups: tuple[Mapping[str, object], ...],
) -> None:
    expected = tuple((item.name, item.version) for item in engines)
    actual_order = tuple((item.engine, item.version) for item in outcomes)
    reject(actual_order != expected, "reader outcome order is malformed")
    memberships: dict[str, list[str]] = {}
    failures = 0
    for outcome in outcomes:
        if outcome.kind is ReaderOutcomeKind.SUCCESS:
            group_id = _required_group(outcome.observation_group)
            _add_group(memberships, group_id, outcome.engine)
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
        try:
            ScanDifference.from_persisted(kind, path)
        except ValueError as error:
            raise ScanRecordError("scan comparison kind or path is malformed") from error
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
    return sha256_hex(codec.canonical_bytes(identity))


def finding_id(signature_sha256: str) -> str:
    reject(not is_sha256(signature_sha256), "scan finding signature is malformed")
    return sha256_hex(codec.canonical_bytes({"signature": signature_sha256}))


def _required_group(value: str | None) -> str:
    if value is None:
        raise ScanRecordError("reader outcome evidence is malformed")
    return value


__all__ = [
    "SCAN_ARTIFACTS",
    "SCAN_FINDING_FORMAT",
    "SCAN_FINDING_FORMATS",
    "SCAN_FINDING_FORMAT_V1",
    "SCAN_FINDING_FORMAT_V2",
    "ScanFindingRecord",
    "ScanRecordError",
    "finding_id",
    "group_members",
    "signature",
    "validate_finding",
]
