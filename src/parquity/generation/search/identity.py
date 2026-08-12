from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

from ...evidence import json_codec as codec
from ...profiles import WriterProfileIdentity
from ...verdicts import FailureFingerprint, Verdict


@total_ordering
@dataclass(frozen=True, slots=True, init=False)
class FindingKey:
    """Campaign-local identity used for retention, minimization, and saved slots."""

    writer: str
    reader: str
    operation: str
    verdict: Verdict
    diagnostic_kind: str
    normalized_detail_sha256: str
    location_class: str
    writer_profile: WriterProfileIdentity | None

    def __init__(self, *_: object, **__: object) -> None:
        raise TypeError("FindingKey values must be derived with finding_key()")

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, FindingKey):
            return NotImplemented
        return _finding_key_order(self) < _finding_key_order(other)


def finding_key(fingerprint: FailureFingerprint) -> FindingKey:
    key = object.__new__(FindingKey)
    object.__setattr__(key, "writer", fingerprint.writer)
    object.__setattr__(key, "reader", fingerprint.reader)
    object.__setattr__(key, "operation", fingerprint.operation)
    object.__setattr__(key, "verdict", fingerprint.verdict)
    object.__setattr__(key, "diagnostic_kind", fingerprint.diagnostic_kind)
    object.__setattr__(key, "normalized_detail_sha256", fingerprint.normalized_detail_sha256)
    object.__setattr__(key, "location_class", _location_class(fingerprint.schema_path))
    object.__setattr__(key, "writer_profile", fingerprint.writer_profile)
    return key


def _location_class(path: str) -> str:
    if path == "$":
        return "root"
    if path == "$schema":
        return "schema"
    if path == "$rows":
        return "rows"
    generated = _generated_location(path)
    if generated is not None:
        return generated
    return f"opaque:{path}"


_SCHEMA_FIELD = re.compile(r"\$schema\.field_[0-9]+")
_ROW_FIELD = re.compile(r"\$rows\[[0-9]+\]\.field_[0-9]+")
_CHILD_FIELD = re.compile(r"\.child_[0-9]+")
_LIST_ITEM = re.compile(r"(?:\[\]|\[[0-9]+\])")
_MAP_ENTRY = re.compile(r"\.entries\[sha256=[0-9a-f]{64}\]")


def _generated_location(path: str) -> str | None:
    prefix: tuple[re.Pattern[str], tuple[str, ...]]
    if path.startswith("$schema."):
        prefix = _SCHEMA_FIELD, ("schema", "field")
    elif path.startswith("$rows["):
        prefix = _ROW_FIELD, ("rows", "field")
    else:
        return None
    match = prefix[0].match(path)
    if match is None:
        return None
    parts: list[str] = list(prefix[1])
    offset = match.end()
    while offset < len(path):
        token = _structural_token(path, offset)
        if token is None:
            return None
        label, offset = token
        parts.append(label)
    return "/".join(parts)


def _structural_token(path: str, offset: int) -> tuple[str, int] | None:
    for pattern, label in (
        (_CHILD_FIELD, "field"),
        (_LIST_ITEM, "item"),
        (_MAP_ENTRY, "entry"),
    ):
        match = pattern.match(path, offset)
        if match is not None:
            return label, match.end()
    for suffix, label in ((".key", "key"), (".value", "value")):
        if path.startswith(suffix, offset):
            return label, offset + len(suffix)
    return None


def _finding_key_order(
    value: FindingKey,
) -> tuple[bool, str, str, str, str, str, str, bytes, str]:
    profile = value.writer_profile
    profile_key = b"" if profile is None else codec.canonical_bytes(profile.to_data())
    return (
        value.writer != value.reader,
        value.operation,
        value.verdict.value,
        value.writer,
        value.reader,
        value.diagnostic_kind,
        value.location_class,
        profile_key,
        value.normalized_detail_sha256,
    )


__all__ = ["FindingKey", "finding_key"]
