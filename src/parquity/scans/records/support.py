from __future__ import annotations

from collections.abc import Mapping

from ...evidence import EngineVersion, engine_versions_from_data, is_sha256
from ...evidence import json_codec as codec
from ..discovery import portable_path

ScanRecordError = codec.FindingValidationError


def digest_path(data: Mapping[str, object]) -> str:
    codec.require_exact_keys(data, {"path", "sha256", "bytes"}, "digest")
    malformed = not is_sha256(text(data, "sha256")) or codec.integer(data["bytes"], "bytes") < 0
    reject(malformed, "artifact digest is malformed")
    path = text(data, "path")
    reject(not portable_path(path), "artifact path is malformed")
    return path


def engine_versions(value: object) -> tuple[EngineVersion, ...]:
    result = engine_versions_from_data(value, "engines")
    names = tuple(item.name for item in result)
    reject(not names or len(names) != len(set(names)), "engine selection is malformed")
    return result


def document(payload: bytes, format_names: str | tuple[str, ...]) -> Mapping[str, object]:
    try:
        data = codec.mapping(codec.decode(payload), "scan manifest")
    except (TypeError, ValueError) as error:
        raise ScanRecordError("scan manifest is malformed") from error
    accepted = (format_names,) if isinstance(format_names, str) else format_names
    malformed = data.get("format") not in accepted or not codec.canonical_bytes_match(payload, data)
    reject(malformed, "scan manifest format or canonical bytes are invalid")
    return data


def text(data: Mapping[str, object], key: str) -> str:
    return codec.string(data[key], key)


def reject(condition: bool, detail: str) -> None:
    if condition:
        raise ScanRecordError(detail)


__all__ = [
    "ScanRecordError",
    "digest_path",
    "document",
    "engine_versions",
    "reject",
    "text",
]
