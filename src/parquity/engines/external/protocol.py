from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypeAlias, cast

from ...evidence import json_codec as codec
from ...profiles import PROFILE_REGISTRY, OptionValue

BRIDGE_PROTOCOL = "parquity.bridge.v1"
MAX_STREAM_BYTES = 64 * 1024
MAX_KIND_LENGTH = 64
CRASH_KIND = "ExternalEngineCrash"
_KIND_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_INFO_KEYS = frozenset({"protocol", "engine", "version", "directions", "writer_profiles"})
_ERROR_KEYS = frozenset({"status", "kind", "detail"})
_DIRECTIONS = ("read", "write")

ProfileOptions: TypeAlias = Mapping[str, OptionValue]


class ExternalEngineProtocolError(RuntimeError):
    """A bridge broke the contract. This is an integration defect, not evidence."""


class ExternalEngineTimeout(RuntimeError):
    """A bridge did not answer in time.

    Deliberately not a provider failure. Exit 1 means the implementation answered and said it
    failed, which is an observation worth recording; a timeout means it never answered, so there is
    nothing to record about it. Treating the two alike would let a slow machine manufacture findings
    against an engine that did nothing wrong.
    """


@dataclass(frozen=True, slots=True)
class BridgeInfo:
    engine: str
    version: str
    reader: bool
    writer: bool
    writer_profiles: Mapping[str, ProfileOptions]


@dataclass(frozen=True, slots=True)
class BridgeFailure:
    kind: str
    detail: str


def parse_info(payload: bytes, expected_engine: str) -> BridgeInfo:
    data = _object(payload, "bridge info")
    unknown = set(data) - _INFO_KEYS
    if unknown or not {"protocol", "engine", "version", "directions"} <= set(data):
        raise ExternalEngineProtocolError("bridge info fields are malformed")
    if data["protocol"] != BRIDGE_PROTOCOL:
        raise ExternalEngineProtocolError(
            f"bridge protocol must be {BRIDGE_PROTOCOL}: {data['protocol']!r}"
        )
    engine = _text(data["engine"], "bridge engine name")
    if engine != expected_engine:
        raise ExternalEngineProtocolError(
            f"bridge reports engine {engine!r} for configured name {expected_engine!r}"
        )
    version = _text(data["version"], "bridge engine version")
    reader, writer = _directions(data["directions"])
    return BridgeInfo(
        engine, version, reader, writer, _writer_profiles(data.get("writer_profiles"))
    )


def parse_success(payload: bytes) -> None:
    data = _object(payload, "bridge response")
    if set(data) != {"status"} or data["status"] != "OK":
        raise ExternalEngineProtocolError("bridge success response is malformed")


def parse_failure(payload: bytes) -> BridgeFailure | None:
    try:
        data = _object(payload, "bridge response")
    except ExternalEngineProtocolError:
        return None
    if frozenset(data) != _ERROR_KEYS or data["status"] != "ERROR":
        return None
    kind = data["kind"]
    detail = data["detail"]
    if not isinstance(kind, str) or not isinstance(detail, str) or not kind_is_valid(kind):
        return None
    return BridgeFailure(kind, detail)


def kind_is_valid(value: str) -> bool:
    return len(value) <= MAX_KIND_LENGTH and _KIND_PATTERN.fullmatch(value) is not None


def _object(payload: bytes, label: str) -> Mapping[str, object]:
    if len(payload) > MAX_STREAM_BYTES:
        raise ExternalEngineProtocolError(f"{label} exceeds {MAX_STREAM_BYTES} bytes")
    try:
        return codec.mapping(codec.decode(payload), label)
    except (codec.EvidenceValidationError, UnicodeDecodeError, ValueError) as error:
        raise ExternalEngineProtocolError(f"{label} is not a JSON object") from error


def _mapping(value: object, label: str) -> Mapping[str, object]:
    try:
        return codec.mapping(value, label)
    except codec.EvidenceValidationError as error:
        raise ExternalEngineProtocolError(str(error)) from error


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalEngineProtocolError(f"{label} must be a non-empty string")
    return value


def _directions(value: object) -> tuple[bool, bool]:
    if not isinstance(value, list):
        raise ExternalEngineProtocolError("bridge directions must be an array")
    items = cast(list[object], value)
    selected = {item for item in items if isinstance(item, str)}
    if len(selected) != len(items) or not selected or not selected <= set(_DIRECTIONS):
        raise ExternalEngineProtocolError("bridge directions must be read, write, or both")
    return "read" in selected, "write" in selected


def _writer_profiles(value: object) -> Mapping[str, ProfileOptions]:
    if value is None:
        return {}
    declared = _mapping(value, "bridge writer profiles")
    return {name: _options(name, declared[name]) for name in declared}


def _options(name: str, value: object) -> ProfileOptions:
    if name not in PROFILE_REGISTRY:
        raise ExternalEngineProtocolError(f"bridge declares an unregistered writer profile: {name}")
    declared = _mapping(value, f"writer profile options: {name}")
    if not declared:
        raise ExternalEngineProtocolError(f"writer profile options must not be empty: {name}")
    options: dict[str, OptionValue] = {}
    for key in declared:
        option = declared[key]
        if not isinstance(option, bool | int | str):
            raise ExternalEngineProtocolError(
                f"writer profile option must be a boolean, integer, or string: {name}.{key}"
            )
        options[key] = option
    return options


__all__ = [
    "BRIDGE_PROTOCOL",
    "CRASH_KIND",
    "MAX_KIND_LENGTH",
    "MAX_STREAM_BYTES",
    "BridgeFailure",
    "BridgeInfo",
    "ExternalEngineProtocolError",
    "ExternalEngineTimeout",
    "kind_is_valid",
    "parse_failure",
    "parse_info",
    "parse_success",
]
