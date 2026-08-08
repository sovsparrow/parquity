from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import cast


class FindingValidationError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FindingValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def required(data: Mapping[str, object], key: str) -> object:
    if key not in data:
        raise FindingValidationError(f"required field is missing: {key}")
    return data[key]


def require_exact_keys(data: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise FindingValidationError(f"{label} fields are malformed")


def mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FindingValidationError(f"{label} must be an object")
    value_mapping = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in value_mapping):
        raise FindingValidationError(f"{label} must be an object")
    return cast(Mapping[str, object], value_mapping)


def sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise FindingValidationError(f"{label} must be an array")
    return cast(Sequence[object], value)


def string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise FindingValidationError(f"{label} must be a string")
    return value


def integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FindingValidationError(f"{label} must be an integer")
    return value


def optional_integer(value: object, label: str) -> int | None:
    return None if value is None else integer(value, label)


def boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise FindingValidationError(f"{label} must be a boolean")
    return value


def decode(payload: str | bytes) -> object:
    return json.loads(
        payload,
        object_pairs_hook=unique_object,
        parse_constant=_reject_constant,
    )


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def is_canonical_json(payload: bytes) -> bool:
    return payload == canonical_bytes(decode(payload))


def _reject_constant(value: str) -> object:
    raise FindingValidationError(f"raw JSON non-finite token is invalid: {value}")


__all__ = [
    "FindingValidationError",
    "boolean",
    "canonical_bytes",
    "decode",
    "integer",
    "is_canonical_json",
    "mapping",
    "optional_integer",
    "require_exact_keys",
    "required",
    "sequence",
    "string",
    "unique_object",
]
