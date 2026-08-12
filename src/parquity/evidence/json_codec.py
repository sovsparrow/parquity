from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence, Set
from typing import cast


class EvidenceValidationError(ValueError):
    pass


# Existing finding, run, and scan decoders expose this name as their public
# validation error. Keep the alias while the neutral codec owns the behavior.
FindingValidationError = EvidenceValidationError


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def required(data: Mapping[str, object], key: str) -> object:
    if key not in data:
        raise EvidenceValidationError(f"required field is missing: {key}")
    return data[key]


def require_exact_keys(data: Mapping[str, object], expected: Set[str], label: str) -> None:
    if set(data) != expected:
        raise EvidenceValidationError(f"{label} fields are malformed")


def mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EvidenceValidationError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise EvidenceValidationError(f"{label} must be an object")
    return cast(Mapping[str, object], raw)


def sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise EvidenceValidationError(f"{label} must be an array")
    return cast(Sequence[object], value)


def mappings(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    return tuple(mapping(item, label) for item in sequence(value, label))


def string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{label} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise EvidenceValidationError(f"{label} must be valid UTF-8 text") from error
    return value


def integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EvidenceValidationError(f"{label} must be an integer")
    return value


def optional_integer(value: object, label: str) -> int | None:
    return None if value is None else integer(value, label)


def boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceValidationError(f"{label} must be a boolean")
    return value


def decode(payload: str | bytes) -> object:
    return json.loads(
        payload,
        object_pairs_hook=unique_object,
        parse_constant=_reject_non_finite,
        parse_float=_finite_float,
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
    return canonical_bytes_match(payload, decode(payload))


def canonical_bytes_match(payload: bytes, value: object) -> bool:
    return payload == canonical_bytes(value)


def _reject_non_finite(value: str) -> object:
    raise EvidenceValidationError(f"raw JSON non-finite token is invalid: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EvidenceValidationError("JSON numeric token exceeds the finite float range")
    return parsed


__all__ = [
    "EvidenceValidationError",
    "FindingValidationError",
    "boolean",
    "canonical_bytes",
    "canonical_bytes_match",
    "decode",
    "integer",
    "is_canonical_json",
    "mapping",
    "mappings",
    "optional_integer",
    "require_exact_keys",
    "required",
    "sequence",
    "string",
    "unique_object",
]
