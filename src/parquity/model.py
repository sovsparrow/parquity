from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from .case import Field, Kind, TypeSpec, decode_value, encode_value, normalize_value, validate_value

CASE_FORMAT = "parquity.case.v1"


@dataclass(frozen=True, slots=True)
class Case:
    fields: tuple[Field, ...]
    rows: tuple[tuple[object, ...], ...]

    def __post_init__(self) -> None:
        if not self.fields or any(
            not isinstance(cast(object, field), Field) for field in self.fields
        ):
            raise ValueError("a case requires at least one Field")
        names = [field.name for field in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("top-level field names must be unique")
        normalized: list[tuple[object, ...]] = []
        for row_index, row in enumerate(self.rows):
            if len(row) != len(self.fields):
                raise ValueError(f"row {row_index} has the wrong width")
            normalized.append(
                tuple(
                    normalize_value(field.type_spec, field.nullable, value, field.name)
                    for field, value in zip(self.fields, row, strict=True)
                )
            )
        object.__setattr__(self, "rows", tuple(normalized))

    @property
    def case_id(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_data(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def to_data(self) -> dict[str, object]:
        return {
            "format": CASE_FORMAT,
            "schema": [field.to_data() for field in self.fields],
            "rows": [
                [
                    encode_value(field.type_spec, value)
                    for field, value in zip(self.fields, row, strict=True)
                ]
                for row in self.rows
            ],
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> Case:
        if set(data) != {"format", "schema", "rows"}:
            raise ValueError("case fields are malformed")
        if data["format"] != CASE_FORMAT:
            raise ValueError(f"case format must be {CASE_FORMAT!r}")
        fields = tuple(
            Field.from_data(_mapping(value, "schema field"))
            for value in _sequence(data["schema"], "schema")
        )
        rows: list[tuple[object, ...]] = []
        for row_index, raw_row in enumerate(_sequence(data["rows"], "rows")):
            values = _sequence(raw_row, f"row {row_index}")
            if len(values) != len(fields):
                raise ValueError(f"row {row_index} has the wrong width")
            rows.append(
                tuple(
                    decode_value(field.type_spec, value)
                    for field, value in zip(fields, values, strict=True)
                )
            )
        return cls(fields, tuple(rows))

    @classmethod
    def from_json(cls, payload: str | bytes) -> Case:
        decoded = cast(
            object,
            json.loads(
                payload,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_non_finite,
                parse_float=_finite_float,
            ),
        )
        return cls.from_data(_mapping(decoded, "case"))


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> object:
    raise ValueError(f"raw JSON non-finite token is invalid: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON numeric token exceeds the finite float range")
    return parsed


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise ValueError(f"{label} must be an object")
    return cast(Mapping[str, object], raw)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise ValueError(f"{label} must be an array")
    return cast(Sequence[object], value)


__all__ = [
    "CASE_FORMAT",
    "Case",
    "Field",
    "Kind",
    "TypeSpec",
    "decode_value",
    "encode_value",
    "validate_value",
]
