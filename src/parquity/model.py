from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from .case import Field, Kind, TypeSpec, decode_value, encode_value, normalize_value
from .evidence import json_codec
from .evidence.digests import sha256_hex

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
        return sha256_hex(self.canonical_bytes())

    def canonical_bytes(self) -> bytes:
        return json_codec.canonical_bytes(self.to_data())

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
            Field.from_data(json_codec.mapping(value, "schema field"))
            for value in json_codec.sequence(data["schema"], "schema")
        )
        rows: list[tuple[object, ...]] = []
        for row_index, raw_row in enumerate(json_codec.sequence(data["rows"], "rows")):
            values = json_codec.sequence(raw_row, f"row {row_index}")
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
        return cls.from_data(json_codec.mapping(json_codec.decode(payload), "case"))


__all__ = [
    "CASE_FORMAT",
    "Case",
    "Field",
    "Kind",
    "TypeSpec",
    "decode_value",
    "encode_value",
]
