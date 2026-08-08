from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .type_grammar import (
    field_from_data,
    field_to_data,
    type_from_data,
    type_to_data,
    validate_field,
    validate_type_spec,
)


class Kind(StrEnum):
    BOOL = "bool"
    INT32 = "int32"
    INT64 = "int64"
    STRING = "string"
    BINARY = "binary"
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    DATE32 = "date32"
    TIMESTAMP = "timestamp"
    DECIMAL128 = "decimal128"
    LIST = "list"
    FIXED_LIST = "fixed_list"
    STRUCT = "struct"
    MAP = "map"


@dataclass(frozen=True, slots=True)
class TypeSpec:
    kind: Kind
    item: TypeSpec | None = None
    item_nullable: bool = True
    size: int | None = None
    fields: tuple[Field, ...] = ()
    unit: str | None = None
    timezone: str | None = None
    precision: int | None = None
    scale: int | None = None
    key: TypeSpec | None = None
    value: TypeSpec | None = None
    value_nullable: bool = True

    def __post_init__(self) -> None:
        validate_type_spec(self, Kind)

    def to_data(self) -> dict[str, object]:
        return type_to_data(self)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> TypeSpec:
        return type_from_data(data, cls, Field, Kind)


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    type_spec: TypeSpec
    nullable: bool = True

    def __post_init__(self) -> None:
        validate_field(self, TypeSpec)

    def to_data(self) -> dict[str, object]:
        return field_to_data(self)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> Field:
        return field_from_data(data, TypeSpec, cls, Kind)


__all__ = ["Field", "Kind", "TypeSpec"]
