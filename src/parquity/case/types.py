from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from ..evidence import json_codec

FIELD_KEYS = frozenset({"name", "nullable", "type"})
_SCALAR_TYPE_KEYS = frozenset({"kind"})
_TYPE_KEYS = {
    "list": frozenset({"kind", "item", "item_nullable"}),
    "fixed_list": frozenset({"kind", "item", "item_nullable", "size"}),
    "struct": frozenset({"kind", "fields"}),
    "timestamp": frozenset({"kind", "unit", "timezone"}),
    "decimal128": frozenset({"kind", "precision", "scale"}),
    "map": frozenset({"kind", "key", "value", "value_nullable"}),
}


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
        validate_type_spec(self)

    def to_data(self) -> dict[str, object]:
        return type_to_data(self)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> TypeSpec:
        return type_from_data(data)


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    type_spec: TypeSpec
    nullable: bool = True

    def __post_init__(self) -> None:
        validate_field(self)

    def to_data(self) -> dict[str, object]:
        return field_to_data(self)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> Field:
        return field_from_data(data)


def validate_type_spec(spec: TypeSpec) -> None:
    if not isinstance(cast(object, spec.kind), Kind):
        raise ValueError("kind must be a Kind")
    json_codec.boolean(spec.item_nullable, "item_nullable")
    json_codec.boolean(spec.value_nullable, "value_nullable")
    kind = spec.kind.value
    if kind in {"bool", "int32", "int64", "string", "binary", "float32", "float64", "date32"}:
        _require_no_parameters(spec)
    elif kind in ("list", "fixed_list"):
        _validate_list(spec)
    elif kind == "struct":
        _validate_struct(spec)
    elif kind == "timestamp":
        _validate_timestamp(spec)
    elif kind == "decimal128":
        _validate_decimal(spec)
    else:
        _validate_map(spec)


def validate_field(field: Field) -> None:
    if not isinstance(cast(object, field.name), str) or not field.name:
        raise ValueError(f"invalid field name: {field.name!r}")
    json_codec.string(field.name, "field name")
    if not field.name.isidentifier():
        raise ValueError(f"invalid field name: {field.name!r}")
    if not isinstance(cast(object, field.type_spec), TypeSpec):
        raise ValueError("field type must be a TypeSpec")
    json_codec.boolean(field.nullable, "nullable")


def type_to_data(spec: TypeSpec) -> dict[str, object]:
    kind = spec.kind.value
    data: dict[str, object] = {"kind": kind}
    if kind in ("list", "fixed_list"):
        data.update(item=_required(spec.item).to_data(), item_nullable=spec.item_nullable)
        if kind == "fixed_list":
            data["size"] = spec.size
    elif kind == "struct":
        data["fields"] = [field.to_data() for field in spec.fields]
    elif kind == "timestamp":
        data.update(unit=spec.unit, timezone=spec.timezone)
    elif kind == "decimal128":
        data.update(precision=spec.precision, scale=spec.scale)
    elif kind == "map":
        data.update(
            key=_required(spec.key).to_data(),
            value=_required(spec.value).to_data(),
            value_nullable=spec.value_nullable,
        )
    return data


def type_from_data(
    data: Mapping[str, object],
) -> TypeSpec:
    kind = Kind(json_codec.string(data.get("kind"), "kind"))
    json_codec.require_exact_keys(data, type_keys(kind.value), f"{kind.value} type")
    if kind.value in ("list", "fixed_list"):
        return TypeSpec(
            kind,
            item=type_from_data(json_codec.mapping(data["item"], "item")),
            item_nullable=json_codec.boolean(data["item_nullable"], "item_nullable"),
            size=json_codec.integer(data["size"], "size") if kind.value == "fixed_list" else None,
        )
    if kind.value == "struct":
        fields = tuple(
            field_from_data(json_codec.mapping(value, "field"))
            for value in json_codec.sequence(data["fields"], "fields")
        )
        return TypeSpec(kind, fields=fields)
    if kind.value == "timestamp":
        timezone = data["timezone"]
        return TypeSpec(
            kind,
            unit=json_codec.string(data["unit"], "unit"),
            timezone=None if timezone is None else json_codec.string(timezone, "timezone"),
        )
    if kind.value == "decimal128":
        return TypeSpec(
            kind,
            precision=json_codec.integer(data["precision"], "precision"),
            scale=json_codec.integer(data["scale"], "scale"),
        )
    if kind.value == "map":
        return TypeSpec(
            kind,
            key=type_from_data(json_codec.mapping(data["key"], "key")),
            value=type_from_data(json_codec.mapping(data["value"], "value")),
            value_nullable=json_codec.boolean(data["value_nullable"], "value_nullable"),
        )
    return TypeSpec(kind)


def field_to_data(field: Field) -> dict[str, object]:
    return {"name": field.name, "nullable": field.nullable, "type": field.type_spec.to_data()}


def field_from_data(
    data: Mapping[str, object],
) -> Field:
    json_codec.require_exact_keys(data, FIELD_KEYS, "field")
    return Field(
        json_codec.string(data["name"], "name"),
        type_from_data(json_codec.mapping(data["type"], "type")),
        json_codec.boolean(data["nullable"], "nullable"),
    )


def _require_no_parameters(spec: TypeSpec) -> None:
    values = (
        spec.item,
        spec.size,
        spec.fields,
        spec.unit,
        spec.timezone,
        spec.precision,
        spec.scale,
        spec.key,
        spec.value,
    )
    if any(value not in (None, ()) for value in values):
        raise ValueError(f"scalar {spec.kind} cannot have type parameters")
    if not spec.item_nullable or not spec.value_nullable:
        raise ValueError(f"scalar {spec.kind} cannot have type parameters")


def _validate_list(spec: TypeSpec) -> None:
    invalid = (
        spec.item is None
        or spec.fields
        or spec.unit is not None
        or spec.timezone is not None
        or spec.precision is not None
        or spec.scale is not None
        or spec.key is not None
        or spec.value is not None
        or not spec.value_nullable
    )
    if invalid:
        raise ValueError("list requires one item type and no other parameters")
    if spec.kind.value == "fixed_list":
        if not _is_int(spec.size) or not 1 <= cast(int, spec.size) <= 2**31 - 1:
            raise ValueError("fixed_list size must be in [1, 2147483647]")
    elif spec.size is not None:
        raise ValueError("list cannot declare a fixed size")


def _validate_struct(spec: TypeSpec) -> None:
    invalid = (
        spec.item is not None
        or spec.size is not None
        or not spec.item_nullable
        or spec.unit is not None
        or spec.timezone is not None
        or spec.precision is not None
        or spec.scale is not None
        or spec.key is not None
        or spec.value is not None
        or not spec.value_nullable
    )
    names = [field.name for field in spec.fields]
    if invalid or not spec.fields:
        raise ValueError("struct requires fields and no other parameters")
    if len(names) != len(set(names)):
        raise ValueError("struct field names must be unique")


def _validate_timestamp(spec: TypeSpec) -> None:
    _require_parameter_defaults(spec)
    if spec.unit not in ("s", "ms", "us", "ns"):
        raise ValueError("timestamp unit must be s, ms, us, or ns")
    if spec.timezone is not None:
        if not isinstance(cast(object, spec.timezone), str):
            raise ValueError("timestamp timezone must be a non-empty control-free label")
        json_codec.string(spec.timezone, "timestamp timezone")
        invalid = not spec.timezone or any(
            unicodedata.category(character) == "Cc" for character in spec.timezone
        )
        if invalid:
            raise ValueError("timestamp timezone must be a non-empty control-free label")


def _validate_decimal(spec: TypeSpec) -> None:
    _require_parameter_defaults(spec)
    if not _is_int(spec.precision) or not 1 <= cast(int, spec.precision) <= 38:
        raise ValueError("decimal128 precision must be in [1, 38]")
    if not _is_int(spec.scale) or not 0 <= cast(int, spec.scale) <= cast(int, spec.precision):
        raise ValueError("decimal128 scale must be in [0, precision]")


def _validate_map(spec: TypeSpec) -> None:
    invalid = (
        spec.key is None
        or spec.value is None
        or spec.item is not None
        or spec.size is not None
        or spec.fields
        or not spec.item_nullable
        or spec.unit is not None
        or spec.timezone is not None
        or spec.precision is not None
        or spec.scale is not None
    )
    if invalid:
        raise ValueError("map requires key, value, and value_nullable only")


def _require_parameter_defaults(spec: TypeSpec) -> None:
    kind = spec.kind.value
    invalid = (
        spec.item is not None
        or spec.size is not None
        or spec.fields
        or not spec.item_nullable
        or (spec.precision is not None and kind == "timestamp")
        or (spec.scale is not None and kind == "timestamp")
        or spec.key is not None
        or spec.value is not None
        or not spec.value_nullable
    )
    invalid = invalid or (
        kind == "decimal128" and (spec.unit is not None or spec.timezone is not None)
    )
    if invalid:
        raise ValueError(f"{spec.kind} has inapplicable type parameters")


def type_keys(kind: str) -> frozenset[str]:
    return _TYPE_KEYS.get(kind, _SCALAR_TYPE_KEYS)


def type_label(spec: TypeSpec) -> str:
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        child = type_label(_required(spec.item))
        nullable = "?" if spec.item_nullable else ""
        prefix = "list" if spec.kind is Kind.LIST else f"fixed_list[{spec.size}]"
        return f"{prefix}<{child}{nullable}>"
    if spec.kind is Kind.STRUCT:
        fields = ", ".join(
            f"{field.name}: {type_label(field.type_spec)}{'?' if field.nullable else ''}"
            for field in spec.fields
        )
        return f"struct<{fields}>"
    if spec.kind is Kind.TIMESTAMP:
        zone = "no timezone" if spec.timezone is None else spec.timezone
        return f"timestamp[{spec.unit}, {zone}]"
    if spec.kind is Kind.DECIMAL128:
        return f"decimal128({spec.precision}, {spec.scale})"
    if spec.kind is Kind.MAP:
        key = type_label(_required(spec.key))
        value = type_label(_required(spec.value))
        return f"map<{key}, {value}{'?' if spec.value_nullable else ''}>"
    return spec.kind.value


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _required(value: TypeSpec | None) -> TypeSpec:
    if value is None:
        raise ValueError("required type parameter is missing")
    return value


__all__ = [
    "FIELD_KEYS",
    "Field",
    "Kind",
    "TypeSpec",
    "field_from_data",
    "field_to_data",
    "type_from_data",
    "type_keys",
    "type_label",
    "type_to_data",
    "validate_field",
    "validate_type_spec",
]
