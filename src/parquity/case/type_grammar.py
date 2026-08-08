from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from .types import Field, Kind, TypeSpec


class _KindFactory(Protocol):
    def __call__(self, value: str) -> Kind: ...


def validate_type_spec(spec: TypeSpec, kind_class: type[Kind]) -> None:
    if not isinstance(cast(object, spec.kind), kind_class):
        raise ValueError("kind must be a Kind")
    _boolean(spec.item_nullable, "item_nullable")
    _boolean(spec.value_nullable, "value_nullable")
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


def validate_field(field: Field, type_class: type[object]) -> None:
    if not isinstance(cast(object, field.name), str) or not field.name:
        raise ValueError(f"invalid field name: {field.name!r}")
    _utf8(field.name, "field name")
    if not field.name.isidentifier():
        raise ValueError(f"invalid field name: {field.name!r}")
    if not isinstance(cast(object, field.type_spec), type_class):
        raise ValueError("field type must be a TypeSpec")
    _boolean(field.nullable, "nullable")


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
    type_factory: type[TypeSpec],
    field_factory: type[Field],
    kind_factory: _KindFactory,
) -> TypeSpec:
    kind = kind_factory(_string(data.get("kind"), "kind"))
    exact_keys(data, _type_keys(kind.value), f"{kind.value} type")
    if kind.value in ("list", "fixed_list"):
        return type_factory(
            kind,
            item=type_from_data(
                _mapping(data["item"], "item"), type_factory, field_factory, kind_factory
            ),
            item_nullable=_boolean(data["item_nullable"], "item_nullable"),
            size=_integer(data["size"], "size") if kind.value == "fixed_list" else None,
        )
    if kind.value == "struct":
        fields = tuple(
            field_from_data(_mapping(value, "field"), type_factory, field_factory, kind_factory)
            for value in _sequence(data["fields"], "fields")
        )
        return type_factory(kind, fields=fields)
    if kind.value == "timestamp":
        timezone = data["timezone"]
        return type_factory(
            kind,
            unit=_string(data["unit"], "unit"),
            timezone=None if timezone is None else _string(timezone, "timezone"),
        )
    if kind.value == "decimal128":
        return type_factory(
            kind,
            precision=_integer(data["precision"], "precision"),
            scale=_integer(data["scale"], "scale"),
        )
    if kind.value == "map":
        return type_factory(
            kind,
            key=type_from_data(
                _mapping(data["key"], "key"), type_factory, field_factory, kind_factory
            ),
            value=type_from_data(
                _mapping(data["value"], "value"), type_factory, field_factory, kind_factory
            ),
            value_nullable=_boolean(data["value_nullable"], "value_nullable"),
        )
    return type_factory(kind)


def field_to_data(field: Field) -> dict[str, object]:
    return {"name": field.name, "nullable": field.nullable, "type": field.type_spec.to_data()}


def field_from_data(
    data: Mapping[str, object],
    type_factory: type[TypeSpec],
    field_factory: type[Field],
    kind_factory: _KindFactory,
) -> Field:
    exact_keys(data, {"name", "nullable", "type"}, "field")
    return field_factory(
        _string(data["name"], "name"),
        type_from_data(_mapping(data["type"], "type"), type_factory, field_factory, kind_factory),
        _boolean(data["nullable"], "nullable"),
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
        _utf8(spec.timezone, "timestamp timezone")
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


def _type_keys(kind: str) -> set[str]:
    branches = {
        "list": {"kind", "item", "item_nullable"},
        "fixed_list": {"kind", "item", "item_nullable", "size"},
        "struct": {"kind", "fields"},
        "timestamp": {"kind", "unit", "timezone"},
        "decimal128": {"kind", "precision", "scale"},
        "map": {"kind", "key", "value", "value_nullable"},
    }
    return branches.get(kind, {"kind"})


def exact_keys(data: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise ValueError(f"{label} fields are malformed")


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


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _integer(value: object, label: str) -> int:
    if not _is_int(value):
        raise ValueError(f"{label} must be an integer")
    return cast(int, value)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _utf8(value: str, label: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must be valid UTF-8 text") from error


def _required(value: TypeSpec | None) -> TypeSpec:
    if value is None:
        raise ValueError("required type parameter is missing")
    return value


__all__ = [
    "exact_keys",
    "field_from_data",
    "field_to_data",
    "type_from_data",
    "type_to_data",
    "validate_field",
    "validate_type_spec",
]
