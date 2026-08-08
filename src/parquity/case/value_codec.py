from __future__ import annotations

import base64
import math
from collections.abc import Mapping
from decimal import Decimal
from typing import cast

from .types import Kind, TypeSpec
from .values import (
    decimal_from_text,
    decimal_text,
    map_entries,
    mapping,
    normalize_float,
    sequence,
    string,
)

_CONTAINER = object()


def encode_value(spec: TypeSpec, value: object) -> object:
    if value is None:
        return None
    if spec.kind is Kind.BINARY:
        return {"$binary": base64.b64encode(cast(bytes, value)).decode("ascii")}
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        number = cast(float, value)
        if math.isnan(number):
            return {"$float": "nan"}
        if math.isinf(number):
            return {"$float": "inf" if number > 0 else "-inf"}
        return number
    if spec.kind is Kind.DECIMAL128:
        return {"$decimal": decimal_text(spec, cast(Decimal, value), "decimal")}
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return [encode_value(item, child) for child in sequence(value, "list")]
    if spec.kind is Kind.STRUCT:
        data = mapping(value, "struct")
        return {
            field.name: encode_value(field.type_spec, data[field.name]) for field in spec.fields
        }
    if spec.kind is Kind.MAP:
        key_spec = cast(TypeSpec, spec.key)
        value_spec = cast(TypeSpec, spec.value)
        return [
            [encode_value(key_spec, entry[0]), encode_value(value_spec, entry[1])]
            for entry in map_entries(value, "map")
        ]
    return value


def decode_value(spec: TypeSpec, value: object) -> object:
    if value is None:
        return None
    tagged = _decode_tagged(spec, value)
    if tagged is not _CONTAINER:
        return tagged
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return [decode_value(item, child) for child in sequence(value, "list")]
    if spec.kind is Kind.STRUCT:
        data = mapping(value, "struct")
        expected = {field.name for field in spec.fields}
        if set(data) != expected:
            raise ValueError("struct has incorrect fields")
        return {
            field.name: decode_value(field.type_spec, data[field.name]) for field in spec.fields
        }
    if spec.kind is Kind.MAP:
        key_spec = cast(TypeSpec, spec.key)
        value_spec = cast(TypeSpec, spec.value)
        return [
            [decode_value(key_spec, entry[0]), decode_value(value_spec, entry[1])]
            for entry in map_entries(value, "map")
        ]
    return value


def _decode_tagged(spec: TypeSpec, value: object) -> object:
    if spec.kind is Kind.BINARY:
        data = _tag(value, "$binary")
        encoded = string(data["$binary"], "$binary")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("binary tag is malformed") from error
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("binary tag is not canonical")
        return decoded
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        if isinstance(value, Mapping):
            data = _tag(cast(object, value), "$float")
            token = string(data["$float"], "$float")
            values = {"nan": math.nan, "inf": math.inf, "-inf": -math.inf}
            if token not in values:
                raise ValueError("float tag is malformed")
            return values[token]
        return normalize_float(spec.kind, value, "float")
    if spec.kind is Kind.DECIMAL128:
        data = _tag(value, "$decimal")
        return decimal_from_text(spec, string(data["$decimal"], "$decimal"))
    return _CONTAINER


def _tag(value: object, name: str) -> Mapping[str, object]:
    data = mapping(value, name)
    if set(data) != {name}:
        raise ValueError(f"{name} tag is malformed")
    return data


__all__ = ["decode_value", "encode_value"]
