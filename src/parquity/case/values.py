from __future__ import annotations

import base64
import math
import re
import struct
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import cast

from ..evidence import json_codec
from .types import Kind, TypeSpec

_INT32 = (-(2**31), 2**31 - 1)
_INT64 = (-(2**63), 2**63 - 1)
_CONTAINER = object()


def normalize_value(spec: TypeSpec, nullable: bool, value: object, path: str) -> object:
    if value is None:
        if not nullable:
            raise ValueError(f"{path} is not nullable")
        return None
    scalar = _normalize_scalar(spec, value, path)
    if scalar is not _CONTAINER:
        return scalar
    if spec.kind is Kind.DECIMAL128:
        if not isinstance(value, Decimal):
            raise ValueError(f"{path} requires Decimal")
        decimal_text(spec, value, path)
        return value
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        return _normalize_list(spec, value, path)
    if spec.kind is Kind.STRUCT:
        return _normalize_struct(spec, value, path)
    return _normalize_map(spec, value, path)


def normalize_float(kind: Kind, value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{path} requires a number or tagged non-finite value")
    try:
        number = float(value)
        if kind is Kind.FLOAT32:
            number = struct.unpack(">f", struct.pack(">f", number))[0]
    except (OverflowError, struct.error) as error:
        raise ValueError(f"{path} exceeds {kind.value}") from error
    if math.isfinite(cast(float, value)) and not math.isfinite(number):
        raise ValueError(f"{path} exceeds {kind.value}")
    return number


def float_bits(kind: Kind, value: object) -> bytes:
    number = normalize_float(kind, value, "float")
    return struct.pack(">f" if kind is Kind.FLOAT32 else ">d", number)


def decimal_from_coefficient(coefficient: int, scale: int) -> Decimal:
    sign = int(coefficient < 0)
    digits = tuple(int(character) for character in str(abs(coefficient)))
    return Decimal((sign, digits, -scale))


def decimal_text(spec: TypeSpec, value: Decimal, path: str) -> str:
    if not value.is_finite():
        raise ValueError(f"{path} requires a finite decimal")
    sign, digits, exponent = value.as_tuple()
    scale = cast(int, spec.scale)
    if exponent != -scale:
        raise ValueError(f"{path} requires exactly {scale} fractional digits")
    coefficient = int("".join(str(digit) for digit in digits))
    if sign:
        if coefficient == 0:
            raise ValueError(f"{path} cannot be negative zero")
        coefficient = -coefficient
    if len(str(abs(coefficient))) > cast(int, spec.precision):
        raise ValueError(f"{path} exceeds decimal precision")
    return _coefficient_text(coefficient, scale)


def decimal_from_text(spec: TypeSpec, text: str) -> Decimal:
    scale = cast(int, spec.scale)
    unsigned = r"(?:0|[1-9][0-9]*)"
    pattern = rf"-?{unsigned}\.[0-9]{{{scale}}}" if scale else r"(?:0|-?[1-9][0-9]*)"
    if re.fullmatch(pattern, text) is None:
        raise ValueError("decimal tag is not canonical")
    value = Decimal(text)
    if decimal_text(spec, value, "decimal") != text:
        raise ValueError("decimal tag is not canonical")
    return value


def semantic_key_bytes(spec: TypeSpec, value: object) -> bytes:
    normalized = normalize_value(spec, False, value, "map key")
    return normalized_key_bytes(spec, normalized)


def normalized_key_bytes(spec: TypeSpec, value: object) -> bytes:
    document = {"type": spec.to_data(), "value": _semantic_value(spec, value)}
    return json_codec.canonical_bytes(document)


def map_entries(value: object, path: str) -> list[Sequence[object]]:
    entries: list[Sequence[object]] = []
    for entry in json_codec.sequence(value, path):
        pair = json_codec.sequence(entry, "map entry")
        if len(pair) != 2:
            raise ValueError(f"{path} map entries must contain two items")
        entries.append(pair)
    return entries


def _normalize_scalar(spec: TypeSpec, value: object, path: str) -> object:
    if spec.kind is Kind.BOOL:
        if not isinstance(value, bool):
            raise ValueError(f"{path} requires bool")
        return value
    if spec.kind in (Kind.INT32, Kind.DATE32):
        return _bounded_int(value, *_INT32, path)
    if spec.kind in (Kind.INT64, Kind.TIMESTAMP):
        return _bounded_int(value, *_INT64, path)
    if spec.kind is Kind.STRING:
        if not isinstance(value, str):
            raise ValueError(f"{path} requires string")
        json_codec.string(value, path)
        return value
    if spec.kind is Kind.BINARY:
        if not isinstance(value, bytes):
            raise ValueError(f"{path} requires bytes")
        return value
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        return normalize_float(spec.kind, value, path)
    return _CONTAINER


def _normalize_list(spec: TypeSpec, value: object, path: str) -> list[object]:
    items = json_codec.sequence(value, path)
    if spec.size is not None and len(items) != spec.size:
        raise ValueError(f"{path} requires exactly {spec.size} items")
    item_spec = cast(TypeSpec, spec.item)
    return [
        normalize_value(item_spec, spec.item_nullable, item, f"{path}[{index}]")
        for index, item in enumerate(items)
    ]


def _normalize_struct(spec: TypeSpec, value: object, path: str) -> dict[str, object]:
    data = json_codec.mapping(value, path)
    expected = {field.name for field in spec.fields}
    if set(data) != expected:
        raise ValueError(f"{path} has incorrect struct fields")
    return {
        field.name: normalize_value(
            field.type_spec, field.nullable, data[field.name], f"{path}.{field.name}"
        )
        for field in spec.fields
    }


def _normalize_map(spec: TypeSpec, value: object, path: str) -> list[list[object]]:
    key_spec = cast(TypeSpec, spec.key)
    value_spec = cast(TypeSpec, spec.value)
    normalized: list[list[object]] = []
    identities: set[bytes] = set()
    for index, entry in enumerate(map_entries(value, path)):
        key = normalize_value(key_spec, False, entry[0], f"{path}[{index}].key")
        item = normalize_value(value_spec, spec.value_nullable, entry[1], f"{path}[{index}].value")
        identity = normalized_key_bytes(key_spec, key)
        if identity in identities:
            raise ValueError(f"{path} contains duplicate map keys")
        identities.add(identity)
        normalized.append([key, item])
    return normalized


def _semantic_value(spec: TypeSpec, value: object) -> object:
    if value is None:
        return None
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        number = cast(float, value)
        return (
            {"$float": "nan"}
            if math.isnan(number)
            else {"$float_bits": float_bits(spec.kind, number).hex()}
        )
    if spec.kind is Kind.DECIMAL128:
        return {"$decimal": decimal_text(spec, cast(Decimal, value), "decimal")}
    if spec.kind is Kind.BINARY:
        return {"$binary": base64.b64encode(cast(bytes, value)).decode("ascii")}
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return [_semantic_value(item, child) for child in json_codec.sequence(value, "list")]
    if spec.kind is Kind.STRUCT:
        data = json_codec.mapping(value, "struct")
        return {
            field.name: _semantic_value(field.type_spec, data[field.name]) for field in spec.fields
        }
    if spec.kind is Kind.MAP:
        key_spec = cast(TypeSpec, spec.key)
        value_spec = cast(TypeSpec, spec.value)
        entries = [
            (
                normalized_key_bytes(key_spec, entry[0]),
                _semantic_value(key_spec, entry[0]),
                _semantic_value(value_spec, entry[1]),
            )
            for entry in map_entries(value, "map")
        ]
        return [[key, item] for _, key, item in sorted(entries, key=lambda entry: entry[0])]
    return value


def _bounded_int(value: object, low: int, high: int, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{path} requires an integer in [{low}, {high}]")
    return value


def _coefficient_text(coefficient: int, scale: int) -> str:
    sign = "-" if coefficient < 0 else ""
    digits = str(abs(coefficient))
    if scale == 0:
        return sign + digits
    padded = digits.rjust(scale + 1, "0")
    return f"{sign}{padded[:-scale]}.{padded[-scale:]}"


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
        return [encode_value(item, child) for child in json_codec.sequence(value, "list")]
    if spec.kind is Kind.STRUCT:
        data = json_codec.mapping(value, "struct")
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
        return [decode_value(item, child) for child in json_codec.sequence(value, "list")]
    if spec.kind is Kind.STRUCT:
        data = json_codec.mapping(value, "struct")
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
        encoded = json_codec.string(data["$binary"], "$binary")
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
            token = json_codec.string(data["$float"], "$float")
            values = {"nan": math.nan, "inf": math.inf, "-inf": -math.inf}
            if token not in values:
                raise ValueError("float tag is malformed")
            return values[token]
        return normalize_float(spec.kind, value, "float")
    if spec.kind is Kind.DECIMAL128:
        data = _tag(value, "$decimal")
        return decimal_from_text(spec, json_codec.string(data["$decimal"], "$decimal"))
    return _CONTAINER


def _tag(value: object, name: str) -> Mapping[str, object]:
    data = json_codec.mapping(value, name)
    if set(data) != {name}:
        raise ValueError(f"{name} tag is malformed")
    return data


__all__ = [
    "decimal_from_coefficient",
    "decode_value",
    "encode_value",
    "float_bits",
    "normalize_value",
    "semantic_key_bytes",
]
