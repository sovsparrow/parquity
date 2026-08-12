from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import cast

from ..case import Kind, TypeSpec, encode_value, float_bits, normalize_value, semantic_key_bytes
from ..evidence import DifferenceEvidence, json_codec, sha256_hex

ValueMismatch = tuple[str, str, DifferenceEvidence]


def value_mismatch(
    spec: TypeSpec,
    expected: object,
    actual: object,
    path: str,
) -> ValueMismatch | None:
    if expected is None or actual is None:
        if expected is actual:
            return None
        return _mismatch(spec, expected, actual, path, f"expected {expected!r}, got {actual!r}")
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        return _list_mismatch(spec, expected, actual, path)
    if spec.kind is Kind.STRUCT:
        return _struct_mismatch(spec, expected, actual, path)
    if spec.kind is Kind.MAP:
        return _map_mismatch(spec, expected, actual, path)
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        return _float_mismatch(spec.kind, expected, actual, path)
    if spec.kind is Kind.DECIMAL128:
        return _decimal_mismatch(spec, expected, actual, path)
    if expected != actual:
        return _mismatch(spec, expected, actual, path, f"expected {expected!r}, got {actual!r}")
    return None


def _float_mismatch(
    kind: Kind, expected: object, actual: object, path: str
) -> ValueMismatch | None:
    spec = TypeSpec(kind)
    try:
        left = normalize_value(TypeSpec(kind), False, expected, path)
        right = normalize_value(TypeSpec(kind), False, actual, path)
    except ValueError:
        return _mismatch(spec, expected, actual, path, f"expected {expected!r}, got {actual!r}")
    if math.isnan(cast(float, left)) and math.isnan(cast(float, right)):
        return None
    if float_bits(kind, left) != float_bits(kind, right):
        return _mismatch(spec, expected, actual, path, f"expected {expected!r}, got {actual!r}")
    return None


def _decimal_mismatch(
    spec: TypeSpec, expected: object, actual: object, path: str
) -> ValueMismatch | None:
    if not isinstance(expected, Decimal) or not isinstance(actual, Decimal):
        return _mismatch(
            spec, expected, actual, path, f"expected decimal {expected!r}, got {actual!r}"
        )
    try:
        left = cast(Decimal, normalize_value(spec, False, expected, path))
        right = cast(Decimal, normalize_value(spec, False, actual, path))
    except ValueError:
        return _mismatch(
            spec, expected, actual, path, f"expected decimal {expected!r}, got {actual!r}"
        )
    if left.as_tuple() != right.as_tuple():
        return _mismatch(
            spec, expected, actual, path, f"expected decimal {expected!r}, got {actual!r}"
        )
    return None


def _list_mismatch(
    spec: TypeSpec, expected: object, actual: object, path: str
) -> ValueMismatch | None:
    left = _sequence(expected)
    right = _sequence(actual)
    if left is None or right is None:
        return _mismatch(spec, expected, actual, path, f"expected list value, got {actual!r}")
    if len(left) != len(right):
        detail = f"expected list length {len(left)}, got {len(right)}"
        return _mismatch(spec, expected, actual, path, detail)
    item = cast(TypeSpec, spec.item)
    for index, (expected_item, actual_item) in enumerate(zip(left, right, strict=True)):
        mismatch = value_mismatch(item, expected_item, actual_item, f"{path}[{index}]")
        if mismatch is not None:
            return mismatch
    return None


def _struct_mismatch(
    spec: TypeSpec, expected: object, actual: object, path: str
) -> ValueMismatch | None:
    left = _mapping(expected)
    right = _mapping(actual)
    if left is None or right is None:
        return _mismatch(spec, expected, actual, path, f"expected struct value, got {actual!r}")
    for field in spec.fields:
        if field.name not in right:
            expected_value = _render(field.type_spec, left[field.name])
            return (
                f"{path}.{field.name}",
                "observed struct field is missing",
                DifferenceEvidence(expected_value, "<missing>"),
            )
        mismatch = value_mismatch(
            field.type_spec,
            left[field.name],
            right[field.name],
            f"{path}.{field.name}",
        )
        if mismatch is not None:
            return mismatch
    return None


def _map_mismatch(
    spec: TypeSpec, expected: object, actual: object, path: str
) -> ValueMismatch | None:
    left_entries = _entries(expected)
    right_entries = _entries(actual)
    if left_entries is None or right_entries is None:
        return _mismatch(spec, expected, actual, path, f"expected map value, got {actual!r}")
    key_spec = cast(TypeSpec, spec.key)
    value_spec = cast(TypeSpec, spec.value)
    left = _map_index(key_spec, left_entries)
    right = _map_index(key_spec, right_entries)
    if left is None or right is None:
        return _mismatch(
            spec, expected, actual, path, "observed map contains a duplicate or invalid key"
        )
    for identity in sorted(set(left) | set(right)):
        digest = sha256_hex(identity)
        entry_path = f"{path}.entries[sha256={digest}]"
        if identity not in left:
            key = _render(key_spec, right[identity][0])
            return entry_path, "unexpected map key", DifferenceEvidence("<absent>", key)
        if identity not in right:
            key = _render(key_spec, left[identity][0])
            return entry_path, "expected map key is missing", DifferenceEvidence(key, "<missing>")
        mismatch = value_mismatch(
            value_spec,
            left[identity][1],
            right[identity][1],
            f"{entry_path}.value",
        )
        if mismatch is not None:
            return mismatch
    return None


def _map_index(
    key_spec: TypeSpec, entries: Sequence[Sequence[object]]
) -> dict[bytes, Sequence[object]] | None:
    indexed: dict[bytes, Sequence[object]] = {}
    try:
        for entry in entries:
            identity = semantic_key_bytes(key_spec, entry[0])
            if identity in indexed:
                return None
            indexed[identity] = entry
    except (IndexError, ValueError):
        return None
    return indexed


def _entries(value: object) -> Sequence[Sequence[object]] | None:
    if isinstance(value, Mapping):
        data = cast(Mapping[object, object], value)
        return tuple((key, item) for key, item in data.items())
    values = _sequence(value)
    if values is None:
        return None
    result: list[Sequence[object]] = []
    for entry in values:
        pair = _sequence(entry)
        if pair is None or len(pair) != 2:
            return None
        result.append(pair)
    return result


def _sequence(value: object) -> Sequence[object] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return None
    return cast(Sequence[object], value)


def _mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    return cast(Mapping[str, object], value)


def _mismatch(
    spec: TypeSpec,
    expected: object,
    actual: object,
    path: str,
    detail: str,
) -> ValueMismatch:
    return path, detail, DifferenceEvidence(_render(spec, expected), _render(spec, actual))


def _render(spec: TypeSpec, value: object) -> str:
    try:
        encoded = encode_value(spec, value)
        return json_codec.canonical_bytes(encoded).decode("utf-8")
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return repr(value)


__all__ = ["ValueMismatch", "value_mismatch"]
