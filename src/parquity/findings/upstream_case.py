from __future__ import annotations

import math
from decimal import Decimal
from typing import cast

from ..model import Case, Field, Kind, TypeSpec


def field_expression(field: Field) -> str:
    return (
        f"pa.field({field.name!r}, {_type_expression(field.type_spec)}, "
        f"nullable={field.nullable!r})"
    )


def rows_source(case: Case) -> str:
    if not _has_extended_types(case):
        return repr(_row_dicts(case))
    rows = [
        "{"
        + ", ".join(
            f"{field.name!r}: {_value_expression(field.type_spec, value)}"
            for field, value in zip(case.fields, row, strict=True)
        )
        + "}"
        for row in case.rows
    ]
    return "[" + ", ".join(rows) + "]"


def table_lines(case: Case) -> list[str]:
    if not _has_temporal(case):
        return ["TABLE = pa.Table.from_pylist(ROWS, schema=SCHEMA)"]
    storage = ", ".join(_storage_field_expression(field) for field in case.fields)
    return [
        f"STORAGE_SCHEMA = pa.schema([{storage}])",
        "TABLE = pa.Table.from_pylist(ROWS, schema=STORAGE_SCHEMA).cast(SCHEMA)",
    ]


def contains(case: Case, kind: Kind) -> bool:
    return any(_contains_type(field.type_spec, {kind}) for field in case.fields)


def _type_expression(spec: TypeSpec) -> str:
    scalar = {
        Kind.BOOL: "pa.bool_()",
        Kind.INT32: "pa.int32()",
        Kind.INT64: "pa.int64()",
        Kind.STRING: "pa.string()",
        Kind.BINARY: "pa.binary()",
        Kind.FLOAT32: "pa.float32()",
        Kind.FLOAT64: "pa.float64()",
        Kind.DATE32: "pa.date32()",
    }
    if spec.kind in scalar:
        return scalar[spec.kind]
    if spec.kind is Kind.TIMESTAMP:
        return f"pa.timestamp({spec.unit!r}, tz={spec.timezone!r})"
    if spec.kind is Kind.DECIMAL128:
        return f"pa.decimal128({spec.precision}, {spec.scale})"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        field = f"pa.field('item', {_type_expression(item)}, nullable={spec.item_nullable!r})"
        return (
            f"pa.list_({field}, list_size={spec.size})"
            if spec.size is not None
            else f"pa.list_({field})"
        )
    if spec.kind is Kind.STRUCT:
        fields = ", ".join(field_expression(field) for field in spec.fields)
        return f"pa.struct([{fields}])"
    key = _type_expression(cast(TypeSpec, spec.key))
    value = _type_expression(cast(TypeSpec, spec.value))
    return (
        f"pa.map_(pa.field('key', {key}, nullable=False), "
        f"pa.field('value', {value}, nullable={spec.value_nullable!r}))"
    )


def _value_expression(spec: TypeSpec, value: object) -> str:
    if value is None:
        return "None"
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        number = cast(float, value)
        if math.isnan(number):
            return "float('nan')"
        if math.isinf(number):
            return "float('inf')" if number > 0 else "float('-inf')"
    if spec.kind is Kind.DECIMAL128:
        return f"Decimal({str(cast(Decimal, value))!r})"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return (
            "["
            + ", ".join(_value_expression(item, child) for child in cast(list[object], value))
            + "]"
        )
    if spec.kind is Kind.STRUCT:
        data = cast(dict[str, object], value)
        return (
            "{"
            + ", ".join(
                f"{field.name!r}: {_value_expression(field.type_spec, data[field.name])}"
                for field in spec.fields
            )
            + "}"
        )
    if spec.kind is Kind.MAP:
        key = cast(TypeSpec, spec.key)
        item = cast(TypeSpec, spec.value)
        return (
            "["
            + ", ".join(
                f"({_value_expression(key, pair[0])}, {_value_expression(item, pair[1])})"
                for pair in cast(list[list[object]], value)
            )
            + "]"
        )
    return repr(value)


def _row_dicts(case: Case) -> list[dict[str, object]]:
    return [
        {field.name: value for field, value in zip(case.fields, row, strict=True)}
        for row in case.rows
    ]


def _storage_field_expression(field: Field) -> str:
    return (
        f"pa.field({field.name!r}, {_storage_type_expression(field.type_spec)}, "
        f"nullable={field.nullable!r})"
    )


def _storage_type_expression(spec: TypeSpec) -> str:
    if spec.kind is Kind.DATE32:
        return "pa.int32()"
    if spec.kind is Kind.TIMESTAMP:
        return "pa.int64()"
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        field = (
            f"pa.field('item', {_storage_type_expression(item)}, nullable={spec.item_nullable!r})"
        )
        return f"pa.list_({field}, list_size={spec.size})" if spec.size else f"pa.list_({field})"
    if spec.kind is Kind.STRUCT:
        return (
            f"pa.struct([{', '.join(_storage_field_expression(field) for field in spec.fields)}])"
        )
    if spec.kind is Kind.MAP:
        key = _storage_type_expression(cast(TypeSpec, spec.key))
        value = _storage_type_expression(cast(TypeSpec, spec.value))
        return (
            f"pa.map_(pa.field('key', {key}, nullable=False), "
            f"pa.field('value', {value}, nullable={spec.value_nullable!r}))"
        )
    return _type_expression(spec)


def _has_extended_types(case: Case) -> bool:
    return any(_contains_type(field.type_spec, None) for field in case.fields)


def _has_temporal(case: Case) -> bool:
    return any(
        _contains_type(field.type_spec, {Kind.DATE32, Kind.TIMESTAMP}) for field in case.fields
    )


def _contains_type(spec: TypeSpec, selected: set[Kind] | None) -> bool:
    extended = {
        Kind.FLOAT32,
        Kind.FLOAT64,
        Kind.DATE32,
        Kind.TIMESTAMP,
        Kind.DECIMAL128,
        Kind.MAP,
    }
    if spec.kind in (extended if selected is None else selected):
        return True
    if spec.item is not None and _contains_type(spec.item, selected):
        return True
    if any(_contains_type(field.type_spec, selected) for field in spec.fields):
        return True
    return (spec.key is not None and _contains_type(spec.key, selected)) or (
        spec.value is not None and _contains_type(spec.value, selected)
    )


__all__ = ["contains", "field_expression", "rows_source", "table_lines"]
