from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Protocol, cast

import pyarrow as pa

from .arrow_bridge import arrow_to_rows
from .comparison_values import value_mismatch
from .model import Case, Field, Kind, TypeSpec
from .result_evidence import DifferenceEvidence
from .verdicts import ComparisonResult, Verdict

SchemaMismatch = tuple[str, str, DifferenceEvidence]


class _SchemaFields(Protocol):
    def __iter__(self) -> Iterator[pa.Field[pa.DataType]]: ...


class _ListType(Protocol):
    @property
    def value_field(self) -> pa.Field[pa.DataType]: ...


class _StructType(Protocol):
    @property
    def num_fields(self) -> int: ...

    def field(self, index: int) -> pa.Field[pa.DataType]: ...


class _MapType(Protocol):
    @property
    def key_field(self) -> pa.Field[pa.DataType]: ...

    @property
    def item_field(self) -> pa.Field[pa.DataType]: ...


class _TypePredicate(Protocol):
    def __call__(self, data_type: pa.DataType) -> bool: ...


class _ArrowTypes(Protocol):
    is_string_view: _TypePredicate
    is_binary_view: _TypePredicate


_ARROW_TYPES = cast(_ArrowTypes, cast(object, pa.types))


class _TimestampFactory(Protocol):
    def __call__(self, unit: str, tz: str | None = None) -> pa.DataType: ...


_TIMESTAMP = cast(_TimestampFactory, cast(object, pa.timestamp))


def compare_case(case: Case, actual: pa.Table) -> ComparisonResult:
    expected_names = [field.name for field in case.fields]
    if actual.column_names != expected_names:
        return ComparisonResult(
            Verdict.SCHEMA_MISMATCH,
            "$schema",
            f"expected columns {expected_names!r}, got {actual.column_names!r}",
            _difference(_json(expected_names), _json(actual.column_names)),
        )
    observed_fields = cast(_SchemaFields, actual.schema)
    for expected, observed in zip(case.fields, observed_fields, strict=True):
        mismatch = _field_mismatch(expected, observed, f"$schema.{expected.name}")
        if mismatch is not None:
            return ComparisonResult(Verdict.SCHEMA_MISMATCH, *mismatch)
    if actual.num_rows != len(case.rows):
        return ComparisonResult(
            Verdict.ROW_COUNT_MISMATCH,
            "$rows",
            f"expected {len(case.rows)} rows, got {actual.num_rows}",
            _difference(str(len(case.rows)), str(actual.num_rows)),
        )
    observed_rows = arrow_to_rows(actual, case.fields)
    for row_index, (expected_row, observed_row) in enumerate(
        zip(case.rows, observed_rows, strict=True)
    ):
        for column_index, field in enumerate(case.fields):
            path = f"$rows[{row_index}].{field.name}"
            mismatch = value_mismatch(
                field.type_spec,
                expected_row[column_index],
                observed_row[column_index],
                path,
            )
            if mismatch is not None:
                return ComparisonResult(Verdict.VALUE_MISMATCH, *mismatch)
    return ComparisonResult(Verdict.PASS, "$", "semantic schema and values match")


def _field_mismatch(
    expected: Field,
    actual: pa.Field[pa.DataType],
    path: str,
) -> SchemaMismatch | None:
    return _type_mismatch(expected.type_spec, actual.type, path)


def _type_mismatch(expected: TypeSpec, actual: pa.DataType, path: str) -> SchemaMismatch | None:
    if expected.kind in (
        Kind.BOOL,
        Kind.INT32,
        Kind.INT64,
        Kind.STRING,
        Kind.BINARY,
        Kind.FLOAT32,
        Kind.FLOAT64,
        Kind.DATE32,
    ):
        if _scalar_matches(expected.kind, actual):
            return None
        return _type_result(path, expected.kind.value, actual)
    if expected.kind in (Kind.TIMESTAMP, Kind.DECIMAL128):
        target = _parameterized_arrow_type(expected)
        return None if actual == target else _type_result(path, str(target), actual)
    return _container_type_mismatch(expected, actual, path)


def _container_type_mismatch(
    expected: TypeSpec, actual: pa.DataType, path: str
) -> SchemaMismatch | None:
    if expected.kind is Kind.LIST:
        if not (pa.types.is_list(actual) or pa.types.is_large_list(actual)):
            return _type_result(path, "list", actual)
        list_type = cast(_ListType, actual)
        return _list_item_mismatch(expected, list_type.value_field, path)
    if expected.kind is Kind.FIXED_LIST:
        if not (
            pa.types.is_list(actual)
            or pa.types.is_large_list(actual)
            or pa.types.is_fixed_size_list(actual)
        ):
            return _type_result(path, "fixed_list", actual)
        list_type = cast(_ListType, actual)
        return _list_item_mismatch(expected, list_type.value_field, path)
    if expected.kind is Kind.STRUCT:
        if not pa.types.is_struct(actual):
            return _type_result(path, "struct", actual)
        return _struct_mismatch(expected, cast(_StructType, actual), path)
    if not pa.types.is_map(actual):
        return _type_result(path, "map", actual)
    map_type = cast(_MapType, actual)
    key_mismatch = _type_mismatch(
        cast(TypeSpec, expected.key), map_type.key_field.type, f"{path}.key"
    )
    if key_mismatch is not None:
        return key_mismatch
    return _type_mismatch(cast(TypeSpec, expected.value), map_type.item_field.type, f"{path}.value")


def _parameterized_arrow_type(spec: TypeSpec) -> pa.DataType:
    if spec.kind is Kind.TIMESTAMP:
        return _TIMESTAMP(cast(str, spec.unit), tz=spec.timezone)
    return pa.decimal128(cast(int, spec.precision), cast(int, spec.scale))


def _struct_mismatch(expected: TypeSpec, actual: _StructType, path: str) -> SchemaMismatch | None:
    if actual.num_fields != len(expected.fields):
        expected_count = str(len(expected.fields))
        observed_count = str(actual.num_fields)
        return path, "struct field count differs", _difference(expected_count, observed_count)
    for index, expected_field in enumerate(expected.fields):
        actual_field = actual.field(index)
        child_path = f"{path}.{expected_field.name}"
        if actual_field.name != expected_field.name:
            detail = f"expected field {expected_field.name}, got {actual_field.name}"
            return (
                child_path,
                detail,
                _difference(_json(expected_field.name), _json(actual_field.name)),
            )
        mismatch = _field_mismatch(expected_field, actual_field, child_path)
        if mismatch is not None:
            return mismatch
    return None


def _scalar_matches(kind: Kind, actual: pa.DataType) -> bool:
    if kind is Kind.BOOL:
        return pa.types.is_boolean(actual)
    if kind is Kind.INT32:
        return pa.types.is_int32(actual)
    if kind is Kind.INT64:
        return pa.types.is_int64(actual)
    if kind is Kind.FLOAT32:
        return pa.types.is_float32(actual)
    if kind is Kind.FLOAT64:
        return pa.types.is_float64(actual)
    if kind is Kind.DATE32:
        return pa.types.is_date32(actual)
    if kind is Kind.STRING:
        return (
            pa.types.is_string(actual)
            or pa.types.is_large_string(actual)
            or _ARROW_TYPES.is_string_view(actual)
        )
    if kind is Kind.BINARY:
        return (
            pa.types.is_binary(actual)
            or pa.types.is_large_binary(actual)
            or _ARROW_TYPES.is_binary_view(actual)
        )
    return False


def _list_item_mismatch(
    expected: TypeSpec,
    actual_item: pa.Field[pa.DataType],
    path: str,
) -> SchemaMismatch | None:
    item_type = cast(TypeSpec, expected.item)
    item_path = f"{path}[]"
    return _type_mismatch(item_type, actual_item.type, item_path)


def _type_result(path: str, expected: str, actual: pa.DataType) -> SchemaMismatch:
    observed = str(actual)
    return path, f"expected {expected}, got {observed}", _difference(expected, observed)


def _difference(expected: str, observed: str) -> DifferenceEvidence:
    return DifferenceEvidence(expected, observed)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
