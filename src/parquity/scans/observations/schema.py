from __future__ import annotations

from typing import Protocol, cast

import pyarrow as pa


class SchemaView(Protocol):
    def field(self, index: int) -> pa.Field[pa.DataType]: ...


class _ListType(Protocol):
    @property
    def value_field(self) -> pa.Field[pa.DataType]: ...


class _FixedListType(_ListType, Protocol):
    @property
    def list_size(self) -> int: ...


class _StructType(Protocol):
    @property
    def num_fields(self) -> int: ...

    def field(self, index: int) -> pa.Field[pa.DataType]: ...


class _MapType(Protocol):
    @property
    def key_field(self) -> pa.Field[pa.DataType]: ...

    @property
    def item_field(self) -> pa.Field[pa.DataType]: ...

    @property
    def keys_sorted(self) -> bool: ...


class _DictionaryType(Protocol):
    @property
    def index_type(self) -> pa.DataType: ...

    @property
    def value_type(self) -> pa.DataType: ...

    @property
    def ordered(self) -> bool: ...


def schema_difference(left: pa.Schema, right: pa.Schema) -> tuple[str, str] | None:
    if len(left) != len(right):
        return "$.schema", f"field count {len(left)} != {len(right)}"
    left_schema = cast(SchemaView, cast(object, left))
    right_schema = cast(SchemaView, cast(object, right))
    for index in range(len(left)):
        left_field = left_schema.field(index)
        right_field = right_schema.field(index)
        if not _fields_equivalent(left_field, right_field, ignore_name=False):
            return (
                f"$.schema.fields[{index}]",
                f"{left_field!s} != {right_field!s}",
            )
    if left.metadata != right.metadata:
        return "$.schema", "schema metadata differs"
    return None


def data_types_equivalent(left: pa.DataType, right: pa.DataType) -> bool:
    if _same_string_representation(left, right) or _same_binary_representation(left, right):
        return True
    if _variable_list(left) or _variable_list(right):
        if not (_variable_list(left) and _variable_list(right)):
            return False
        return _list_children_equivalent(left, right)
    if pa.types.is_fixed_size_list(left) or pa.types.is_fixed_size_list(right):
        if not (pa.types.is_fixed_size_list(left) and pa.types.is_fixed_size_list(right)):
            return False
        left_list = cast(_FixedListType, cast(object, left))
        right_list = cast(_FixedListType, cast(object, right))
        return left_list.list_size == right_list.list_size and _list_children_equivalent(
            left, right
        )
    if pa.types.is_struct(left) or pa.types.is_struct(right):
        return _structs_equivalent(left, right)
    if pa.types.is_map(left) or pa.types.is_map(right):
        return _maps_equivalent(left, right)
    if pa.types.is_dictionary(left) or pa.types.is_dictionary(right):
        return _dictionaries_equivalent(left, right)
    return left.equals(right)


def scalar_aliases_equivalent(
    left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType]
) -> bool | None:
    if _same_string_representation(left.type, right.type) or _same_binary_representation(
        left.type, right.type
    ):
        return left.as_py() == right.as_py()
    return None


def _fields_equivalent(
    left: pa.Field[pa.DataType], right: pa.Field[pa.DataType], *, ignore_name: bool
) -> bool:
    names_match = ignore_name or left.name == right.name
    return (
        names_match
        and left.nullable == right.nullable
        and left.metadata == right.metadata
        and data_types_equivalent(left.type, right.type)
    )


def _list_children_equivalent(left: pa.DataType, right: pa.DataType) -> bool:
    left_list = cast(_ListType, cast(object, left))
    right_list = cast(_ListType, cast(object, right))
    return _fields_equivalent(left_list.value_field, right_list.value_field, ignore_name=True)


def _structs_equivalent(left: pa.DataType, right: pa.DataType) -> bool:
    if not (pa.types.is_struct(left) and pa.types.is_struct(right)):
        return False
    left_struct = cast(_StructType, cast(object, left))
    right_struct = cast(_StructType, cast(object, right))
    return left_struct.num_fields == right_struct.num_fields and all(
        _fields_equivalent(left_struct.field(index), right_struct.field(index), ignore_name=False)
        for index in range(left_struct.num_fields)
    )


def _maps_equivalent(left: pa.DataType, right: pa.DataType) -> bool:
    if not (pa.types.is_map(left) and pa.types.is_map(right)):
        return False
    left_map = cast(_MapType, cast(object, left))
    right_map = cast(_MapType, cast(object, right))
    return (
        left_map.keys_sorted == right_map.keys_sorted
        and _fields_equivalent(left_map.key_field, right_map.key_field, ignore_name=True)
        and _fields_equivalent(left_map.item_field, right_map.item_field, ignore_name=True)
    )


def _dictionaries_equivalent(left: pa.DataType, right: pa.DataType) -> bool:
    if not (pa.types.is_dictionary(left) and pa.types.is_dictionary(right)):
        return False
    left_dictionary = cast(_DictionaryType, cast(object, left))
    right_dictionary = cast(_DictionaryType, cast(object, right))
    return (
        left_dictionary.ordered == right_dictionary.ordered
        and left_dictionary.index_type.equals(right_dictionary.index_type)
        and data_types_equivalent(left_dictionary.value_type, right_dictionary.value_type)
    )


def _variable_list(value: pa.DataType) -> bool:
    return pa.types.is_list(value) or pa.types.is_large_list(value)


def _same_string_representation(left: pa.DataType, right: pa.DataType) -> bool:
    return _string_type(left) and _string_type(right)


def _same_binary_representation(left: pa.DataType, right: pa.DataType) -> bool:
    return _binary_type(left) and _binary_type(right)


def _string_type(value: pa.DataType) -> bool:
    return (
        pa.types.is_string(value)
        or pa.types.is_large_string(value)
        or pa.types.is_string_view(value)
    )


def _binary_type(value: pa.DataType) -> bool:
    return (
        pa.types.is_binary(value)
        or pa.types.is_large_binary(value)
        or pa.types.is_binary_view(value)
    )


__all__ = [
    "data_types_equivalent",
    "scalar_aliases_equivalent",
    "schema_difference",
]
