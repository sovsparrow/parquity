from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Protocol, cast

import pyarrow as pa

from .types import Field, Kind, TypeSpec

if TYPE_CHECKING:
    from ..model import Case


class _ArrayFactory(Protocol):
    def __call__(
        self,
        values: Sequence[object],
        **options: pa.DataType,
    ) -> pa.Array[pa.Scalar[pa.DataType]]: ...


class _PyArrowModule(Protocol):
    array: _ArrayFactory


class _TimestampFactory(Protocol):
    def __call__(self, unit: str, tz: str | None = None) -> pa.DataType: ...


class _MapFactory(Protocol):
    def __call__(
        self,
        key_type: pa.DataType | pa.Field[pa.DataType],
        item_type: pa.DataType | pa.Field[pa.DataType],
        keys_sorted: bool = False,
    ) -> pa.DataType: ...


class _ToPyList(Protocol):
    def to_pylist(self) -> list[object]: ...


class _CombineChunks(Protocol):
    def combine_chunks(self) -> object: ...


class _ArrayView(Protocol):
    @property
    def offset(self) -> int: ...

    @property
    def type(self) -> pa.DataType: ...

    def cast(self, target_type: pa.DataType) -> object: ...

    def is_null(self) -> object: ...

    def __len__(self) -> int: ...


class _ListArrayView(_ArrayView, Protocol):
    @property
    def offsets(self) -> object: ...

    @property
    def values(self) -> object: ...


class _MapArrayView(_ArrayView, Protocol):
    @property
    def offsets(self) -> object: ...

    @property
    def keys(self) -> object: ...

    @property
    def items(self) -> object: ...


class _StructArrayView(_ArrayView, Protocol):
    def field(self, index: int) -> object: ...


class _FixedListType(Protocol):
    list_size: int


_PYARROW = cast(_PyArrowModule, cast(object, pa))
_TIMESTAMP = cast(_TimestampFactory, cast(object, pa.timestamp))
_MAP = cast(_MapFactory, cast(object, pa.map_))


def case_to_arrow(case: Case) -> pa.Table:
    schema = pa.schema([field_to_arrow(field) for field in case.fields])
    columns: list[pa.Array[pa.Scalar[pa.DataType]]] = []
    for index, field in enumerate(case.fields):
        values = [_storage_value(field.type_spec, row[index]) for row in case.rows]
        storage = _PYARROW.array(values, type=_storage_type(field.type_spec))
        target = type_to_arrow(field.type_spec)
        columns.append(storage if storage.type == target else storage.cast(target))
    return pa.Table.from_arrays(columns, schema=schema)


def arrow_to_rows(
    table: pa.Table, fields: tuple[Field, ...] | None = None
) -> tuple[tuple[object, ...], ...]:
    if fields is not None and len(fields) != table.num_columns:
        raise ValueError("field count does not match observed table")
    columns = tuple(
        _column_values(table, index, None if fields is None else fields[index].type_spec)
        for index in range(table.num_columns)
    )
    return tuple(
        tuple(column[row_index] for column in columns) for row_index in range(table.num_rows)
    )


def field_to_arrow(field: Field) -> pa.Field[pa.DataType]:
    return pa.field(field.name, type_to_arrow(field.type_spec), nullable=field.nullable)


def type_to_arrow(spec: TypeSpec) -> pa.DataType:
    scalar = _scalar_arrow_type(spec)
    if scalar is not None:
        return scalar
    if spec.kind is Kind.TIMESTAMP:
        return _TIMESTAMP(cast(str, spec.unit), tz=spec.timezone)
    if spec.kind is Kind.DECIMAL128:
        return pa.decimal128(cast(int, spec.precision), cast(int, spec.scale))
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item_type = cast(TypeSpec, spec.item)
        item = pa.field("item", type_to_arrow(item_type), nullable=spec.item_nullable)
        if spec.size is not None:
            return pa.list_(item, list_size=spec.size)
        return pa.list_(item)
    if spec.kind is Kind.STRUCT:
        return pa.struct([field_to_arrow(field) for field in spec.fields])
    key = pa.field("key", type_to_arrow(cast(TypeSpec, spec.key)), nullable=False)
    value = pa.field(
        "value", type_to_arrow(cast(TypeSpec, spec.value)), nullable=spec.value_nullable
    )
    return _MAP(key, value)


def _scalar_arrow_type(spec: TypeSpec) -> pa.DataType | None:
    factories: dict[Kind, Callable[[], pa.DataType]] = {
        Kind.BOOL: pa.bool_,
        Kind.INT32: pa.int32,
        Kind.INT64: pa.int64,
        Kind.STRING: pa.string,
        Kind.BINARY: pa.binary,
        Kind.FLOAT32: pa.float32,
        Kind.FLOAT64: pa.float64,
        Kind.DATE32: pa.date32,
    }
    factory = factories.get(spec.kind)
    return None if factory is None else factory()


def _storage_type(spec: TypeSpec) -> pa.DataType:
    if spec.kind is Kind.DATE32:
        return pa.int32()
    if spec.kind is Kind.TIMESTAMP:
        return pa.int64()
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = pa.field(
            "item", _storage_type(cast(TypeSpec, spec.item)), nullable=spec.item_nullable
        )
        return pa.list_(item, list_size=spec.size) if spec.size is not None else pa.list_(item)
    if spec.kind is Kind.STRUCT:
        return pa.struct(
            [
                pa.field(
                    field.name,
                    _storage_type(field.type_spec),
                    nullable=field.nullable,
                )
                for field in spec.fields
            ]
        )
    if spec.kind is Kind.MAP:
        key = pa.field("key", _storage_type(cast(TypeSpec, spec.key)), nullable=False)
        value = pa.field(
            "value", _storage_type(cast(TypeSpec, spec.value)), nullable=spec.value_nullable
        )
        return _MAP(key, value)
    return type_to_arrow(spec)


def _storage_value(spec: TypeSpec, value: object) -> object:
    if value is None:
        return None
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        return [_storage_value(item, child) for child in cast(Sequence[object], value)]
    if spec.kind is Kind.STRUCT:
        data = cast(dict[str, object], value)
        return {
            field.name: _storage_value(field.type_spec, data[field.name]) for field in spec.fields
        }
    if spec.kind is Kind.MAP:
        key = cast(TypeSpec, spec.key)
        item = cast(TypeSpec, spec.value)
        return [
            (_storage_value(key, pair[0]), _storage_value(item, pair[1]))
            for pair in cast(Sequence[Sequence[object]], value)
        ]
    return value


def _column_values(table: pa.Table, index: int, spec: TypeSpec | None) -> list[object]:
    column = table.column(index)
    if spec is None:
        return _pylist(column)
    array = cast(_CombineChunks, cast(object, column)).combine_chunks()
    return _observation_values(array, spec)


def _observation_values(array: object, spec: TypeSpec) -> list[object]:
    if spec.kind is Kind.DATE32:
        return _pylist(cast(_ArrayView, array).cast(pa.int32()))
    if spec.kind is Kind.TIMESTAMP:
        return _pylist(cast(_ArrayView, array).cast(pa.int64()))
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        return _list_observation_values(cast(_ListArrayView, array), spec)
    if spec.kind is Kind.STRUCT:
        return _struct_observation_values(cast(_StructArrayView, array), spec)
    if spec.kind is Kind.MAP:
        return _map_observation_values(cast(_MapArrayView, array), spec)
    return _pylist(array)


def _list_observation_values(array: _ListArrayView, spec: TypeSpec) -> list[object]:
    children = _observation_values(array.values, cast(TypeSpec, spec.item))
    nulls = _nulls(array)
    if pa.types.is_fixed_size_list(array.type):
        size = cast(_FixedListType, cast(object, array.type)).list_size
        start = array.offset * size
        return [
            None if null else children[start + index * size : start + (index + 1) * size]
            for index, null in enumerate(nulls)
        ]
    offsets = cast(list[int], _pylist(array.offsets))
    return [
        None if null else children[offsets[index] : offsets[index + 1]]
        for index, null in enumerate(nulls)
    ]


def _struct_observation_values(array: _StructArrayView, spec: TypeSpec) -> list[object]:
    children = tuple(
        _observation_values(array.field(index), field.type_spec)
        for index, field in enumerate(spec.fields)
    )
    return [
        None
        if null
        else {field.name: children[index][row] for index, field in enumerate(spec.fields)}
        for row, null in enumerate(_nulls(array))
    ]


def _map_observation_values(array: _MapArrayView, spec: TypeSpec) -> list[object]:
    keys = _observation_values(array.keys, cast(TypeSpec, spec.key))
    items = _observation_values(array.items, cast(TypeSpec, spec.value))
    offsets = cast(list[int], _pylist(array.offsets))
    return [
        None
        if null
        else [(keys[entry], items[entry]) for entry in range(offsets[row], offsets[row + 1])]
        for row, null in enumerate(_nulls(array))
    ]


def _nulls(array: _ArrayView) -> list[bool]:
    return cast(list[bool], _pylist(array.is_null()))


def _pylist(value: object) -> list[object]:
    return cast(_ToPyList, value).to_pylist()
