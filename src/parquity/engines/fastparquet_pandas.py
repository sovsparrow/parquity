from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from importlib import import_module
from typing import Protocol, cast

import pyarrow as pa

from ..model import Case, Kind, TypeSpec


class _SeriesFactory(Protocol):
    def __call__(self, values: object, *, dtype: object) -> object: ...


class _ArrowDtypeFactory(Protocol):
    def __call__(self, data_type: pa.DataType) -> object: ...


class _DataFrameFactory(Protocol):
    def __call__(self, columns: Mapping[str, object]) -> object: ...


class _PandasModule(Protocol):
    Series: _SeriesFactory
    DataFrame: _DataFrameFactory
    ArrowDtype: _ArrowDtypeFactory


class _Schema(Protocol):
    def __iter__(self) -> Iterator[pa.Field[pa.DataType]]: ...


class _ListType(Protocol):
    value_field: pa.Field[pa.DataType]


class _StructType(Protocol):
    def __iter__(self) -> Iterator[pa.Field[pa.DataType]]: ...


class _MapType(Protocol):
    key_field: pa.Field[pa.DataType]
    item_field: pa.Field[pa.DataType]


_PANDAS_DTYPES = {
    Kind.BOOL: "boolean",
    Kind.INT32: "Int32",
    Kind.INT64: "Int64",
    Kind.STRING: "string[python]",
    Kind.BINARY: "object",
    Kind.FLOAT32: "Float32",
    Kind.FLOAT64: "Float64",
    Kind.DATE32: "object",
    Kind.TIMESTAMP: "object",
    Kind.DECIMAL128: "object",
    Kind.LIST: "object",
    Kind.FIXED_LIST: "object",
    Kind.STRUCT: "object",
    Kind.MAP: "object",
}
_ARROW_SCALARS: tuple[tuple[Callable[[pa.DataType], bool], Kind], ...] = (
    (pa.types.is_boolean, Kind.BOOL),
    (pa.types.is_int32, Kind.INT32),
    (pa.types.is_int64, Kind.INT64),
    (pa.types.is_string, Kind.STRING),
    (pa.types.is_large_string, Kind.STRING),
    (pa.types.is_binary, Kind.BINARY),
    (pa.types.is_large_binary, Kind.BINARY),
    (pa.types.is_float32, Kind.FLOAT32),
    (pa.types.is_float64, Kind.FLOAT64),
    (pa.types.is_date32, Kind.DATE32),
    (pa.types.is_timestamp, Kind.TIMESTAMP),
    (pa.types.is_decimal128, Kind.DECIMAL128),
)


def table_to_pandas(table: pa.Table) -> object:
    pandas = _pandas_module()
    columns: dict[str, object] = {}
    schema = cast(_Schema, cast(object, table.schema))
    for index, field in enumerate(schema):
        dtype: object = _arrow_pandas_dtype(field.type)
        column = table.column(index)
        if _requires_arrow_dtype(field.type):
            values: object = column
            dtype = pandas.ArrowDtype(field.type)
        else:
            values = cast(Callable[[], list[object]], column.to_pylist)()
        columns[field.name] = pandas.Series(values, dtype=dtype)
    return pandas.DataFrame(columns)


def frame_source_lines(case: Case) -> list[str]:
    return [
        "frame = pd.DataFrame({",
        *(
            _series_source(index, field.name, field.type_spec)
            for index, field in enumerate(case.fields)
        ),
        "})",
    ]


def _series_source(index: int, name: str, spec: TypeSpec) -> str:
    dtype = pandas_dtype(spec)
    if _requires_arrow_dtype_spec(spec):
        return (
            f"    {name!r}: pd.Series(TABLE.column({index}), "
            f"dtype=pd.ArrowDtype(TABLE.schema.field({index}).type)),"
        )
    return f"    {name!r}: pd.Series(TABLE.column({index}).to_pylist(), dtype={dtype!r}),"


def pandas_dtype(spec: TypeSpec) -> str:
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        pandas_dtype(cast(TypeSpec, spec.item))
    elif spec.kind is Kind.STRUCT:
        for field in spec.fields:
            pandas_dtype(field.type_spec)
    elif spec.kind is Kind.MAP:
        pandas_dtype(cast(TypeSpec, spec.key))
        pandas_dtype(cast(TypeSpec, spec.value))
    try:
        return _PANDAS_DTYPES[spec.kind]
    except KeyError as error:
        raise TypeError(f"fastparquet pandas conversion does not support {spec.kind}") from error


def _arrow_pandas_dtype(data_type: pa.DataType) -> str:
    scalar = _scalar_kind(data_type)
    if scalar is not None:
        return _PANDAS_DTYPES[scalar]
    if pa.types.is_map(data_type):
        mapping = cast(_MapType, cast(object, data_type))
        _arrow_pandas_dtype(mapping.key_field.type)
        _arrow_pandas_dtype(mapping.item_field.type)
        return _PANDAS_DTYPES[Kind.MAP]
    if (
        pa.types.is_list(data_type)
        or pa.types.is_large_list(data_type)
        or pa.types.is_fixed_size_list(data_type)
    ):
        _arrow_pandas_dtype(cast(_ListType, cast(object, data_type)).value_field.type)
        kind = Kind.FIXED_LIST if pa.types.is_fixed_size_list(data_type) else Kind.LIST
        return _PANDAS_DTYPES[kind]
    if pa.types.is_struct(data_type):
        for field in cast(_StructType, cast(object, data_type)):
            _arrow_pandas_dtype(field.type)
        return _PANDAS_DTYPES[Kind.STRUCT]
    raise TypeError(f"fastparquet pandas conversion does not support Arrow type {data_type}")


def _scalar_kind(data_type: pa.DataType) -> Kind | None:
    for predicate, kind in _ARROW_SCALARS:
        if predicate(data_type):
            return kind
    return None


def _requires_arrow_dtype_spec(spec: TypeSpec) -> bool:
    return spec.kind in (
        Kind.DATE32,
        Kind.TIMESTAMP,
        Kind.DECIMAL128,
        Kind.LIST,
        Kind.FIXED_LIST,
        Kind.STRUCT,
        Kind.MAP,
    )


def _requires_arrow_dtype(data_type: pa.DataType) -> bool:
    return (
        pa.types.is_date32(data_type)
        or pa.types.is_timestamp(data_type)
        or pa.types.is_decimal128(data_type)
        or pa.types.is_map(data_type)
        or pa.types.is_list(data_type)
        or pa.types.is_large_list(data_type)
        or pa.types.is_fixed_size_list(data_type)
        or pa.types.is_struct(data_type)
    )


def _pandas_module() -> _PandasModule:
    return cast(_PandasModule, cast(object, import_module("pandas")))


__all__ = ["frame_source_lines", "pandas_dtype", "table_to_pandas"]
