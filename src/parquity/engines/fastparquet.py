from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa

from ..model import Kind
from ..profiles import WriterProfileIdentity
from .base import EngineIdentity, EngineReaderWriter, ProviderOperationError


class _Write(Protocol):
    def __call__(
        self, path: str, frame: object, *, write_index: bool, **options: object
    ) -> None: ...


class _ParquetFile(Protocol):
    def to_pandas(self) -> object: ...


class _ParquetFileFactory(Protocol):
    def __call__(self, path: str, *, pandas_nulls: bool) -> _ParquetFile: ...


class _FastparquetModule(Protocol):
    write: _Write
    ParquetFile: _ParquetFileFactory


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


class _ArrowTableFactory(Protocol):
    def from_pandas(self, frame: object, *, preserve_index: bool) -> pa.Table: ...


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
_ARROW_TABLE = cast(_ArrowTableFactory, cast(object, pa.Table))


@dataclass(frozen=True, slots=True)
class FastparquetEngine:
    identity: EngineIdentity

    def write(self, table: pa.Table, path: Path) -> None:
        try:
            frame = table_to_pandas(table)
            _fastparquet_module().write(str(path), frame, write_index=False)
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = {
            "compression-gzip": {"compression": "GZIP"},
            "compression-brotli": {"compression": "BROTLI"},
            "row-group-2": {"row_group_offsets": 2},
            "min-max-statistics-off": {"stats": False},
        }
        selected = options.get(name)
        return None if selected is None else WriterProfileIdentity(name, selected)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the fastparquet translation")
        try:
            frame = table_to_pandas(table)
            _fastparquet_module().write(
                str(path), frame, write_index=False, **profile.effective_options
            )
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "write", error) from error

    def read(self, path: Path) -> pa.Table:
        try:
            frame = _fastparquet_module().ParquetFile(str(path), pandas_nulls=True).to_pandas()
            return _ARROW_TABLE.from_pandas(frame, preserve_index=False)
        except Exception as error:
            raise ProviderOperationError(self.identity.name, "read", error) from error


def create_engine(version: str) -> EngineReaderWriter:
    return FastparquetEngine(EngineIdentity("fastparquet", version))


def table_to_pandas(table: pa.Table) -> object:
    pandas = _pandas_module()
    columns: dict[str, object] = {}
    schema = cast(_Schema, cast(object, table.schema))
    for index, field in enumerate(schema):
        dtype, uses_arrow_dtype = pandas_dtype_plan(field.type)
        column = table.column(index)
        values: object
        if uses_arrow_dtype:
            values = column
            dtype = pandas.ArrowDtype(field.type)
        else:
            values = cast(Callable[[], list[object]], column.to_pylist)()
        columns[field.name] = pandas.Series(values, dtype=dtype)
    return pandas.DataFrame(columns)


def pandas_dtype_plan(data_type: pa.DataType) -> tuple[str, bool]:
    return _arrow_pandas_dtype(data_type), _requires_arrow_dtype(data_type)


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


def _fastparquet_module() -> _FastparquetModule:
    return cast(_FastparquetModule, cast(object, import_module("fastparquet")))


def _pandas_module() -> _PandasModule:
    return cast(_PandasModule, cast(object, import_module("pandas")))
