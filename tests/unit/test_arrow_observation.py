from __future__ import annotations

from typing import Protocol, cast

import pyarrow as pa

from parquity.case.arrow import arrow_to_rows
from parquity.comparison.table import compare_case
from parquity.model import Case, Field, Kind, TypeSpec


class _MapArrayFactory(Protocol):
    def __call__(
        self,
        offsets: object,
        keys: object,
        items: object,
    ) -> pa.Array[pa.Scalar[pa.DataType]]: ...


class _MapArrayClass(Protocol):
    from_arrays: _MapArrayFactory


_MAP_ARRAY = cast(_MapArrayClass, cast(object, pa.MapArray))


def test_temporal_map_key_with_an_all_valid_bitmap_is_observed_as_an_epoch() -> None:
    key = pa.Array.from_buffers(
        pa.date32(),
        1,
        [pa.py_buffer(b"\x01"), pa.py_buffer(b"\x00\x00\x00\x00")],
    )
    assert key.null_count == 0
    assert key.buffers()[0] is not None
    mapping = _MAP_ARRAY.from_arrays(pa.array([0, 1], type=pa.int64()), key, pa.array(["x"]))
    spec = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.DATE32),
        value=TypeSpec(Kind.STRING),
        value_nullable=True,
    )
    fields = (Field("value", spec, False),)
    case = Case(fields, (([[0, "x"]],),))
    table = pa.Table.from_arrays([mapping], names=["value"])

    assert arrow_to_rows(table, fields) == (([(0, "x")],),)
    assert compare_case(case, table).passed
