from __future__ import annotations

from collections.abc import Sequence

import pyarrow as pa
import pytest

from parquity.scans.observations import (
    Observation,
    decode_observation,
    encode_observation,
    group_observations,
)


def _observation(
    engine: str, field: pa.Field[pa.DataType], values: Sequence[object]
) -> Observation:
    array = pa.array(values, type=field.type)
    table = pa.Table.from_arrays([array], schema=pa.schema([field]))
    payload, metadata = encode_observation(table)
    return decode_observation(engine, payload, metadata)


_EQUIVALENT_FIELDS = (
    (pa.field("value", pa.string()), pa.field("value", pa.large_string()), ["x"]),
    (pa.field("value", pa.large_string()), pa.field("value", pa.string_view()), ["x"]),
    (pa.field("value", pa.string_view()), pa.field("value", pa.string()), ["x"]),
    (pa.field("value", pa.binary()), pa.field("value", pa.large_binary()), [b"x"]),
    (pa.field("value", pa.large_binary()), pa.field("value", pa.binary_view()), [b"x"]),
    (pa.field("value", pa.binary_view()), pa.field("value", pa.binary()), [b"x"]),
    (
        pa.field("value", pa.list_(pa.field("item", pa.string()))),
        pa.field("value", pa.large_list(pa.field("l", pa.large_string()))),
        [["x"]],
    ),
    (
        pa.field("value", pa.list_(pa.field("item", pa.list_(pa.binary())))),
        pa.field(
            "value",
            pa.large_list(pa.field("element", pa.large_list(pa.binary_view()))),
        ),
        [[[b"x"]]],
    ),
)


@pytest.mark.parametrize(("left", "right", "values"), _EQUIVALENT_FIELDS)
def test_representation_aliases_share_one_group(
    left: pa.Field[pa.DataType],
    right: pa.Field[pa.DataType],
    values: Sequence[object],
) -> None:
    grouped = group_observations(
        (_observation("left", left, values), _observation("right", right, values))
    )
    assert len(grouped.groups) == 1
    assert grouped.groups[0].engines == ("left", "right")
    assert grouped.differences == ()


_DISTINCT_FIELDS = (
    (pa.field("left", pa.int32()), pa.field("right", pa.int32())),
    (
        pa.field("value", pa.map_(pa.string(), pa.int32())),
        pa.field(
            "value",
            pa.list_(
                pa.struct(
                    [
                        pa.field("key", pa.string(), nullable=False),
                        pa.field("value", pa.int32()),
                    ]
                )
            ),
        ),
    ),
    (pa.field("value", pa.list_(pa.int32(), 1)), pa.field("value", pa.list_(pa.int32(), 2))),
    (pa.field("value", pa.int32()), pa.field("value", pa.int32(), nullable=False)),
    (pa.field("value", pa.decimal128(18, 2)), pa.field("value", pa.decimal128(18, 3))),
    (pa.field("value", pa.timestamp("ms")), pa.field("value", pa.timestamp("us"))),
    (
        pa.field("value", pa.timestamp("us", tz="UTC")),
        pa.field("value", pa.timestamp("us", tz="Europe/Istanbul")),
    ),
    (
        pa.field("value", pa.dictionary(pa.int8(), pa.string())),
        pa.field("value", pa.dictionary(pa.int16(), pa.string())),
    ),
)


@pytest.mark.parametrize(("left", "right"), _DISTINCT_FIELDS)
def test_semantic_schema_boundaries_remain_distinct(
    left: pa.Field[pa.DataType], right: pa.Field[pa.DataType]
) -> None:
    grouped = group_observations((_observation("left", left, []), _observation("right", right, [])))
    assert len(grouped.groups) == 2
    assert len(grouped.differences) == 1
    assert grouped.differences[0].kind == "SCHEMA_DIFFERENCE"
    assert grouped.differences[0].path == "$.schema.fields[0]"


def test_equivalent_schema_still_exposes_value_difference() -> None:
    left = _observation("left", pa.field("value", pa.string()), ["expected"])
    right = _observation("right", pa.field("value", pa.large_string()), ["observed"])
    grouped = group_observations((left, right))
    assert len(grouped.groups) == 2
    assert len(grouped.differences) == 1
    difference = grouped.differences[0]
    assert (difference.kind, difference.path) == (
        "VALUE_DIFFERENCE",
        "$.rows[0].columns[0]",
    )
    assert difference.detail == "column 'value': 'expected' != 'observed'"
