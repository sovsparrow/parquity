from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import NamedTuple, Protocol, cast

import pyarrow as pa
import pyarrow.ipc as ipc

from .records import MAX_OBSERVATION_BYTES, valid_digest

_DETAIL_LIMIT = 500


class ObservationError(ValueError): ...


@dataclass(frozen=True, slots=True)
class ObservationMetadata:
    byte_count: int
    sha256: str
    row_count: int
    column_count: int
    schema_sha256: str

    def __post_init__(self) -> None:
        counts = (self.byte_count, self.row_count, self.column_count)
        digests = (self.sha256, self.schema_sha256)
        if any(value < 0 for value in counts) or self.byte_count > MAX_OBSERVATION_BYTES:
            raise ObservationError("observation metadata counts are invalid")
        if any(not valid_digest(value) for value in digests):
            raise ObservationError("observation metadata digests are invalid")


class ObservationGroup(NamedTuple):
    group_id: str
    engines: tuple[str, ...]


class ObservationDifference(NamedTuple):
    left_group: str
    right_group: str
    kind: str
    path: str
    detail: str

    def to_data(self) -> dict[str, object]:
        return cast(dict[str, object], self._asdict())


class _SchemaView(Protocol):
    def field(self, index: int) -> pa.Field[pa.DataType]: ...


class _FieldView(Protocol):
    def equals(self, other: object, check_metadata: bool = False) -> bool: ...


class _ValuesView(Protocol):
    @property
    def values(self) -> pa.Array[pa.Scalar[pa.DataType]]: ...


class _StructView(Protocol):
    def __getitem__(self, index: int) -> pa.Scalar[pa.DataType]: ...


class _DictionaryView(Protocol):
    @property
    def value(self) -> pa.Scalar[pa.DataType]: ...


class _ScalarView(Protocol):
    def equals(self, other: object) -> bool: ...


class _ValueMismatch(NamedTuple):
    location: str
    detail: str


class Observation(NamedTuple):
    engine: str
    table: pa.Table
    metadata: ObservationMetadata


class GroupedObservations(NamedTuple):
    groups: tuple[ObservationGroup, ...]
    differences: tuple[ObservationDifference, ...]


def normalize_table(table: pa.Table) -> pa.Table:
    return table.replace_schema_metadata(None).combine_chunks()


def encode_observation(table: pa.Table) -> tuple[bytes, ObservationMetadata]:
    normalized = normalize_table(table)
    sink = pa.BufferOutputStream()
    with ipc.new_file(sink, normalized.schema) as writer:
        writer.write_table(normalized)
    payload = sink.getvalue().to_pybytes()
    if len(payload) > MAX_OBSERVATION_BYTES:
        raise ObservationError("observation artifact exceeds 256 MiB")
    carrier_schema = ipc.open_file(pa.BufferReader(payload)).schema
    return payload, _metadata(normalized, payload, carrier_schema)


def decode_observation(
    engine: str,
    payload: bytes,
    expected: ObservationMetadata,
) -> Observation:
    if len(payload) > MAX_OBSERVATION_BYTES or (
        len(payload),
        hashlib.sha256(payload).hexdigest(),
    ) != (
        expected.byte_count,
        expected.sha256,
    ):
        raise ObservationError("observation artifact digest does not match")
    try:
        table = ipc.open_file(pa.BufferReader(payload)).read_all()
        normalized = normalize_table(table)
    except (pa.ArrowException, OSError) as error:
        raise ObservationError("observation artifact is not valid Arrow IPC") from error
    if _metadata(normalized, payload, normalized.schema) != expected:
        raise ObservationError("observation control evidence does not match the artifact")
    return Observation(engine, normalized, expected)


def group_observations(observations: tuple[Observation, ...]) -> GroupedObservations:
    representatives: list[Observation] = []
    members: list[list[str]] = []
    for observation in observations:
        group_index = next(
            (
                index
                for index, representative in enumerate(representatives)
                if _compare_tables(observation.table, representative.table, "", "") is None
            ),
            None,
        )
        if group_index is None:
            group_index = len(representatives)
            representatives.append(observation)
            members.append([])
        members[group_index].append(observation.engine)
    groups = tuple(
        ObservationGroup(f"group-{index + 1}", tuple(group_members))
        for index, group_members in enumerate(members)
    )
    differences = tuple(
        _required_difference(
            representatives[left].table,
            representatives[right].table,
            groups[left].group_id,
            groups[right].group_id,
        )
        for left in range(len(representatives))
        for right in range(left + 1, len(representatives))
    )
    return GroupedObservations(groups, differences)


def _compare_tables(
    left: pa.Table,
    right: pa.Table,
    left_group: str,
    right_group: str,
) -> ObservationDifference | None:
    if not left.schema.equals(right.schema, check_metadata=True):
        path, detail = _schema_difference(left.schema, right.schema)
        return ObservationDifference(left_group, right_group, "SCHEMA_DIFFERENCE", path, detail)
    if left.num_rows != right.num_rows:
        detail = f"row count {left.num_rows} != {right.num_rows}"
        return ObservationDifference(
            left_group, right_group, "ROW_COUNT_DIFFERENCE", "$.rows", detail
        )
    for column_index in range(left.num_columns):
        left_column = left.column(column_index)
        right_column = right.column(column_index)
        for row_index in range(left.num_rows):
            left_value = left_column[row_index]
            right_value = right_column[row_index]
            mismatch = _value_mismatch(left_value, right_value, "$")
            if mismatch is None:
                continue
            schema = cast(_SchemaView, cast(object, left.schema))
            name = schema.field(column_index).name
            location = "" if mismatch.location == "$" else f" at {mismatch.location}"
            detail = f"column {name!r}{location}: {mismatch.detail}"[:_DETAIL_LIMIT]
            return ObservationDifference(
                left_group,
                right_group,
                "VALUE_DIFFERENCE",
                f"$.rows[{row_index}].columns[{column_index}]",
                detail,
            )
    return None


def _required_difference(
    left: pa.Table,
    right: pa.Table,
    left_group: str,
    right_group: str,
) -> ObservationDifference:
    difference = _compare_tables(left, right, left_group, right_group)
    if difference is None:
        raise ObservationError("observation groups do not differ")
    return difference


def _value_mismatch(
    left: pa.Scalar[pa.DataType],
    right: pa.Scalar[pa.DataType],
    location: str,
) -> _ValueMismatch | None:
    if left.is_valid != right.is_valid:
        return _leaf_mismatch(left, right, location)
    if not left.is_valid:
        return None
    value_type = left.type
    if pa.types.is_floating(value_type):
        return None if _floats_equal(left, right) else _leaf_mismatch(left, right, location)
    if pa.types.is_list(value_type) or pa.types.is_large_list(value_type):
        return _list_mismatch(left, right, location)
    if pa.types.is_fixed_size_list(value_type):
        return _list_mismatch(left, right, location)
    if pa.types.is_struct(value_type):
        return _struct_mismatch(left, right, location)
    if pa.types.is_map(value_type):
        return _map_mismatch(left, right, location)
    if pa.types.is_dictionary(value_type):
        left_value = cast(_DictionaryView, cast(object, left)).value
        right_value = cast(_DictionaryView, cast(object, right)).value
        return _value_mismatch(left_value, right_value, f"{location}.dictionary")
    if not cast(_ScalarView, cast(object, left)).equals(right):
        return _leaf_mismatch(left, right, location)
    return None


def _list_mismatch(
    left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType], location: str
) -> _ValueMismatch | None:
    left_values = cast(_ValuesView, cast(object, left)).values
    right_values = cast(_ValuesView, cast(object, right)).values
    if len(left_values) != len(right_values):
        return _ValueMismatch(location, f"length {len(left_values)} != {len(right_values)}")
    for index in range(len(left_values)):
        mismatch = _value_mismatch(left_values[index], right_values[index], f"{location}[{index}]")
        if mismatch is not None:
            return mismatch
    return None


def _struct_mismatch(
    left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType], location: str
) -> _ValueMismatch | None:
    left_view = cast(_StructView, cast(object, left))
    right_view = cast(_StructView, cast(object, right))
    for index in range(cast(pa.StructType, left.type).num_fields):
        mismatch = _value_mismatch(
            left_view[index], right_view[index], f"{location}.fields[{index}]"
        )
        if mismatch is not None:
            return mismatch
    return None


def _map_mismatch(
    left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType], location: str
) -> _ValueMismatch | None:
    left_entries = cast(_ValuesView, cast(object, left)).values
    right_entries = cast(_ValuesView, cast(object, right)).values
    if len(left_entries) != len(right_entries):
        return _ValueMismatch(location, f"length {len(left_entries)} != {len(right_entries)}")
    for index in range(len(left_entries)):
        left_entry = cast(_StructView, cast(object, left_entries[index]))
        right_entry = cast(_StructView, cast(object, right_entries[index]))
        for field_index, field_name in enumerate(("key", "value")):
            nested = f"{location}.entries[{index}].{field_name}"
            mismatch = _value_mismatch(left_entry[field_index], right_entry[field_index], nested)
            if mismatch is not None:
                return mismatch
    return None


def _floats_equal(left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType]) -> bool:
    left_value, right_value = cast(float, left.as_py()), cast(float, right.as_py())
    if math.isnan(left_value) and math.isnan(right_value):
        return True
    formats = {16: "e", 32: "f", 64: "d"}
    width = cast(int, cast(object, left.type.bit_width))
    return struct.pack(f"<{formats[width]}", left_value) == struct.pack(
        f"<{formats[width]}", right_value
    )


def _leaf_mismatch(
    left: pa.Scalar[pa.DataType], right: pa.Scalar[pa.DataType], location: str
) -> _ValueMismatch:
    return _ValueMismatch(location, f"{_scalar_repr(left)} != {_scalar_repr(right)}")


def _scalar_repr(value: pa.Scalar[pa.DataType]) -> str:
    if pa.types.is_temporal(value.type):
        try:
            raw = value.cast(pa.int64()).as_py()
        except (pa.ArrowException, OverflowError, ValueError):
            pass
        else:
            return f"{value.type}({raw!r})"
    try:
        return repr(value.as_py())
    except (OverflowError, ValueError):
        return repr(value)


def _schema_difference(left: pa.Schema, right: pa.Schema) -> tuple[str, str]:
    if len(left) != len(right):
        return "$.schema", f"field count {len(left)} != {len(right)}"
    left_view = cast(_SchemaView, cast(object, left))
    right_view = cast(_SchemaView, cast(object, right))
    for index in range(len(left)):
        left_field = left_view.field(index)
        right_field = right_view.field(index)
        if not cast(_FieldView, cast(object, left_field)).equals(right_field, check_metadata=True):
            return (
                f"$.schema.fields[{index}]",
                f"{left_field!s} != {right_field!s}"[:_DETAIL_LIMIT],
            )
    return "$.schema", "schema metadata differs"


def _metadata(table: pa.Table, payload: bytes, schema: pa.Schema) -> ObservationMetadata:
    schema_payload = schema.serialize().to_pybytes()
    return ObservationMetadata(
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        table.num_rows,
        table.num_columns,
        hashlib.sha256(schema_payload).hexdigest(),
    )
