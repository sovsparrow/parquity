from __future__ import annotations

import math
import struct
from typing import cast

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from ..case import decimal_from_coefficient, semantic_key_bytes
from ..model import Case, Field, Kind, TypeSpec

MAX_FIELDS = 4
MAX_ROWS = 4
MAX_STRING_SIZE = 12
MAX_BINARY_SIZE = 12
MAX_LIST_WIDTH = 4
MAX_FIXED_LIST_SIZE = 4
MAX_STRUCT_FIELDS = 3
MAX_DEPTH = 4
MAX_NODES = 128
MAX_SLOTS = 256

_PLAIN_SCALARS = (Kind.BOOL, Kind.INT32, Kind.INT64, Kind.STRING, Kind.BINARY)
_EXTENDED_SCALARS = (Kind.FLOAT32, Kind.FLOAT64, Kind.DATE32, Kind.TIMESTAMP, Kind.DECIMAL128)
_TIMEZONES: tuple[str | None, ...] = (None, "UTC", "America/New_York", "Europe/Istanbul")
_LEGACY_SCALAR_SPECS = tuple(TypeSpec(kind) for kind in _PLAIN_SCALARS)


def bounded_cases() -> SearchStrategy[Case]:
    return _cases()


@st.composite
def _scalar_types(draw: st.DrawFn) -> TypeSpec:
    kind = draw(st.sampled_from((*_PLAIN_SCALARS, *_EXTENDED_SCALARS)))
    if kind is Kind.TIMESTAMP:
        return TypeSpec(
            kind,
            unit=draw(st.sampled_from(("s", "ms", "us", "ns"))),
            timezone=draw(st.sampled_from(_TIMEZONES)),
        )
    if kind is Kind.DECIMAL128:
        precision = draw(st.integers(min_value=1, max_value=38))
        return TypeSpec(kind, precision=precision, scale=draw(st.integers(0, precision)))
    return TypeSpec(kind)


def _legacy_scalar_types() -> SearchStrategy[TypeSpec]:
    return st.sampled_from(_LEGACY_SCALAR_SPECS)


@st.composite
def _types(draw: st.DrawFn, depth: int, slots: int, nodes: int) -> TypeSpec:
    kinds = ["scalar"]
    if depth < MAX_DEPTH and slots >= 1 and nodes >= 2:
        kinds.extend(("list", "fixed_list"))
    if depth < MAX_DEPTH and slots >= 1 and nodes >= 3:
        kinds.append("struct")
    if depth < MAX_DEPTH and slots >= 8 and nodes >= 3:
        kinds.append("map")
    kind = draw(st.sampled_from(kinds))
    if kind == "scalar":
        return draw(_scalar_types())
    if kind in ("list", "fixed_list"):
        width = 4 if kind == "list" else draw(st.integers(1, MAX_FIXED_LIST_SIZE))
        child = draw(_legacy_scalar_types())
        return TypeSpec(
            Kind.LIST if kind == "list" else Kind.FIXED_LIST,
            item=child,
            item_nullable=draw(st.booleans()),
            size=None if kind == "list" else width,
        )
    if kind == "struct":
        maximum = min(MAX_STRUCT_FIELDS, slots, max(1, (nodes - 1) // 2))
        count = draw(st.integers(1, maximum))
        fields = tuple(
            Field(
                f"child_{index}",
                draw(_legacy_scalar_types()),
                draw(st.booleans()),
            )
            for index in range(count)
        )
        return TypeSpec(Kind.STRUCT, fields=fields)
    return TypeSpec(
        Kind.MAP,
        key=draw(_scalar_types()),
        value=draw(_scalar_types()),
        value_nullable=draw(st.booleans()),
    )


def _scalar_values(spec: TypeSpec) -> SearchStrategy[object]:
    if spec.kind is Kind.BOOL:
        return cast(SearchStrategy[object], st.booleans())
    if spec.kind in (Kind.INT32, Kind.DATE32):
        return _bounded_integers(-(2**31), 2**31 - 1, _date_boundaries())
    if spec.kind in (Kind.INT64, Kind.TIMESTAMP):
        boundaries = (
            _timestamp_boundaries(cast(str, spec.unit)) if spec.kind is Kind.TIMESTAMP else ()
        )
        return _bounded_integers(-(2**63), 2**63 - 1, boundaries)
    if spec.kind is Kind.STRING:
        characters = st.characters(blacklist_categories=("Cs",))
        return cast(SearchStrategy[object], st.text(alphabet=characters, max_size=MAX_STRING_SIZE))
    if spec.kind is Kind.BINARY:
        return cast(SearchStrategy[object], st.binary(max_size=MAX_BINARY_SIZE))
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        return _float_values(spec.kind)
    if spec.kind is Kind.DECIMAL128:
        return _decimal_values(spec)
    raise TypeError("scalar value strategy received a container")


def _bounded_integers(low: int, high: int, boundaries: tuple[int, ...]) -> SearchStrategy[object]:
    selected = tuple(value for value in boundaries if low <= value <= high)
    values = st.one_of(
        st.sampled_from((low, low + 1, -1, 0, 1, high - 1, high, *selected)), st.integers(low, high)
    )
    return cast(SearchStrategy[object], values)


def _float_values(kind: Kind) -> SearchStrategy[object]:
    width = 32 if kind is Kind.FLOAT32 else 64
    boundaries = _float_boundaries(width)
    arbitrary = st.integers(0, 2**width - 1).map(lambda bits: _float_from_bits(width, bits))
    return cast(SearchStrategy[object], st.one_of(st.sampled_from(boundaries), arbitrary))


def _float_boundaries(width: int) -> tuple[float, ...]:
    bits = (
        (0, 1, 0x007FFFFF, 0x00800000, 0x7F7FFFFF, 0x7F800000, 0x7FC00000, 0x80000000)
        if width == 32
        else (
            0,
            1,
            0x000FFFFFFFFFFFFF,
            0x0010000000000000,
            0x7FEFFFFFFFFFFFFF,
            0x7FF0000000000000,
            0x7FF8000000000000,
            0x8000000000000000,
        )
    )
    positive = tuple(_float_from_bits(width, value) for value in bits)
    negative = tuple(-value for value in positive if not math.isnan(value))
    return (*positive, *negative)


def _float_from_bits(width: int, bits: int) -> float:
    code = ">I" if width == 32 else ">Q"
    value = ">f" if width == 32 else ">d"
    return cast(float, struct.unpack(value, struct.pack(code, bits))[0])


def _decimal_values(spec: TypeSpec) -> SearchStrategy[object]:
    maximum = 10 ** cast(int, spec.precision) - 1
    scale = cast(int, spec.scale)
    boundaries = {0, 1, -1, maximum, -maximum}
    for exponent in range(1, cast(int, spec.precision) + 1):
        power = 10**exponent
        boundaries.update((power - 1, -(power - 1)))
    coefficients = st.one_of(
        st.sampled_from(tuple(sorted(value for value in boundaries if abs(value) <= maximum))),
        st.integers(-maximum, maximum),
    )
    return cast(
        SearchStrategy[object],
        coefficients.map(lambda value: decimal_from_coefficient(value, scale)),
    )


def _non_null_values(spec: TypeSpec) -> SearchStrategy[object]:
    if spec.kind not in (Kind.LIST, Kind.FIXED_LIST, Kind.STRUCT, Kind.MAP):
        return _scalar_values(spec)
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        minimum = 0 if spec.size is None else spec.size
        maximum = MAX_LIST_WIDTH if spec.size is None else spec.size
        return cast(
            SearchStrategy[object],
            st.lists(value_strategy(item, spec.item_nullable), min_size=minimum, max_size=maximum),
        )
    if spec.kind is Kind.STRUCT:
        mapping = {
            field.name: value_strategy(field.type_spec, field.nullable) for field in spec.fields
        }
        return cast(SearchStrategy[object], st.fixed_dictionaries(mapping))
    return _map_values(spec)


@st.composite
def _map_values(draw: st.DrawFn, spec: TypeSpec) -> object:
    key_spec = cast(TypeSpec, spec.key)
    value_spec = cast(TypeSpec, spec.value)
    requested = draw(st.integers(0, MAX_LIST_WIDTH))
    candidates = draw(
        st.lists(
            value_strategy(key_spec, False),
            min_size=requested,
            max_size=requested * 4 + 4,
        )
    )
    keys: list[object] = []
    identities: set[bytes] = set()
    for candidate in candidates:
        identity = semantic_key_bytes(key_spec, candidate)
        if identity in identities:
            continue
        identities.add(identity)
        keys.append(candidate)
        if len(keys) == requested:
            break
    return [[key, draw(value_strategy(value_spec, spec.value_nullable))] for key in keys]


def value_strategy(spec: TypeSpec, nullable: bool) -> SearchStrategy[object]:
    values = _non_null_values(spec)
    if not nullable:
        return values
    return cast(SearchStrategy[object], st.one_of(st.none(), values))


@st.composite
def _cases(draw: st.DrawFn) -> Case:
    field_count = draw(st.integers(1, MAX_FIELDS))
    nodes = max(1, (MAX_NODES - field_count) // field_count)
    slots = MAX_SLOTS // field_count
    fields = tuple(
        Field(
            f"field_{index}",
            draw(_types(1, slots, nodes)),
            draw(st.booleans()),
        )
        for index in range(field_count)
    )
    row_count = draw(st.integers(0, MAX_ROWS))
    rows = tuple(
        tuple(draw(value_strategy(field.type_spec, field.nullable)) for field in fields)
        for _ in range(row_count)
    )
    return Case(fields, rows)


def _date_boundaries() -> tuple[int, ...]:
    return (-719162, -719161, -1, 0, 1, 11016, 11017, 11018, 2932896)


def _timestamp_boundaries(unit: str) -> tuple[int, ...]:
    factor = {"s": 1, "ms": 1_000, "us": 1_000_000, "ns": 1_000_000_000}[unit]
    seconds = (-62135596800, -1, 0, 1, 1615705199, 1615705200, 1636264799, 253402300799)
    converted = tuple(value * factor for value in seconds)
    edges = (-factor - 1, -factor, -factor + 1, factor - 1, factor, factor + 1)
    return (*converted, *edges)


__all__ = ["bounded_cases", "value_strategy"]
