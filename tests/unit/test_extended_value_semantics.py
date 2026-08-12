from __future__ import annotations

import hashlib
import math
import struct
from decimal import Decimal
from typing import cast

import pyarrow as pa
import pytest

from parquity.case import semantic_key_bytes
from parquity.case.arrow import arrow_to_rows, case_to_arrow
from parquity.comparison.table import compare_case
from parquity.comparison.values import value_mismatch
from parquity.findings.upstream_script import render_upstream_repro
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, Verdict


def test_float_comparison_uses_declared_width_bits_nan_equivalence_and_signed_zero() -> None:
    f32 = TypeSpec(Kind.FLOAT32)
    expected = Case((Field("value", f32, False),), ((float("nan"),),))
    different_nan = struct.unpack(">f", bytes.fromhex("7fa00001"))[0]
    assert compare_case(expected, case_to_arrow(Case(expected.fields, ((different_nan,),)))).passed

    negative = Case((Field("value", f32, False),), ((-0.0,),))
    mismatch = compare_case(negative, case_to_arrow(Case(negative.fields, ((0.0,),))))
    assert mismatch.verdict is Verdict.VALUE_MISMATCH
    assert struct.pack(">f", negative.rows[0][0]) == bytes.fromhex("80000000")


def test_temporal_observation_uses_raw_epoch_integers_at_full_width() -> None:
    fields = (
        Field("day", TypeSpec(Kind.DATE32), False),
        Field("tick", TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC"), False),
        Field(
            "nested",
            TypeSpec(
                Kind.LIST,
                item=TypeSpec(Kind.TIMESTAMP, unit="us", timezone=None),
                item_nullable=False,
            ),
            False,
        ),
    )
    case = Case(fields, (((-(2**31)), 2**63 - 1, [-(2**63), 0]),))
    table = case_to_arrow(case)
    assert table.schema == pa.schema(
        [
            pa.field("day", pa.date32(), nullable=False),
            pa.field("tick", pa.timestamp("ns", tz="UTC"), nullable=False),
            pa.field(
                "nested",
                pa.list_(pa.field("item", pa.timestamp("us"), nullable=False)),
                nullable=False,
            ),
        ]
    )
    assert arrow_to_rows(table, fields) == case.rows
    assert compare_case(case, table).passed


def test_decimal_schema_and_coefficients_are_exact_without_float_conversion() -> None:
    spec = TypeSpec(Kind.DECIMAL128, precision=38, scale=18)
    value = Decimal("99999999999999999999.999999999999999999")
    case = Case((Field("amount", spec, False),), ((value,),))
    table = case_to_arrow(case)
    assert table.schema == pa.schema([pa.field("amount", pa.decimal128(38, 18), nullable=False)])
    assert arrow_to_rows(table, case.fields) == ((value,),)
    assert compare_case(case, table).passed


def test_map_comparison_is_order_independent_and_paths_hash_typed_key_bytes() -> None:
    spec = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.STRING),
        value=TypeSpec(Kind.INT32),
        value_nullable=False,
    )
    fields = (Field("lookup", spec, False),)
    expected = Case(fields, (([["b", 2], ["a", 1]],),))
    reordered = Case(fields, (([["a", 1], ["b", 2]],),))
    assert compare_case(expected, case_to_arrow(reordered)).passed

    missing = Case(fields, (([["a", 1]],),))
    mismatch = compare_case(expected, case_to_arrow(missing))
    typed_key = b'{"type":{"kind":"string"},"value":"b"}'
    digest = hashlib.sha256(typed_key).hexdigest()
    assert mismatch.verdict is Verdict.VALUE_MISMATCH
    assert mismatch.path == f"$rows[0].lookup.entries[sha256={digest}]"

    changed = Case(fields, (([["a", 1], ["b", 3]],),))
    mismatch = compare_case(expected, case_to_arrow(changed))
    assert mismatch.path == f"$rows[0].lookup.entries[sha256={digest}].value"
    assert len(digest) == 64 and digest == digest.lower()


def test_case_float32_quantization_is_stable() -> None:
    value = 1.0 + 2**-24
    case = Case((Field("value", TypeSpec(Kind.FLOAT32), False),), ((value,),))
    observed = cast(float, case.rows[0][0])
    assert observed == 1.0
    assert not math.copysign(1.0, observed) < 0


@pytest.mark.parametrize(
    ("spec", "value"),
    (
        (TypeSpec(Kind.INT32), None),
        (TypeSpec(Kind.BOOL), 1),
        (TypeSpec(Kind.DATE32), 2**31),
        (TypeSpec(Kind.TIMESTAMP, unit="ns"), True),
        (TypeSpec(Kind.STRING), b"x"),
        (TypeSpec(Kind.BINARY), "x"),
        (TypeSpec(Kind.FLOAT32), "1"),
        (TypeSpec(Kind.FLOAT32), 1e100),
        (TypeSpec(Kind.DECIMAL128, precision=4, scale=2), 1),
        (TypeSpec(Kind.DECIMAL128, precision=4, scale=2), Decimal("NaN")),
        (TypeSpec(Kind.DECIMAL128, precision=4, scale=2), Decimal("1.2")),
        (TypeSpec(Kind.DECIMAL128, precision=4, scale=2), Decimal("-0.00")),
        (TypeSpec(Kind.DECIMAL128, precision=4, scale=2), Decimal("123.00")),
        (TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)), "bad"),
        (TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=2), [1]),
        (
            TypeSpec(Kind.STRUCT, fields=(Field("x", TypeSpec(Kind.INT32), False),)),
            {},
        ),
        (
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.INT32),
                value_nullable=False,
            ),
            "bad",
        ),
        (
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.INT32),
                value_nullable=False,
            ),
            [["x"]],
        ),
        (
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.INT32),
                value_nullable=False,
            ),
            [[None, 1]],
        ),
        (
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.INT32),
                value_nullable=False,
            ),
            [["x", None]],
        ),
    ),
)
def test_runtime_value_validation_rejects_wrong_shapes_and_ranges(
    spec: TypeSpec, value: object
) -> None:
    with pytest.raises(ValueError):
        Case((Field("value", spec, False),), ((value,),))


def test_recursive_semantic_key_identity_covers_every_container_value_family() -> None:
    nested_map = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.STRING),
        value=TypeSpec(Kind.FLOAT64),
        value_nullable=True,
    )
    key = TypeSpec(
        Kind.STRUCT,
        fields=(
            Field("blob", TypeSpec(Kind.BINARY), False),
            Field("amount", TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),
            Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)), False),
            Field("lookup", nested_map, False),
            Field("optional", TypeSpec(Kind.STRING), True),
        ),
    )
    left = {
        "blob": b"\x00",
        "amount": Decimal("1.20"),
        "items": [1, None],
        "lookup": [["b", float("nan")], ["a", -0.0]],
        "optional": None,
    }
    right = {**left, "lookup": [["a", -0.0], ["b", float("nan")]]}
    assert semantic_key_bytes(key, left) == semantic_key_bytes(key, right)


def test_recursive_comparison_rejects_malformed_observations_at_typed_paths() -> None:
    decimal = TypeSpec(Kind.DECIMAL128, precision=4, scale=2)
    list_spec = TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32), item_nullable=False)
    struct_spec = TypeSpec(Kind.STRUCT, fields=(Field("x", TypeSpec(Kind.INT32), False),))
    map_spec = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.STRING),
        value=TypeSpec(Kind.INT32),
        value_nullable=False,
    )

    def assert_mismatch(spec: TypeSpec, expected: object, actual: object) -> None:
        assert value_mismatch(spec, expected, actual, "$value") is not None

    assert_mismatch(TypeSpec(Kind.INT32), None, 1)
    assert_mismatch(TypeSpec(Kind.FLOAT32), 1.0, "bad")
    assert_mismatch(decimal, 1, Decimal("1.00"))
    assert_mismatch(decimal, Decimal("1.00"), Decimal("1.0"))
    assert_mismatch(decimal, Decimal("1.00"), Decimal("2.00"))
    assert_mismatch(list_spec, [1], "bad")
    assert_mismatch(list_spec, [1], [1, 2])
    assert_mismatch(list_spec, [1], [2])
    assert_mismatch(struct_spec, {"x": 1}, [])
    assert_mismatch(struct_spec, {"x": 1}, {})
    assert_mismatch(struct_spec, {"x": 1}, {"x": 2})
    assert_mismatch(map_spec, [["a", 1]], "bad")
    assert_mismatch(map_spec, [["a", 1]], [["a", 1], ["a", 2]])
    empty_entry: list[object] = []
    assert_mismatch(map_spec, [["a", 1]], [empty_entry])
    assert_mismatch(map_spec, [["a", 1]], [[1, 1]])
    assert_mismatch(map_spec, [], {"b": 2})
    assert_mismatch(map_spec, [["a", 1]], [])


def test_extended_upstream_source_preserves_typed_identity() -> None:
    value = TypeSpec(
        Kind.STRUCT,
        fields=(
            Field(
                "ticks",
                TypeSpec(
                    Kind.LIST,
                    item=TypeSpec(Kind.TIMESTAMP, unit="us", timezone="UTC"),
                    item_nullable=False,
                ),
                False,
            ),
        ),
    )
    lookup = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.STRING),
        value=value,
        value_nullable=False,
    )
    fields = (
        Field("day", TypeSpec(Kind.DATE32), False),
        Field("amount", TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),
        Field("lookup", lookup, False),
        Field("ratio", TypeSpec(Kind.FLOAT64), False),
        Field("negative", TypeSpec(Kind.FLOAT32), False),
        Field("note", TypeSpec(Kind.STRING), True),
    )
    case = Case(
        fields,
        ((0, Decimal("1.20"), [["a", {"ticks": [-1]}]], float("inf"), -float("inf"), None),),
    )
    target = CellResult(
        "pyarrow", "1", "pyarrow", "1", "compare", Verdict.VALUE_MISMATCH, "$", "controlled"
    )
    source = render_upstream_repro(case, target).decode()
    assert "pa.date32()" in source
    assert "pa.timestamp('us', tz='UTC')" in source
    assert "Decimal('1.20')" in source
    assert "float('inf')" in source and "float('-inf')" in source
    assert "pa.map_(" in source
    compile(source, "upstream_repro.py", "exec")


def test_arrow_observation_rejects_a_conflicting_field_roster() -> None:
    case = Case((Field("x", TypeSpec(Kind.INT32), False),), ((1,),))
    table = case_to_arrow(case)
    assert arrow_to_rows(table, case.fields) == ((1,),)
    with pytest.raises(ValueError, match="field count"):
        arrow_to_rows(table, ())


@pytest.mark.parametrize(
    ("spec", "value"),
    (
        (TypeSpec(Kind.STRING), "\ud800"),
        (TypeSpec(Kind.LIST, item=TypeSpec(Kind.STRING)), ["ok", "\ud800"]),
        (
            TypeSpec(Kind.STRUCT, fields=(Field("text", TypeSpec(Kind.STRING), False),)),
            {"text": "\ud800"},
        ),
        (
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.STRING),
                value_nullable=False,
            ),
            [["key", "\ud800"]],
        ),
    ),
)
def test_lone_surrogate_string_values_are_rejected_recursively(
    spec: TypeSpec, value: object
) -> None:
    with pytest.raises(ValueError):
        Case((Field("value", spec, False),), ((value,),))
