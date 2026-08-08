from __future__ import annotations

import json
from decimal import Decimal

import pyarrow as pa
import pytest

from parquity.arrow_bridge import case_to_arrow
from parquity.model import Case, Field, Kind, TypeSpec

_LEGACY = (
    b'{"format":"parquity.case.v1","rows":[[1]],"schema":'
    b'[{"name":"x","nullable":false,"type":{"kind":"int32"}}]}'
)
_EXTENDED = (
    b'{"format":"parquity.case.v1","rows":[[{"$float":"nan"},-1,'
    b'-9223372036854775808,{"$decimal":"12.30"},[["b",-0.0],["a",null]]]],'
    b'"schema":[{"name":"f32","nullable":false,"type":{"kind":"float32"}},'
    b'{"name":"day","nullable":false,"type":{"kind":"date32"}},'
    b'{"name":"tick","nullable":false,"type":{"kind":"timestamp",'
    b'"timezone":"Europe/Istanbul","unit":"ns"}},{"name":"amount",'
    b'"nullable":false,"type":{"kind":"decimal128","precision":6,"scale":2}},'
    b'{"name":"lookup","nullable":false,"type":{"key":{"kind":"string"},'
    b'"kind":"map","value":{"kind":"float64"},"value_nullable":true}}]}'
)


def _extended_case() -> Case:
    return Case(
        (
            Field("f32", TypeSpec(Kind.FLOAT32), False),
            Field("day", TypeSpec(Kind.DATE32), False),
            Field(
                "tick",
                TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="Europe/Istanbul"),
                False,
            ),
            Field("amount", TypeSpec(Kind.DECIMAL128, precision=6, scale=2), False),
            Field(
                "lookup",
                TypeSpec(
                    Kind.MAP,
                    key=TypeSpec(Kind.STRING),
                    value=TypeSpec(Kind.FLOAT64),
                    value_nullable=True,
                ),
                False,
            ),
        ),
        ((float("nan"), -1, -(2**63), Decimal("12.30"), [["b", -0.0], ["a", None]]),),
    )


def test_legacy_and_extended_cases_have_literal_final_v1_bytes_and_ids() -> None:
    legacy = Case((Field("x", TypeSpec(Kind.INT32), False),), ((1,),))
    extended = _extended_case()
    assert legacy.canonical_bytes() == _LEGACY
    assert legacy.case_id == "7f66c87349cf81e06d34f71d9e992669e28caa68170c89de3cd291310936a63b"
    assert extended.canonical_bytes() == _EXTENDED
    assert extended.case_id == "db4e5099ff0b85231593836883e116eea0cb769659187311bc85ad68c234f742"
    assert Case.from_json(_LEGACY) == legacy
    decoded = Case.from_json(_EXTENDED)
    assert decoded.canonical_bytes() == _EXTENDED
    assert decoded.rows[0][4] == [["b", -0.0], ["a", None]]


@pytest.mark.parametrize(
    "type_data",
    (
        {"kind": "float32", "scale": 0},
        {"kind": "timestamp", "unit": "minute", "timezone": None},
        {"kind": "timestamp", "unit": "ns"},
        {"kind": "decimal128", "precision": 39, "scale": 0},
        {"kind": "decimal128", "precision": 3, "scale": 4},
        {"kind": "map", "key": {"kind": "string"}, "value_nullable": False},
    ),
)
def test_extended_type_grammar_rejects_unknown_missing_and_invalid_parameters(
    type_data: dict[str, object],
) -> None:
    document = {
        "format": "parquity.case.v1",
        "schema": [{"name": "value", "nullable": False, "type": type_data}],
        "rows": [],
    }
    with pytest.raises(ValueError):
        Case.from_json(json.dumps(document))


@pytest.mark.parametrize(
    "row",
    (
        "[NaN]",
        '[{"$float":"nan","extra":true}]',
        '[{"$decimal":"1e0"}]',
        '[{"$decimal":"+1.00"}]',
    ),
)
def test_extended_value_grammar_rejects_noncanonical_json_tokens(row: str) -> None:
    field = (
        '{"name":"value","nullable":false,"type":'
        + (
            '{"kind":"float64"}'
            if "float" in row or row == "[NaN]"
            else '{"kind":"decimal128","precision":3,"scale":2}'
        )
        + "}"
    )
    with pytest.raises(ValueError):
        Case.from_json(f'{{"format":"parquity.case.v1","schema":[{field}],"rows":[{row}]}}')


def test_finite_numeric_overflow_is_rejected_before_tagged_float_decoding() -> None:
    prefix = (
        b'{"format":"parquity.case.v1","schema":[{"name":"value","nullable":false,'
        b'"type":{"kind":"float64"}}],"rows":[['
    )
    for token in (b"1e400", b"-1e400"):
        with pytest.raises(ValueError):
            Case.from_json(prefix + token + b"]]}")
    finite = Case.from_json(prefix + b"1e3]]}")
    assert finite.rows == ((1000.0,),)
    assert Case.from_json(finite.canonical_bytes()) == finite
    for tag, expected in ((b"inf", float("inf")), (b"-inf", float("-inf"))):
        tagged = Case.from_json(prefix + b'{"$float":"' + tag + b'"}]]}')
        assert tagged.rows == ((expected,),)
        assert Case.from_json(tagged.canonical_bytes()) == tagged


def test_duplicate_json_fields_and_semantically_duplicate_map_keys_fail_closed() -> None:
    duplicate = _LEGACY.replace(b'"rows"', b'"rows":[],"rows"', 1)
    with pytest.raises(ValueError):
        Case.from_json(duplicate)
    map_type = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.FLOAT32),
        value=TypeSpec(Kind.INT32),
        value_nullable=False,
    )
    with pytest.raises(ValueError, match="duplicate map keys"):
        Case((Field("values", map_type, False),), (([[0.0, 1], [0, 2]],),))


def test_constructor_grammar_rejects_inapplicable_parameters_and_labels() -> None:
    constructors = (
        lambda: TypeSpec(Kind.FLOAT32, item_nullable=False),
        lambda: TypeSpec(Kind.LIST),
        lambda: TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=0),
        lambda: TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32), size=1),
        lambda: TypeSpec(Kind.STRUCT),
        lambda: TypeSpec(
            Kind.STRUCT,
            fields=(Field("x", TypeSpec(Kind.INT32)), Field("x", TypeSpec(Kind.INT64))),
        ),
        lambda: TypeSpec(Kind.TIMESTAMP, unit="ns", timezone=""),
        lambda: TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC\n"),
        lambda: TypeSpec(Kind.TIMESTAMP, item=TypeSpec(Kind.INT32), unit="ns"),
        lambda: TypeSpec(Kind.DECIMAL128, precision=True, scale=0),
        lambda: TypeSpec(Kind.DECIMAL128, precision=3, scale=True),
        lambda: TypeSpec(Kind.MAP, key=TypeSpec(Kind.STRING)),
    )
    for construct in constructors:
        with pytest.raises(ValueError):
            construct()


@pytest.mark.parametrize(
    "type_data",
    (
        {"kind": "fixed_list", "item": {"kind": "int32"}, "item_nullable": False, "size": True},
        {"kind": "timestamp", "unit": 1, "timezone": None},
        {"kind": "list", "item": [], "item_nullable": False},
        {"kind": "struct", "fields": {}},
    ),
)
def test_type_decoder_rejects_wrong_json_shapes(type_data: dict[str, object]) -> None:
    document = {
        "format": "parquity.case.v1",
        "schema": [{"name": "value", "nullable": False, "type": type_data}],
        "rows": [],
    }
    with pytest.raises(ValueError):
        Case.from_data(document)


@pytest.mark.parametrize(
    ("type_data", "value"),
    (
        ({"kind": "binary"}, {"$binary": "AB=="}),
        ({"kind": "binary"}, {"$binary": 1}),
        ({"kind": "float32"}, {"$float": "other"}),
        ({"kind": "decimal128", "precision": 3, "scale": 2}, {"$decimal": "1.00", "x": 1}),
        (
            {
                "kind": "struct",
                "fields": [{"name": "x", "nullable": False, "type": {"kind": "int32"}}],
            },
            {},
        ),
        (
            {
                "kind": "map",
                "key": {"kind": "string"},
                "value": {"kind": "int32"},
                "value_nullable": False,
            },
            [["x"]],
        ),
    ),
)
def test_tagged_and_container_value_decoders_reject_malformed_shapes(
    type_data: dict[str, object], value: object
) -> None:
    document = {
        "format": "parquity.case.v1",
        "schema": [{"name": "value", "nullable": False, "type": type_data}],
        "rows": [[value]],
    }
    with pytest.raises(ValueError):
        Case.from_data(document)


def test_binary_and_integer_scale_decimal_use_their_canonical_tags() -> None:
    case = Case(
        (
            Field("blob", TypeSpec(Kind.BINARY), False),
            Field("amount", TypeSpec(Kind.DECIMAL128, precision=3, scale=0), False),
        ),
        ((b"\x00\x01", Decimal("12")),),
    )
    decoded = Case.from_json(case.canonical_bytes())
    assert decoded == case
    assert decoded.to_data()["rows"] == [[{"$binary": "AAE="}, {"$decimal": "12"}]]


def test_negative_fractional_decimal_round_trips_with_byte_identical_identity() -> None:
    spec = TypeSpec(Kind.DECIMAL128, precision=3, scale=2)
    case = Case((Field("amount", spec, False),), ((Decimal("-0.01"),),))
    encoded = case.canonical_bytes()
    decoded = Case.from_json(encoded)
    assert decoded.rows == ((Decimal("-0.01"),),)
    assert decoded.canonical_bytes() == encoded
    assert decoded.case_id == case.case_id
    for invalid in ("-0.00", "-00.01", "-.01", "-0.010"):
        with pytest.raises(ValueError):
            Case.from_json(encoded.replace(b"-0.01", invalid.encode()))


def test_valid_non_ascii_text_is_byte_stable_and_arrow_constructible() -> None:
    case = Case(
        (
            Field("café", TypeSpec(Kind.STRING), False),
            Field("tick", TypeSpec(Kind.TIMESTAMP, unit="us", timezone="Etc/É"), False),
        ),
        (("İstanbul 🧪", 0),),
    )
    encoded = case.canonical_bytes()
    decoded = Case.from_json(encoded)
    assert decoded.canonical_bytes() == encoded
    assert decoded.case_id == case.case_id
    assert "İstanbul 🧪".encode() in encoded
    assert case_to_arrow(decoded).num_rows == 1


def test_lone_surrogate_schema_text_is_rejected_during_admission() -> None:
    with pytest.raises(ValueError):
        Field("value\ud800", TypeSpec(Kind.STRING), False)
    with pytest.raises(ValueError):
        TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC\ud800")
    document = {
        "format": "parquity.case.v1",
        "schema": [
            {
                "name": "tick",
                "nullable": False,
                "type": {"kind": "timestamp", "unit": "ns", "timezone": "UTC\ud800"},
            }
        ],
        "rows": [],
    }
    with pytest.raises(ValueError):
        Case.from_data(document)
    with pytest.raises(ValueError):
        Case.from_data(
            {
                "format": "parquity.case.v1",
                "schema": [{"name": "text", "nullable": False, "type": {"kind": "string"}}],
                "rows": [["\ud800"]],
            }
        )


def test_fixed_list_width_matches_the_arrow_signed_int32_boundary() -> None:
    maximum = 2**31 - 1
    spec = TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=maximum)
    case = Case((Field("items", spec, False),), ())
    assert case_to_arrow(case).num_rows == 0

    with pytest.raises(ValueError):
        TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=maximum + 1)
    document = {
        "format": "parquity.case.v1",
        "schema": [
            {
                "name": "items",
                "nullable": False,
                "type": {
                    "kind": "fixed_list",
                    "item": {"kind": "int32"},
                    "item_nullable": True,
                    "size": maximum + 1,
                },
            }
        ],
        "rows": [],
    }
    with pytest.raises(ValueError):
        Case.from_data(document)


def test_nullable_fixed_list_with_required_items_converts_a_null_value() -> None:
    spec = TypeSpec(
        Kind.FIXED_LIST,
        item=TypeSpec(Kind.BOOL),
        item_nullable=False,
        size=1,
    )
    case = Case((Field("value", spec, nullable=True),), ((None,),))

    table = case_to_arrow(case)

    assert table.num_rows == 1
    expected = pa.schema(
        [
            pa.field(
                "value",
                pa.list_(pa.field("item", pa.bool_(), nullable=False), list_size=1),
                nullable=True,
            )
        ]
    )
    assert table.schema == expected
    assert table.column("value").to_pylist() == [None]
