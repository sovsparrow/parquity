from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from parquity.model import CASE_FORMAT, Case, Field, Kind, TypeSpec

GeneratedRow = tuple[
    bool | None,
    int | None,
    int | None,
    str | None,
    bytes | None,
    list[int | None] | None,
    list[bool],
    dict[str, object],
]


class _FormatProbe(Mapping[str, object]):
    def __init__(self, format_value: object, *, present: bool) -> None:
        self._format_value = format_value
        self._present = present

    def __getitem__(self, key: str) -> object:
        if key != "format":
            raise AssertionError("case content decoded before format validation")
        if not self._present:
            raise KeyError(key)
        return self._format_value

    def __iter__(self) -> Iterator[str]:
        return iter(("format",)) if self._present else iter(())

    def __len__(self) -> int:
        return 1 if self._present else 0


def _fixed_flags(left: bool, right: bool) -> list[bool]:
    return [left, right]


def _record(label: str | None, count: int) -> dict[str, object]:
    return {"label": label, "count": count}


_ROW_STRATEGY = st.tuples(
    st.one_of(st.none(), st.booleans()),
    st.one_of(st.none(), st.integers(-(2**31), 2**31 - 1)),
    st.one_of(st.none(), st.integers(-(2**63), 2**63 - 1)),
    st.one_of(st.none(), st.text(max_size=12)),
    st.one_of(st.none(), st.binary(max_size=12)),
    st.one_of(
        st.none(),
        st.lists(st.one_of(st.none(), st.integers(-(2**31), 2**31 - 1)), max_size=4),
    ),
    st.builds(_fixed_flags, st.booleans(), st.booleans()),
    st.builds(_record, st.one_of(st.none(), st.text(max_size=8)), st.integers(-20, 20)),
)


_ROUND_TRIP_FIELDS = (
    Field("flag", TypeSpec(Kind.BOOL)),
    Field("small", TypeSpec(Kind.INT32)),
    Field("large", TypeSpec(Kind.INT64)),
    Field("label", TypeSpec(Kind.STRING)),
    Field("payload", TypeSpec(Kind.BINARY)),
    Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32))),
    Field(
        "fixed_flags",
        TypeSpec(
            Kind.FIXED_LIST,
            item=TypeSpec(Kind.BOOL),
            item_nullable=False,
            size=2,
        ),
        nullable=False,
    ),
    Field(
        "record",
        TypeSpec(
            Kind.STRUCT,
            fields=(
                Field("label", TypeSpec(Kind.STRING)),
                Field("count", TypeSpec(Kind.INT32), nullable=False),
            ),
        ),
        nullable=False,
    ),
)


@settings(max_examples=30, derandomize=True, database=None, deadline=None)
@given(rows=st.lists(_ROW_STRATEGY, max_size=6))
def test_bounded_cases_round_trip_without_changing_canonical_identity(
    rows: list[GeneratedRow],
) -> None:
    case = Case(_ROUND_TRIP_FIELDS, tuple(rows))

    decoded = Case.from_json(case.canonical_bytes())

    assert decoded == case
    assert decoded.canonical_bytes() == case.canonical_bytes()
    assert case.case_id == hashlib.sha256(case.canonical_bytes()).hexdigest()


def test_canonical_bytes_have_an_independent_stable_binary_and_unicode_oracle() -> None:
    case = Case(
        (
            Field("blob", TypeSpec(Kind.BINARY), nullable=False),
            Field("label", TypeSpec(Kind.STRING), nullable=False),
        ),
        ((b"\x00\xff", "café"),),
    )
    expected = (
        '{"format":"parquity.case.v1","rows":[[{"$binary":"AP8="},"café"]],'
        '"schema":['
        '{"name":"blob","nullable":false,"type":{"kind":"binary"}},'
        '{"name":"label","nullable":false,"type":{"kind":"string"}}]}'
    ).encode()

    assert case.canonical_bytes() == expected
    assert case.case_id == hashlib.sha256(expected).hexdigest()


def test_nullable_struct_child_must_be_present_even_when_its_value_is_null() -> None:
    schema: list[object] = [
        {
            "name": "record",
            "nullable": False,
            "type": {
                "kind": "struct",
                "fields": [{"name": "note", "nullable": True, "type": {"kind": "string"}}],
            },
        }
    ]
    present: dict[str, object] = {
        "format": CASE_FORMAT,
        "schema": schema,
        "rows": [[{"note": None}]],
    }
    missing: dict[str, object] = {
        "format": CASE_FORMAT,
        "schema": schema,
        "rows": [[{}]],
    }

    assert Case.from_data(present).rows == (({"note": None},),)
    with pytest.raises(ValueError):
        Case.from_data(missing)


def test_struct_values_reject_extra_keys_instead_of_discarding_input() -> None:
    struct = TypeSpec(Kind.STRUCT, fields=(Field("note", TypeSpec(Kind.STRING)),))

    with pytest.raises(ValueError):
        Case((Field("record", struct),), (({"note": None, "ignored": "data"},),))


def test_type_specs_reject_ambiguous_or_incomplete_child_configuration() -> None:
    invalid_kind: object = "bool"
    invalid_item_nullable: object = 0

    with pytest.raises(ValueError):
        TypeSpec(cast(Kind, invalid_kind))
    with pytest.raises(ValueError):
        TypeSpec(Kind.BOOL, item_nullable=cast(bool, invalid_item_nullable))
    with pytest.raises(ValueError):
        TypeSpec(Kind.LIST)
    with pytest.raises(ValueError):
        TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32), size=2)
    with pytest.raises(ValueError):
        TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=0)
    with pytest.raises(ValueError):
        TypeSpec(Kind.STRUCT, fields=())
    with pytest.raises(ValueError):
        TypeSpec(
            Kind.STRUCT,
            fields=(Field("value", TypeSpec(Kind.BOOL)), Field("value", TypeSpec(Kind.INT32))),
        )
    with pytest.raises(ValueError):
        TypeSpec(Kind.BOOL, item=TypeSpec(Kind.BOOL))


def test_case_validation_rejects_width_nullability_and_scalar_domain_regressions() -> None:
    with pytest.raises(ValueError):
        Case((), ())
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.BOOL)),), ((),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.BOOL), nullable=False),), ((None,),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.BOOL)),), ((1,),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.INT32)),), ((2**31,),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.INT64)),), ((True,),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.STRING)),), ((b"text",),))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.BINARY)),), (("bytes",),))


def test_field_and_nested_value_validation_rejects_lossy_or_ambiguous_cases() -> None:
    invalid_nullable: object = 1

    with pytest.raises(ValueError):
        Field("not valid", TypeSpec(Kind.BOOL))
    with pytest.raises(ValueError):
        Field("value", TypeSpec(Kind.BOOL), nullable=cast(bool, invalid_nullable))
    with pytest.raises(ValueError):
        Case((Field("value", TypeSpec(Kind.BOOL)), Field("value", TypeSpec(Kind.INT32))), ())
    with pytest.raises(ValueError):
        Case(
            (Field("items", TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=2)),),
            (([True],),),
        )
    with pytest.raises(ValueError):
        Case((Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.BOOL))),), (("not-a-list",),))
    with pytest.raises(ValueError):
        Case(
            (
                Field(
                    "record",
                    TypeSpec(
                        Kind.STRUCT,
                        fields=(Field("flag", TypeSpec(Kind.BOOL)),),
                    ),
                ),
            ),
            (([True],),),
        )


def test_case_decoder_rejects_non_array_rows_and_invalid_binary_envelopes() -> None:
    empty_rows: list[object] = []
    invalid_schema: dict[str, object] = {
        "format": CASE_FORMAT,
        "schema": "not-an-array",
        "rows": empty_rows,
    }
    with pytest.raises(ValueError):
        Case.from_data(invalid_schema)
    with pytest.raises(ValueError):
        Case.from_data(
            {
                "format": CASE_FORMAT,
                "schema": [{"name": "payload", "type": {"kind": "binary"}}],
                "rows": "not-an-array",
            }
        )
    with pytest.raises(ValueError):
        Case.from_data(
            {
                "format": CASE_FORMAT,
                "schema": [{"name": "payload", "type": {"kind": "binary"}}],
                "rows": [[{"$binary": "not base64!"}]],
            }
        )


def test_case_decoder_rejects_missing_or_non_exact_format_before_content() -> None:
    with pytest.raises(ValueError):
        Case.from_data(_FormatProbe(CASE_FORMAT, present=False))
    with pytest.raises(ValueError):
        Case.from_data(_FormatProbe("parquity.case.v2", present=True))
