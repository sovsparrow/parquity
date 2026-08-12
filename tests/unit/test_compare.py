from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast, overload

import pyarrow as pa

from parquity.comparison.table import ComparisonResult, compare_case
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import Verdict


class _ArrayFactory(Protocol):
    def __call__(
        self,
        values: Sequence[object],
        **options: pa.DataType,
    ) -> pa.Array[pa.Scalar[pa.DataType]]: ...


class _TableFactory(Protocol):
    @overload
    def __call__(
        self,
        data: Sequence[pa.Array[pa.Scalar[pa.DataType]]],
        *,
        schema: pa.Schema,
    ) -> pa.Table: ...

    @overload
    def __call__(self, data: Mapping[str, Sequence[object]]) -> pa.Table: ...


class _PyArrowModule(Protocol):
    array: _ArrayFactory
    table: _TableFactory


_PYARROW = cast(_PyArrowModule, cast(object, pa))


def test_semantically_equal_scalar_and_nested_values_return_typed_pass_evidence() -> None:
    fields = (
        Field("flag", TypeSpec(Kind.BOOL), nullable=False),
        Field("small", TypeSpec(Kind.INT32), nullable=False),
        Field("large", TypeSpec(Kind.INT64), nullable=False),
        Field("label", TypeSpec(Kind.STRING), nullable=False),
        Field("payload", TypeSpec(Kind.BINARY), nullable=False),
        Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)), nullable=False),
        Field(
            "fixed",
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
                fields=(Field("note", TypeSpec(Kind.STRING)),),
            ),
            nullable=False,
        ),
    )
    row = (True, 7, 2**40, "ok", b"data", [1, None], [True, False], {"note": None})
    case = Case(fields, (row,))
    schema = pa.schema(
        [
            pa.field("flag", pa.bool_(), nullable=False),
            pa.field("small", pa.int32(), nullable=False),
            pa.field("large", pa.int64(), nullable=False),
            pa.field("label", pa.string(), nullable=False),
            pa.field("payload", pa.binary(), nullable=False),
            pa.field("items", pa.list_(pa.field("item", pa.int32())), nullable=False),
            pa.field(
                "fixed",
                pa.list_(pa.field("item", pa.bool_(), nullable=False), list_size=2),
                nullable=False,
            ),
            pa.field(
                "record",
                pa.struct([pa.field("note", pa.string())]),
                nullable=False,
            ),
        ]
    )
    table = pa.Table.from_pylist(
        [
            {
                "flag": True,
                "small": 7,
                "large": 2**40,
                "label": "ok",
                "payload": b"data",
                "items": [1, None],
                "fixed": [True, False],
                "record": {"note": None},
            }
        ],
        schema=schema,
    )

    result = compare_case(case, table)

    assert result == ComparisonResult(Verdict.PASS, "$", "semantic schema and values match")
    assert result.passed


def test_schema_type_disagreements_report_distinct_semantic_paths() -> None:
    scalar = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ())
    mapping = TypeSpec(
        Kind.MAP, key=TypeSpec(Kind.INT32), value=TypeSpec(Kind.STRING), value_nullable=False
    )
    mapped = Case((Field("value", mapping, nullable=False),), ())
    disagreements = (
        (scalar, pa.int64(), "$schema.value"),
        (mapped, pa.map_(pa.int64(), pa.string()), "$schema.value.key"),
        (mapped, pa.map_(pa.int32(), pa.binary()), "$schema.value.value"),
    )
    for case, observed_type, expected_path in disagreements:
        table = _PYARROW.table(
            [_PYARROW.array([], type=observed_type)],
            schema=pa.schema([pa.field("value", observed_type)]),
        )
        result = compare_case(case, table)
        assert (result.verdict, result.path) == (Verdict.SCHEMA_MISMATCH, expected_path)


def test_container_expectations_reject_scalar_arrow_type_at_field_path() -> None:
    table = _PYARROW.table(
        [_PYARROW.array([], type=pa.int32())],
        schema=pa.schema([pa.field("value", pa.int32())]),
    )
    expectations = (
        TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)),
        TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.INT32), size=1),
        TypeSpec(
            Kind.STRUCT,
            fields=(Field("child", TypeSpec(Kind.INT32)),),
        ),
    )

    for expectation in expectations:
        case = Case((Field("value", expectation),), ())

        result = compare_case(case, table)

        assert result.verdict is Verdict.SCHEMA_MISMATCH
        assert result.path == "$schema.value"


def test_struct_shape_disagreements_report_exact_semantic_paths() -> None:
    expected = TypeSpec(
        Kind.STRUCT,
        fields=(Field("child", TypeSpec(Kind.INT32)),),
    )
    case = Case((Field("record", expected),), ())
    disagreements = (
        (
            pa.struct(
                [
                    pa.field("child", pa.int32()),
                    pa.field("extra", pa.int32()),
                ]
            ),
            "$schema.record",
        ),
        (pa.struct([pa.field("other", pa.int32())]), "$schema.record.child"),
        (pa.struct([pa.field("child", pa.int64())]), "$schema.record.child"),
    )

    for observed_type, expected_path in disagreements:
        table = _PYARROW.table(
            [_PYARROW.array([], type=observed_type)],
            schema=pa.schema([pa.field("record", observed_type)]),
        )

        result = compare_case(case, table)

        assert result.verdict is Verdict.SCHEMA_MISMATCH
        assert result.path == expected_path


def test_schema_name_disagreement_is_not_misreported_as_a_value_failure() -> None:
    case = Case((Field("expected", TypeSpec(Kind.BOOL)),), ((True,),))
    table = _PYARROW.table({"observed": [True]})

    result = compare_case(case, table)

    assert result.verdict is Verdict.SCHEMA_MISMATCH
    assert result.path == "$schema"


def test_row_count_disagreement_precedes_value_comparison() -> None:
    case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,), (2,)))
    table = _PYARROW.table(
        [_PYARROW.array([1], type=pa.int32())],
        schema=pa.schema([pa.field("value", pa.int32())]),
    )

    result = compare_case(case, table)

    assert result.verdict is Verdict.ROW_COUNT_MISMATCH
    assert result.path == "$rows"


def test_nested_value_disagreement_reports_the_exact_list_element_path() -> None:
    field = Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32)), nullable=False)
    case = Case((field,), (([1, 2],),))
    schema = pa.schema([pa.field("items", pa.list_(pa.field("item", pa.int32())), nullable=False)])
    table = pa.Table.from_pylist([{"items": [1, 3]}], schema=schema)

    result = compare_case(case, table)

    assert result.verdict is Verdict.VALUE_MISMATCH
    assert result.path == "$rows[0].items[1]"


def test_fixed_list_accepts_ordinary_list_with_matching_child_type_and_width() -> None:
    fixed_case = Case(
        (
            Field(
                "items",
                TypeSpec(
                    Kind.FIXED_LIST,
                    item=TypeSpec(Kind.BOOL),
                    item_nullable=False,
                    size=2,
                ),
                nullable=False,
            ),
        ),
        (([True, False],),),
    )
    ordinary_list_table = pa.Table.from_pylist(
        [{"items": [True, False]}],
        schema=pa.schema(
            [pa.field("items", pa.list_(pa.field("item", pa.bool_())), nullable=True)]
        ),
    )

    result = compare_case(fixed_case, ordinary_list_table)

    assert result.verdict is Verdict.PASS
    assert result.path == "$"


def test_fixed_list_wrong_observed_width_is_value_evidence_at_row_path() -> None:
    fixed_case = Case(
        (
            Field(
                "items",
                TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=2),
            ),
        ),
        (([True, False],),),
    )
    wrong_width_table = pa.Table.from_pylist(
        [{"items": [True, False, True]}],
        schema=pa.schema([pa.field("items", pa.list_(pa.field("item", pa.bool_())))]),
    )

    result = compare_case(fixed_case, wrong_width_table)

    assert result.verdict is Verdict.VALUE_MISMATCH
    assert result.path == "$rows[0].items"


def test_recursive_nullability_metadata_alone_does_not_fail() -> None:
    integer = TypeSpec(Kind.INT32)
    case = Case(
        (
            Field("scalar", integer, nullable=False),
            Field(
                "record",
                TypeSpec(Kind.STRUCT, fields=(Field("child", integer, nullable=False),)),
                nullable=False,
            ),
            Field(
                "items",
                TypeSpec(Kind.LIST, item=integer, item_nullable=False),
                nullable=False,
            ),
            Field(
                "fixed",
                TypeSpec(Kind.FIXED_LIST, item=integer, item_nullable=False, size=2),
                nullable=False,
            ),
            Field(
                "mapping",
                TypeSpec(
                    Kind.MAP,
                    key=integer,
                    value=TypeSpec(Kind.STRING),
                    value_nullable=False,
                ),
                nullable=False,
            ),
        ),
        (),
    )
    schema = pa.schema(
        [
            pa.field("scalar", pa.int32()),
            pa.field("record", pa.struct([pa.field("child", pa.int32())])),
            pa.field("items", pa.list_(pa.field("item", pa.int32()))),
            pa.field("fixed", pa.list_(pa.field("item", pa.int32()), list_size=2)),
            pa.field("mapping", pa.map_(pa.int32(), pa.string())),
        ]
    )

    result = compare_case(case, pa.Table.from_pylist([], schema=schema))

    assert (result.verdict, result.path) == (Verdict.PASS, "$")


def test_null_and_list_length_disagreements_remain_value_evidence() -> None:
    scalar_case = Case((Field("value", TypeSpec(Kind.STRING)),), (("present",),))
    null_table = _PYARROW.table(
        [_PYARROW.array([None], type=pa.string())],
        schema=pa.schema([pa.field("value", pa.string())]),
    )
    list_case = Case(
        (Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32))),),
        (([1, 2],),),
    )
    short_table = pa.Table.from_pylist(
        [{"items": [1]}],
        schema=pa.schema([pa.field("items", pa.list_(pa.field("item", pa.int32())))]),
    )

    null_result = compare_case(scalar_case, null_table)
    length_result = compare_case(list_case, short_table)

    assert null_result.verdict is Verdict.VALUE_MISMATCH
    assert null_result.path == "$rows[0].value"
    assert length_result.verdict is Verdict.VALUE_MISMATCH
    assert length_result.path == "$rows[0].items"
