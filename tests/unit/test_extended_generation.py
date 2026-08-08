from __future__ import annotations

from decimal import Decimal
from typing import cast

import pytest
from hypothesis import find, given, settings

from parquity.case import semantic_key_bytes
from parquity.generation.reduction_values import container_cases, scalar_cases
from parquity.generation.schema import SchemaPlan, SchemaProfileError
from parquity.generation.strategies import bounded_cases, value_strategy
from parquity.model import Case, Field, Kind, TypeSpec

_SEARCH = settings(max_examples=300, database=None, deadline=None)


def test_boundary_weighted_scalar_strategies_reach_frozen_classes() -> None:
    f32 = find(
        value_strategy(TypeSpec(Kind.FLOAT32), False),
        lambda value: isinstance(value, float) and value != value,
        settings=_SEARCH,
    )
    day = find(
        value_strategy(TypeSpec(Kind.DATE32), False),
        lambda value: value == -(2**31),
        settings=_SEARCH,
    )
    timestamp = find(
        value_strategy(TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC"), False),
        lambda value: value == 1_615_705_200_000_000_000,
        settings=_SEARCH,
    )
    decimal = cast(
        Decimal,
        find(
            value_strategy(TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),
            lambda value: value == Decimal("99.99"),
            settings=_SEARCH,
        ),
    )
    negative_fraction = find(
        value_strategy(TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),
        lambda value: value == Decimal("-0.01"),
        settings=_SEARCH,
    )
    assert f32 != f32
    assert day == -(2**31)
    assert timestamp == 1_615_705_200_000_000_000
    assert decimal.as_tuple().exponent == -2
    assert negative_fraction == Decimal("-0.01")
    reduced = Case(
        (Field("amount", TypeSpec(Kind.DECIMAL128, precision=4, scale=2), False),),
        ((Decimal("12.34"),),),
    )
    candidate = next(item for item in scalar_cases(reduced) if item.rows[0][0] == negative_fraction)
    assert (
        Case.from_json(candidate.canonical_bytes()).canonical_bytes() == candidate.canonical_bytes()
    )


def test_generic_generation_reaches_maps_with_extended_key_or_value_types() -> None:
    case = find(
        bounded_cases(),
        lambda value: any(
            field.type_spec.kind is Kind.MAP
            and (
                field.type_spec.key.kind in {Kind.FLOAT32, Kind.FLOAT64, Kind.DATE32}
                or field.type_spec.value.kind
                in {Kind.TIMESTAMP, Kind.DECIMAL128, Kind.FLOAT32, Kind.FLOAT64}
            )
            for field in value.fields
        ),
        settings=_SEARCH,
    )
    assert len(case.rows) <= 4
    assert len(case.fields) <= 4


@given(
    entries=value_strategy(
        TypeSpec(
            Kind.MAP,
            key=TypeSpec(Kind.FLOAT32),
            value=TypeSpec(Kind.DECIMAL128, precision=5, scale=2),
            value_nullable=True,
        ),
        False,
    )
)
@settings(max_examples=50, database=None, deadline=None)
def test_map_generation_constructs_bounded_semantically_unique_keys(entries: object) -> None:
    values = cast(list[list[object]], entries)
    identities = [semantic_key_bytes(TypeSpec(Kind.FLOAT32), entry[0]) for entry in values]
    assert len(values) <= 4
    assert len(identities) == len(set(identities))


def test_schema_budget_uses_exact_expanded_map_slot_arithmetic() -> None:
    integer = TypeSpec(Kind.INT32)
    at_limit = TypeSpec(
        Kind.MAP,
        key=integer,
        value=TypeSpec(Kind.FIXED_LIST, item=integer, item_nullable=False, size=63),
        value_nullable=False,
    )
    over_limit = TypeSpec(
        Kind.MAP,
        key=integer,
        value=TypeSpec(Kind.FIXED_LIST, item=integer, item_nullable=False, size=64),
        value_nullable=False,
    )
    plan = SchemaPlan.from_case(Case((Field("lookup", at_limit, False),), ()))
    assert plan.fields[0].type_spec == at_limit
    with pytest.raises(SchemaProfileError) as raised:
        SchemaPlan.from_case(Case((Field("lookup", over_limit, False),), ()))
    assert raised.value.kind == "SCHEMA_LIMIT_EXCEEDED"


def test_map_reduction_preserves_schema_uniqueness_and_reaches_key_value_children() -> None:
    spec = TypeSpec(
        Kind.MAP,
        key=TypeSpec(Kind.INT32),
        value=TypeSpec(Kind.FLOAT64),
        value_nullable=False,
    )
    case = Case((Field("lookup", spec, False),), (([[7, 9.0], [8, -0.0]],),))
    containers = tuple(container_cases(case))
    scalars = tuple(scalar_cases(case))
    assert any(len(cast(list[object], candidate.rows[0][0])) == 1 for candidate in containers)
    assert any(
        cast(list[list[object]], candidate.rows[0][0])[0][0] in (0, 1, -1) for candidate in scalars
    )
    assert any(
        cast(list[list[object]], candidate.rows[0][0])[0][1] in (0.0, -0.0, 1.0, -1.0)
        for candidate in scalars
    )
    assert all(candidate.fields == case.fields for candidate in (*containers, *scalars))
