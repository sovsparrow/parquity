from __future__ import annotations

import math
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from decimal import Decimal
from typing import cast

from ..case import decimal_from_coefficient, float_bits
from ..model import Case, Field, Kind, TypeSpec


def container_cases(case: Case) -> Iterator[Case]:
    for index, field in enumerate(case.fields):
        values = _column(case, index)
        for type_spec, replacements in _container_variants(field.type_spec, values):
            candidate = _replace_field(
                case, index, replace(field, type_spec=type_spec), replacements
            )
            if candidate is not None:
                yield candidate


def scalar_cases(case: Case) -> Iterator[Case]:
    for row_index, row in enumerate(case.rows):
        for column_index, field in enumerate(case.fields):
            for value in _scalar_variants(field.type_spec, row[column_index]):
                rows = list(case.rows)
                replacement = list(row)
                replacement[column_index] = value
                rows[row_index] = tuple(replacement)
                try:
                    yield Case(case.fields, tuple(rows))
                except ValueError:
                    continue


def _container_variants(
    spec: TypeSpec, values: tuple[object, ...]
) -> Iterator[tuple[TypeSpec, tuple[object, ...]]]:
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        yield from _list_container_variants(spec, values)
    elif spec.kind is Kind.STRUCT:
        yield from _struct_container_variants(spec, values)
    elif spec.kind is Kind.MAP:
        yield from _map_container_variants(spec, values)


def _list_container_variants(
    spec: TypeSpec, values: tuple[object, ...]
) -> Iterator[tuple[TypeSpec, tuple[object, ...]]]:
    if spec.kind is Kind.LIST:
        for row_index, value in enumerate(values):
            if value is None:
                continue
            items = list(_sequence(value))
            for item_index in range(len(items)):
                replacements = list(values)
                replacements[row_index] = items[:item_index] + items[item_index + 1 :]
                yield spec, tuple(replacements)
    elif cast(int, spec.size) > 1:
        for item_index in range(cast(int, spec.size)):
            replacements = tuple(
                None
                if value is None
                else list(_sequence(value))[:item_index] + list(_sequence(value))[item_index + 1 :]
                for value in values
            )
            yield replace(spec, size=cast(int, spec.size) - 1), replacements
    item = cast(TypeSpec, spec.item)
    locations = _list_locations(values)
    child_values = tuple(value for _, _, value in locations)
    for child_spec, child_replacements in _container_variants(item, child_values):
        rebuilt = [None if value is None else list(_sequence(value)) for value in values]
        for (row_index, item_index, _), replacement in zip(
            locations, child_replacements, strict=True
        ):
            cast(list[object], rebuilt[row_index])[item_index] = replacement
        yield replace(spec, item=child_spec), tuple(rebuilt)


def _struct_container_variants(
    spec: TypeSpec, values: tuple[object, ...]
) -> Iterator[tuple[TypeSpec, tuple[object, ...]]]:
    if len(spec.fields) > 1:
        for index, field in enumerate(spec.fields):
            fields = spec.fields[:index] + spec.fields[index + 1 :]
            replacements = tuple(
                None
                if value is None
                else {key: item for key, item in _mapping(value).items() if key != field.name}
                for value in values
            )
            yield replace(spec, fields=fields), replacements
    for index, field in enumerate(spec.fields):
        child_values = tuple(_mapping(value)[field.name] for value in values if value is not None)
        for child_spec, child_replacements in _container_variants(field.type_spec, child_values):
            replacement_iter = iter(child_replacements)
            rebuilt = tuple(
                None if value is None else {**_mapping(value), field.name: next(replacement_iter)}
                for value in values
            )
            fields = _replace_tuple(spec.fields, index, replace(field, type_spec=child_spec))
            yield replace(spec, fields=fields), rebuilt


def _map_container_variants(
    spec: TypeSpec, values: tuple[object, ...]
) -> Iterator[tuple[TypeSpec, tuple[object, ...]]]:
    for row_index, value in enumerate(values):
        if value is None:
            continue
        entries = list(_sequence(value))
        for entry_index in range(len(entries)):
            replacements = list(values)
            replacements[row_index] = entries[:entry_index] + entries[entry_index + 1 :]
            yield spec, tuple(replacements)
    locations = _map_locations(values)
    for offset, child_spec in ((0, cast(TypeSpec, spec.key)), (1, cast(TypeSpec, spec.value))):
        child_values = tuple(_sequence(entry)[offset] for _, _, entry in locations)
        for replacement_spec, replacements in _container_variants(child_spec, child_values):
            rebuilt = [
                None if value is None else [list(_sequence(item)) for item in _sequence(value)]
                for value in values
            ]
            for (row, entry, _), replacement in zip(locations, replacements, strict=True):
                cast(list[list[object]], rebuilt[row])[entry][offset] = replacement
            change = {"key": replacement_spec} if offset == 0 else {"value": replacement_spec}
            yield replace(spec, **change), tuple(rebuilt)


def _scalar_variants(spec: TypeSpec, value: object) -> Iterator[object]:
    if value is None:
        return
    if spec.kind not in (Kind.LIST, Kind.FIXED_LIST, Kind.STRUCT, Kind.MAP):
        yield from _simpler_scalar_values(spec, value)
    elif spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        yield from _list_scalar_variants(spec, value)
    elif spec.kind is Kind.STRUCT:
        yield from _struct_scalar_variants(spec, value)
    else:
        yield from _map_scalar_variants(spec, value)


def _list_scalar_variants(spec: TypeSpec, value: object) -> Iterator[object]:
    items = list(_sequence(value))
    for index, item in enumerate(items):
        for child in _scalar_variants(cast(TypeSpec, spec.item), item):
            replacement = list(items)
            replacement[index] = child
            yield replacement


def _struct_scalar_variants(spec: TypeSpec, value: object) -> Iterator[object]:
    mapping = _mapping(value)
    for field in spec.fields:
        for child in _scalar_variants(field.type_spec, mapping[field.name]):
            yield {**mapping, field.name: child}


def _map_scalar_variants(spec: TypeSpec, value: object) -> Iterator[object]:
    entries = [list(_sequence(entry)) for entry in _sequence(value)]
    for index, entry in enumerate(entries):
        children = ((0, cast(TypeSpec, spec.key)), (1, cast(TypeSpec, spec.value)))
        for offset, child_spec in children:
            for child in _scalar_variants(child_spec, entry[offset]):
                replacement = [list(item) for item in entries]
                replacement[index][offset] = child
                yield replacement


def _simpler_scalar_values(spec: TypeSpec, value: object) -> Iterator[object]:
    if spec.kind is Kind.BOOL:
        simple: tuple[object, ...] = (False,)
    elif spec.kind in (Kind.INT32, Kind.INT64, Kind.DATE32, Kind.TIMESTAMP):
        simple = (0, 1, -1)
    elif spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        simple = (0.0, -0.0, 1.0, -1.0, math.inf, -math.inf, math.nan)
    elif spec.kind is Kind.DECIMAL128:
        scale = cast(int, spec.scale)
        simple = tuple(decimal_from_coefficient(item, scale) for item in (0, 1, -1))
    elif spec.kind is Kind.STRING:
        simple = ("",)
    else:
        simple = (b"",)
    for candidate in simple:
        if _same_scalar(spec, candidate, value):
            return
        yield candidate


def _same_scalar(spec: TypeSpec, left: object, right: object) -> bool:
    if spec.kind in (Kind.FLOAT32, Kind.FLOAT64):
        return float_bits(spec.kind, left) == float_bits(spec.kind, right)
    if spec.kind is Kind.DECIMAL128:
        return cast(Decimal, left).as_tuple() == cast(Decimal, right).as_tuple()
    return left == right


def _replace_field(case: Case, index: int, field: Field, values: tuple[object, ...]) -> Case | None:
    fields = _replace_tuple(case.fields, index, field)
    rows = tuple(
        (*row[:index], value, *row[index + 1 :])
        for row, value in zip(case.rows, values, strict=True)
    )
    try:
        return Case(fields, rows)
    except ValueError:
        return None


def _replace_tuple(values: tuple[Field, ...], index: int, value: Field) -> tuple[Field, ...]:
    return (*values[:index], value, *values[index + 1 :])


def _column(case: Case, index: int) -> tuple[object, ...]:
    return tuple(row[index] for row in case.rows)


def _list_locations(values: tuple[object, ...]) -> tuple[tuple[int, int, object], ...]:
    return tuple(
        (row, item, value)
        for row, container in enumerate(values)
        if container is not None
        for item, value in enumerate(_sequence(container))
    )


def _map_locations(values: tuple[object, ...]) -> tuple[tuple[int, int, object], ...]:
    return _list_locations(values)


def _sequence(value: object) -> Sequence[object]:
    return cast(Sequence[object], value)


def _mapping(value: object) -> Mapping[str, object]:
    return cast(Mapping[str, object], value)


__all__ = ["container_cases", "scalar_cases"]
