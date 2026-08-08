from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from typing import cast

from ..model import Case, Field, Kind, TypeSpec
from ..verdicts import FailureFingerprint, MatrixRun
from .reduction_values import container_cases, scalar_cases

Evaluate = Callable[[Case], MatrixRun]
CandidateAdmission = Callable[[Case], bool]


def admit_every_candidate(case: Case) -> bool:
    del case
    return True


@dataclass(frozen=True, slots=True)
class ReductionCounts:
    fields: int = 0
    rows: int = 0
    nullability: int = 0
    containers: int = 0
    scalars: int = 0

    @property
    def total(self) -> int:
        return self.fields + self.rows + self.nullability + self.containers + self.scalars

    def to_data(self) -> dict[str, object]:
        return {
            "fields": self.fields,
            "rows": self.rows,
            "nullability": self.nullability,
            "containers": self.containers,
            "scalars": self.scalars,
            "total": self.total,
        }


@dataclass(frozen=True, slots=True)
class StructuralReduction:
    case: Case
    run: MatrixRun
    counts: ReductionCounts


def reduce_case(
    case: Case,
    run: MatrixRun,
    fingerprint: FailureFingerprint,
    evaluate: Evaluate,
    candidate_admission: CandidateAdmission = admit_every_candidate,
) -> StructuralReduction:
    current_case = case
    current_run = run
    categories: tuple[tuple[str, Callable[[Case], Iterator[Case]]], ...] = (
        ("fields", _field_cases),
        ("rows", _row_cases),
        ("nullability", _nullability_cases),
        ("containers", container_cases),
        ("scalars", scalar_cases),
    )
    values: dict[str, int] = {name: 0 for name, _ in categories}
    accepted_states = {current_case.canonical_bytes()}
    while True:
        sweep_accepted = 0
        for name, candidates in categories:
            current_case, current_run, accepted = _reduce_category(
                current_case,
                current_run,
                fingerprint,
                evaluate,
                candidates,
                candidate_admission,
                accepted_states,
            )
            values[name] += accepted
            sweep_accepted += accepted
        if sweep_accepted == 0:
            break
    return StructuralReduction(current_case, current_run, ReductionCounts(**values))


def _reduce_category(
    case: Case,
    run: MatrixRun,
    fingerprint: FailureFingerprint,
    evaluate: Evaluate,
    candidates: Callable[[Case], Iterator[Case]],
    candidate_admission: CandidateAdmission,
    accepted_states: set[bytes],
) -> tuple[Case, MatrixRun, int]:
    accepted = 0
    while True:
        replacement: tuple[Case, MatrixRun] | None = None
        for candidate in candidates(case):
            if not candidate_admission(candidate):
                continue
            candidate_bytes = candidate.canonical_bytes()
            if candidate_bytes == case.canonical_bytes():
                continue
            candidate_run = evaluate(candidate)
            if any(result.fingerprint == fingerprint for result in candidate_run.failures):
                if candidate_bytes in accepted_states:
                    raise RuntimeError("structural reduction cycle detected")
                accepted_states.add(candidate_bytes)
                replacement = (candidate, candidate_run)
                break
        if replacement is None:
            return case, run, accepted
        case, run = replacement
        accepted += 1


def _field_cases(case: Case) -> Iterator[Case]:
    if len(case.fields) == 1:
        return
    for index in range(len(case.fields)):
        fields = case.fields[:index] + case.fields[index + 1 :]
        rows = tuple(row[:index] + row[index + 1 :] for row in case.rows)
        yield Case(fields, rows)


def _row_cases(case: Case) -> Iterator[Case]:
    for index in range(len(case.rows)):
        yield Case(case.fields, case.rows[:index] + case.rows[index + 1 :])


def _nullability_cases(case: Case) -> Iterator[Case]:
    for index, field in enumerate(case.fields):
        values = _column(case, index)
        if field.nullable:
            candidate = _replace_field(case, index, replace(field, nullable=False), values)
            if candidate is not None:
                yield candidate
        for type_spec in _type_nullability_variants(field.type_spec):
            candidate = _replace_field(case, index, replace(field, type_spec=type_spec), values)
            if candidate is not None:
                yield candidate


def _type_nullability_variants(spec: TypeSpec) -> Iterator[TypeSpec]:
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        yield from _list_nullability_variants(spec)
    elif spec.kind is Kind.STRUCT:
        yield from _struct_nullability_variants(spec)
    elif spec.kind is Kind.MAP:
        yield from _map_nullability_variants(spec)


def _list_nullability_variants(spec: TypeSpec) -> Iterator[TypeSpec]:
    if spec.item_nullable:
        yield replace(spec, item_nullable=False)
    for child in _type_nullability_variants(cast(TypeSpec, spec.item)):
        yield replace(spec, item=child)


def _struct_nullability_variants(spec: TypeSpec) -> Iterator[TypeSpec]:
    for index, field in enumerate(spec.fields):
        if field.nullable:
            fields = _replace_tuple(spec.fields, index, replace(field, nullable=False))
            yield replace(spec, fields=fields)
        for child in _type_nullability_variants(field.type_spec):
            fields = _replace_tuple(spec.fields, index, replace(field, type_spec=child))
            yield replace(spec, fields=fields)


def _map_nullability_variants(spec: TypeSpec) -> Iterator[TypeSpec]:
    if spec.value_nullable:
        yield replace(spec, value_nullable=False)
    for key in _type_nullability_variants(cast(TypeSpec, spec.key)):
        yield replace(spec, key=key)
    for value in _type_nullability_variants(cast(TypeSpec, spec.value)):
        yield replace(spec, value=value)


def _replace_field(
    case: Case,
    index: int,
    field: Field,
    values: tuple[object, ...],
) -> Case | None:
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


__all__ = [
    "CandidateAdmission",
    "ReductionCounts",
    "StructuralReduction",
    "admit_every_candidate",
    "reduce_case",
]
