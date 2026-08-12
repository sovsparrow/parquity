from __future__ import annotations

from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from ..case.types import FIELD_KEYS, type_keys
from ..evidence import json_codec
from ..model import CASE_FORMAT, Case, Field, Kind, TypeSpec
from ..verdicts import CaseEvaluator, MatrixRun
from .limits import MAX_DEPTH, MAX_LIST_WIDTH, MAX_NODES, MAX_ROWS, MAX_SLOTS
from .strategies import value_strategy

MAX_SCHEMA_DEPTH = MAX_DEPTH
MAX_SCHEMA_NODES = MAX_NODES
MAX_SCHEMA_SLOTS = MAX_SLOTS


class SchemaProfileError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class SchemaPlan:
    fields: tuple[Field, ...]
    schema_case_id: str

    @classmethod
    def from_case(cls, case: Case) -> SchemaPlan:
        if case.rows:
            raise SchemaProfileError("INVALID_SCHEMA", "schema Case rows must be empty")
        _validate_budget(case.fields)
        return cls(case.fields, Case(case.fields, ()).case_id)

    def cases(self) -> SearchStrategy[Case]:
        row = st.tuples(*(value_strategy(field.type_spec, field.nullable) for field in self.fields))
        rows = st.lists(row, min_size=0, max_size=MAX_ROWS).map(tuple)
        return rows.map(self._case)

    def admits(self, candidate: Case) -> bool:
        return Case(candidate.fields, ()).case_id == self.schema_case_id

    def bind(self, evaluator: CaseEvaluator) -> SchemaEvaluator:
        return SchemaEvaluator(self, evaluator)

    def _case(self, rows: tuple[tuple[object, ...], ...]) -> Case:
        return Case(self.fields, rows)


@dataclass(frozen=True, slots=True)
class SchemaEvaluator:
    plan: SchemaPlan
    evaluator: CaseEvaluator

    def __call__(self, case: Case, directory: Path, /) -> MatrixRun:
        self._assert_identity(case)
        run = self.evaluator(case, directory)
        self._assert_identity(case)
        return run

    def _assert_identity(self, case: Case) -> None:
        if not self.plan.admits(case):
            raise RuntimeError("schema identity changed inside the fixed-schema campaign")


def load_schema(path: Path) -> SchemaPlan:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise SchemaProfileError(
            "SCHEMA_UNREADABLE", f"cannot read schema file: {error}"
        ) from error
    try:
        decoded = json_codec.decode(payload)
        data = _schema_document(decoded)
        case = Case.from_data(data)
        return SchemaPlan.from_case(case)
    except SchemaProfileError:
        raise
    except RecursionError as error:
        raise SchemaProfileError(
            "INVALID_SCHEMA", "schema input nesting exceeds parser limits"
        ) from error
    except (TypeError, ValueError) as error:
        raise SchemaProfileError("INVALID_SCHEMA", f"schema input is not valid: {error}") from error


def _schema_document(value: object) -> Mapping[str, object]:
    data = _mapping(value)
    _require_keys(data, {"format", "schema", "rows"})
    if data["format"] != CASE_FORMAT:
        raise ValueError("schema input has the wrong format")
    schema = _array(data["schema"])
    rows = _array(data["rows"])
    if rows:
        raise ValueError("schema Case rows must be empty")
    _validate_grammar(schema)
    return data


def _validate_grammar(schema: list[object]) -> None:
    pending = [("field", _mapping(value), 1) for value in schema]
    maximum_depth = 0
    nodes = 0
    while pending:
        entry, data, depth = pending.pop()
        nodes = _bounded_add(nodes, 1, MAX_SCHEMA_NODES)
        if entry == "field":
            _require_keys(data, FIELD_KEYS)
            pending.append(("type", _mapping(data["type"]), depth))
            continue
        maximum_depth = max(maximum_depth, depth)
        kind = Kind(data.get("kind"))
        _require_keys(data, type_keys(kind.value))
        if kind is Kind.LIST or kind is Kind.FIXED_LIST:
            pending.append(("type", _mapping(data["item"]), depth + 1))
        elif kind is Kind.STRUCT:
            pending.extend(
                ("field", _mapping(value), depth + 1) for value in _array(data["fields"])
            )
        elif kind is Kind.MAP:
            pending.append(("type", _mapping(data["key"]), depth + 1))
            pending.append(("type", _mapping(data["value"]), depth + 1))
    if maximum_depth > MAX_SCHEMA_DEPTH or nodes > MAX_SCHEMA_NODES:
        _raise_limit()


def _validate_budget(fields: tuple[Field, ...]) -> None:
    maximum_depth = 0
    nodes = 0
    slots = 0
    for field in fields:
        depth, child_nodes, child_slots = _measure_type(field.type_spec)
        maximum_depth = max(maximum_depth, depth)
        nodes = _bounded_add(nodes, 1 + child_nodes, MAX_SCHEMA_NODES)
        slots = _bounded_add(slots, child_slots, MAX_SCHEMA_SLOTS)
        if maximum_depth > MAX_SCHEMA_DEPTH or nodes > MAX_SCHEMA_NODES or slots > MAX_SCHEMA_SLOTS:
            raise SchemaProfileError(
                "SCHEMA_LIMIT_EXCEEDED", "schema exceeds the fixed generation budget"
            )


def _measure_type(spec: TypeSpec, level: int = 1) -> tuple[int, int, int]:
    if level > MAX_SCHEMA_DEPTH:
        _raise_limit()
    if spec.kind not in (Kind.LIST, Kind.FIXED_LIST, Kind.STRUCT, Kind.MAP):
        return 1, 1, 1
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = cast(TypeSpec, spec.item)
        depth, nodes, slots = _measure_type(item, level + 1)
        width = MAX_LIST_WIDTH if spec.size is None else spec.size
        nodes = _bounded_add(1, nodes, MAX_SCHEMA_NODES)
        slots = _bounded_multiply(width, slots, MAX_SCHEMA_SLOTS)
        if nodes > MAX_SCHEMA_NODES or slots > MAX_SCHEMA_SLOTS:
            _raise_limit()
        return 1 + depth, nodes, slots
    if spec.kind is Kind.MAP:
        key_depth, key_nodes, key_slots = _measure_type(cast(TypeSpec, spec.key), level + 1)
        value_depth, value_nodes, value_slots = _measure_type(cast(TypeSpec, spec.value), level + 1)
        nodes = _bounded_add(
            1, _bounded_add(key_nodes, value_nodes, MAX_SCHEMA_NODES), MAX_SCHEMA_NODES
        )
        pair_slots = _bounded_add(key_slots, value_slots, MAX_SCHEMA_SLOTS)
        slots = _bounded_multiply(MAX_LIST_WIDTH, pair_slots, MAX_SCHEMA_SLOTS)
        if nodes > MAX_SCHEMA_NODES or slots > MAX_SCHEMA_SLOTS:
            _raise_limit()
        return 1 + max(key_depth, value_depth), nodes, slots
    depth = 0
    nodes = 1
    slots = 0
    for field in spec.fields:
        child_depth, child_nodes, child_slots = _measure_type(field.type_spec, level + 1)
        depth = max(depth, child_depth)
        nodes = _bounded_add(nodes, 1 + child_nodes, MAX_SCHEMA_NODES)
        slots = _bounded_add(slots, child_slots, MAX_SCHEMA_SLOTS)
        if nodes > MAX_SCHEMA_NODES or slots > MAX_SCHEMA_SLOTS:
            _raise_limit()
    return 1 + depth, nodes, slots


def _raise_limit() -> None:
    raise SchemaProfileError("SCHEMA_LIMIT_EXCEEDED", "schema exceeds the fixed generation budget")


def _bounded_add(left: int, right: int, limit: int) -> int:
    if left > limit or right > limit - left:
        return limit + 1
    return left + right


def _bounded_multiply(left: int, right: int, limit: int) -> int:
    if left > limit or right > limit or (left and right > limit // left):
        return limit + 1
    return left * right


def _mapping(value: object) -> Mapping[str, object]:
    return json_codec.mapping(value, "schema input")


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("schema input field must be an array")
    return cast(list[object], value)


def _require_keys(data: Mapping[str, object], expected: Set[str]) -> None:
    if set(data) != expected:
        raise ValueError("schema input fields are malformed")


__all__ = [
    "MAX_SCHEMA_DEPTH",
    "MAX_SCHEMA_NODES",
    "MAX_SCHEMA_SLOTS",
    "SchemaPlan",
    "SchemaProfileError",
    "load_schema",
]
