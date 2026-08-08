from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import NamedTuple

from ..model import Case, Field, Kind, TypeSpec
from ..scans import symptoms


class DetailRule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    replacement: str


DETAIL_RULES_V1 = (
    DetailRule(
        "temporary-root-separator", re.compile(r"<parquity-temp>[/\\]+"), "<parquity-temp>/"
    ),
    DetailRule("whitespace", re.compile(r"\s+"), " "),
)
_GENERATED_ROW = re.compile(r"^\$rows\[(?:0|[1-9][0-9]*)\]")
_CONTAINER_ITEM = re.compile(r"^\[(0|[1-9][0-9]*)\]")
_MAP_ENTRY = re.compile(r"^\.entries\[sha256=([0-9a-f]{64})\]")
_UNRESOLVED_FIELD = re.compile(r"\.[A-Za-z_][A-Za-z0-9_]*")


def normalize_detail_v1(detail: str) -> str:
    normalized = detail
    for rule in DETAIL_RULES_V1:
        normalized = rule.pattern.sub(rule.replacement, normalized)
    return normalized.strip()


def detail_sha256_v1(detail: str) -> str:
    return hashlib.sha256(normalize_detail_v1(detail).encode()).hexdigest()


def normalize_generated_path(path: str, case: Case) -> object:
    row_match = _GENERATED_ROW.match(path)
    if row_match is not None:
        remainder = path[row_match.end() :]
        normalized_row = "$rows[*]"
        field_match = _top_level_field(remainder, case)
        if field_match is None:
            return normalized_row + remainder
        field, suffix = field_match
        return {
            "root": "rows",
            "row": "*",
            "column": field_shape(field),
            "path": _nested_path(suffix, field.type_spec),
        }
    if path.startswith("$schema."):
        field_match = _top_level_field(path[len("$schema") :], case)
        if field_match is not None:
            field, suffix = field_match
            return {
                "root": "schema",
                "column": field_shape(field),
                "path": _nested_path(suffix, field.type_spec),
            }
    return path


def normalize_scan_path(path: str) -> str:
    return symptoms.normalize_location(path)


def field_shape(field: Field) -> Mapping[str, object]:
    return {"nullable": field.nullable, "type": type_shape(field.type_spec)}


def type_shape(spec: TypeSpec) -> Mapping[str, object]:
    shape: dict[str, object] = {"kind": spec.kind.value}
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        if spec.item is None:
            raise RuntimeError("validated list type omitted its item shape")
        shape.update(item=type_shape(spec.item), item_nullable=spec.item_nullable)
        if spec.kind is Kind.FIXED_LIST:
            shape["size"] = spec.size
    elif spec.kind is Kind.STRUCT:
        shape["fields"] = [field_shape(field) for field in spec.fields]
    elif spec.kind is Kind.TIMESTAMP:
        shape.update(unit=spec.unit, timezone=spec.timezone)
    elif spec.kind is Kind.DECIMAL128:
        shape.update(precision=spec.precision, scale=spec.scale)
    elif spec.kind is Kind.MAP:
        if spec.key is None or spec.value is None:
            raise RuntimeError("validated map type omitted its key or value shape")
        shape.update(
            key=type_shape(spec.key),
            value=type_shape(spec.value),
            value_nullable=spec.value_nullable,
        )
    return shape


def _top_level_field(remainder: str, case: Case) -> tuple[Field, str] | None:
    if not remainder.startswith("."):
        return None
    for field in case.fields:
        prefix = f".{field.name}"
        if remainder == prefix:
            return field, ""
        if remainder.startswith(prefix) and remainder[len(prefix) : len(prefix) + 1] in (".", "["):
            return field, remainder[len(prefix) :]
    return None


def _nested_path(suffix: str, spec: TypeSpec) -> list[Mapping[str, object]]:
    steps: list[Mapping[str, object]] = []
    remainder = suffix
    current = spec
    while remainder:
        if current.kind is Kind.STRUCT:
            matched = _struct_field(remainder, current.fields)
            if matched is None:
                break
            index, field, remainder = matched
            steps.append({"struct_field": index, "shape": field_shape(field)})
            current = field.type_spec
            continue
        if current.kind in (Kind.LIST, Kind.FIXED_LIST) and current.item is not None:
            item_shape = {
                "nullable": current.item_nullable,
                "type": type_shape(current.item),
            }
            if remainder.startswith("[]"):
                steps.append({"container_item": "schema", "shape": item_shape})
                remainder = remainder[2:]
            elif match := _CONTAINER_ITEM.match(remainder):
                steps.append({"container_item": int(match.group(1)), "shape": item_shape})
                remainder = remainder[match.end() :]
            else:
                break
            current = current.item
            continue
        map_step = _map_path_step(remainder, current)
        if map_step is not None:
            additions, remainder, next_type = map_step
            steps.extend(additions)
            if next_type is not None:
                current = next_type
                continue
            break
        break
    if remainder:
        steps.append({"unresolved": _UNRESOLVED_FIELD.sub(".<field>", remainder)})
    return steps


def _map_path_step(
    remainder: str, spec: TypeSpec
) -> tuple[list[Mapping[str, object]], str, TypeSpec | None] | None:
    if spec.kind is not Kind.MAP or spec.key is None or spec.value is None:
        return None
    for name, child, nullable in (
        ("key", spec.key, False),
        ("value", spec.value, spec.value_nullable),
    ):
        prefix = f".{name}"
        suffix = remainder[len(prefix) :]
        valid_suffix = not suffix or suffix[0] in ".["
        if remainder.startswith(prefix) and valid_suffix:
            step: Mapping[str, object] = {
                f"map_{name}": True,
                "shape": {"nullable": nullable, "type": type_shape(child)},
            }
            return [step], suffix, child
    match = _MAP_ENTRY.match(remainder)
    if match is None:
        return None
    steps: list[Mapping[str, object]] = [
        {"map_entry_sha256": match.group(1), "key": type_shape(spec.key)}
    ]
    remainder = remainder[match.end() :]
    if not remainder.startswith(".value"):
        return steps, remainder, None
    steps.append(
        {
            "map_value": True,
            "shape": {"nullable": spec.value_nullable, "type": type_shape(spec.value)},
        }
    )
    return steps, remainder[len(".value") :], spec.value


def _struct_field(remainder: str, fields: tuple[Field, ...]) -> tuple[int, Field, str] | None:
    if not remainder.startswith("."):
        return None
    for index, field in enumerate(fields):
        prefix = f".{field.name}"
        suffix = remainder[len(prefix) :]
        if remainder.startswith(prefix) and (not suffix or suffix[0] in ".["):
            return index, field, suffix
    return None


__all__ = [
    "DETAIL_RULES_V1",
    "detail_sha256_v1",
    "field_shape",
    "normalize_detail_v1",
    "normalize_generated_path",
    "normalize_scan_path",
    "type_shape",
]
