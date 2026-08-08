from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from typing import cast

from .model import Case, Kind, TypeSpec
from .verdicts import CellResult, Verdict

_MARKDOWN_PUNCTUATION = frozenset("\\`*_{}[]<>()#|&")
_ROW_FIELD = re.compile(r"\$rows\[([0-9]+)\]\.(.*)")
_ROW_COLUMN = re.compile(r"\$\.rows\[([0-9]+)\]\.columns\[([0-9]+)\]")
_MAX_PREVIEW_CELLS = 32


@dataclass(frozen=True, slots=True)
class TypeDescription:
    name: str
    shape: str


def markdown_literal(value: str) -> str:
    rendered = json.dumps(value, ensure_ascii=False)
    return "".join(
        f"\\{character}" if character in _MARKDOWN_PUNCTUATION else character
        for character in rendered
    )


def profile_label(profile: object | None, *, profiled: bool) -> str:
    if not profiled:
        return ""
    if profile is None:
        return " [default]"
    name = getattr(profile, "name", None)
    if not isinstance(name, str):
        raise TypeError("writer profile evidence is malformed")
    return f" [{name}]"


def render_case_schema(case: Case) -> tuple[str, ...]:
    lines = [
        "| # | Column | Type | Nullable | Shape |",
        "|---:|---|---|---|---|",
    ]
    for index, field in enumerate(case.fields, start=1):
        description = describe_type(field.type_spec)
        lines.append(
            f"| {index} | {_code(_field_label(field.name))} | {_code(description.name)} | "
            f"{'yes' if field.nullable else 'no'} | {_text(description.shape)} |"
        )
    return tuple(lines)


def render_case_rows(case: Case) -> tuple[str, ...]:
    rows = cast(list[list[object]], case.to_data()["rows"])
    lines = [
        "| Row | Column | Value |",
        "|---:|---|---|",
    ]
    shown = 0
    for row_index, row in enumerate(rows, start=1):
        for field, value in zip(case.fields, row, strict=True):
            if shown == _MAX_PREVIEW_CELLS:
                remaining = len(rows) * len(case.fields) - shown
                lines.append(f"| … | … | {remaining} more cells; see `case.json` |")
                return tuple(lines)
            rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            lines.append(f"| {row_index} | {_code(_field_label(field.name))} | {_code(rendered)} |")
            shown += 1
    if not rows:
        lines.append("| — | — | This Case has no rows. |")
    return tuple(lines)


def render_pipeline(result: CellResult) -> tuple[str, ...]:
    writer = result.writer + profile_label(result.writer_profile, profiled=True)
    steps = [("1", "Build input", "Case is the expected table")]
    if result.operation == "write":
        steps.append(("2", f"Write with {writer}", _result_text(result)))
    else:
        steps.append(("2", f"Write with {writer}", "completed"))
        if result.operation == "read":
            steps.append(("3", f"Read with {result.reader}", _result_text(result)))
        else:
            steps.extend(
                (
                    ("3", f"Read with {result.reader}", "completed"),
                    ("4", "Compare with the Case", _result_text(result)),
                )
            )
    return (
        "| Step | Stage | Outcome |",
        "|---:|---|---|",
        *(f"| {number} | {_text(stage)} | {_text(outcome)} |" for number, stage, outcome in steps),
    )


def render_difference(result: CellResult, case: Case | None = None) -> tuple[str, ...]:
    location = human_location(result.schema_path, case)
    if result.operation != "compare":
        return (
            f"- Location: {location}",
            f"- Provider diagnostic: {_text(result.diagnostic_kind)}",
            f"- Detail: {markdown_literal(result.detail)}",
        )
    if result.difference is None:
        return (
            f"- Location: {location}",
            "- Structured expected/observed evidence is unavailable for this record.",
            f"- Detail: {markdown_literal(result.detail)}",
        )
    return (
        f"- Location: {location}",
        "",
        "| Expected from the Case | Observed from the reader |",
        "|---|---|",
        f"| {_code(result.difference.expected)} | {_code(result.difference.observed)} |",
        "",
        f"Technical detail: {markdown_literal(result.detail)}",
    )


def render_matrix(
    results: tuple[CellResult, ...],
    *,
    profiled: bool,
    case: Case | None = None,
) -> tuple[str, ...]:
    lines = [
        "| Writer output | Reader | Stage | Result | Location |",
        "|---|---|---|---|---|",
    ]
    for result in results:
        writer = result.writer + profile_label(result.writer_profile, profiled=profiled)
        reader = "—" if result.reader == "*" else result.reader
        location = "—" if result.passed else human_location(result.schema_path, case)
        lines.append(
            f"| {_code(writer)} | {_code(reader)} | {_code(result.operation)} | "
            f"{_code(result.verdict.value)} | {location} |"
        )
    return tuple(lines)


def human_location(path: str, case: Case | None = None) -> str:
    if path == "$":
        return f"whole table ({_code(path)})"
    if path == "$schema":
        return f"table schema ({_code(path)})"
    if path == "$rows":
        return f"row count ({_code(path)})"
    if path.startswith("$schema."):
        name = path.removeprefix("$schema.")
        return f"schema field {_code(_field_label(name))} ({_code(path)})"
    scan_match = _ROW_COLUMN.fullmatch(path)
    if scan_match is not None:
        row, column = (int(value) + 1 for value in scan_match.groups())
        return f"row {row}, column {column} ({_code(path)})"
    match = _ROW_FIELD.fullmatch(path)
    if match is not None:
        row = int(match.group(1)) + 1
        name, suffix = _generated_field(match.group(2), case)
        ordinal = _field_ordinal(case, name)
        column = (
            f"column {ordinal}, {_code(_field_label(name))}"
            if ordinal is not None
            else f"column {_code(_field_label(name))}"
        )
        nested = "" if not suffix else f", nested path {_code(suffix)}"
        return f"row {row}, {column}{nested} ({_code(path)})"
    return f"canonical path {_code(path)}"


def describe_type(spec: TypeSpec) -> TypeDescription:
    if spec.kind in (Kind.LIST, Kind.FIXED_LIST):
        item = describe_type(cast(TypeSpec, spec.item))
        nullable = "items may be null" if spec.item_nullable else "items are required"
        if spec.kind is Kind.FIXED_LIST:
            item_word = "item" if spec.size == 1 else "items"
            return TypeDescription(
                "fixed-size list",
                f"exactly {spec.size} {item_word}; item type {item.name}; {nullable}",
            )
        return TypeDescription("list", f"item type {item.name}; {nullable}")
    if spec.kind is Kind.STRUCT:
        fields = ", ".join(
            f"{_field_label(field.name)}: {describe_type(field.type_spec).name}"
            for field in spec.fields
        )
        return TypeDescription("struct", fields)
    if spec.kind is Kind.MAP:
        key = describe_type(cast(TypeSpec, spec.key)).name
        value = describe_type(cast(TypeSpec, spec.value)).name
        nullable = "values may be null" if spec.value_nullable else "values are required"
        return TypeDescription("map", f"key {key}; value {value}; {nullable}")
    if spec.kind is Kind.TIMESTAMP:
        timezone = "no timezone" if spec.timezone is None else f"timezone {spec.timezone}"
        return TypeDescription("timestamp", f"unit {spec.unit}; {timezone}")
    if spec.kind is Kind.DECIMAL128:
        return TypeDescription("decimal128", f"precision {spec.precision}; scale {spec.scale}")
    return TypeDescription(spec.kind.value, "—")


def _field_ordinal(case: Case | None, name: str) -> int | None:
    if case is None:
        return None
    return next(
        (index for index, field in enumerate(case.fields, start=1) if field.name == name),
        None,
    )


def _field_label(name: str) -> str:
    return name if name else '"" (empty name)'


def _generated_field(value: str, case: Case | None) -> tuple[str, str]:
    if case is not None:
        names = sorted((field.name for field in case.fields), key=len, reverse=True)
        for name in names:
            if value == name:
                return name, ""
            if value.startswith((f"{name}[", f"{name}.")):
                return name, value[len(name) :]
    match = re.fullmatch(r"([^\[.]+)(.*)", value)
    return (value, "") if match is None else (match.group(1), match.group(2))


def _result_text(result: CellResult) -> str:
    labels = {
        Verdict.PASS: "completed",
        Verdict.WRITE_ERROR: "writer raised an error",
        Verdict.READ_ERROR: "reader raised an error",
        Verdict.SCHEMA_MISMATCH: "schema disagreed",
        Verdict.ROW_COUNT_MISMATCH: "row count disagreed",
        Verdict.VALUE_MISMATCH: "value disagreed",
    }
    return labels[result.verdict]


def _code(value: str) -> str:
    escaped = html.escape(value, quote=True)
    escaped = escaped.replace("|", "&#124;").replace("\r", "&#13;").replace("\n", "&#10;")
    return f"<code>{escaped}</code>"


def _text(value: str) -> str:
    return html.escape(value, quote=False).replace("|", "&#124;").replace("\n", " ")


__all__ = [
    "TypeDescription",
    "describe_type",
    "human_location",
    "markdown_literal",
    "profile_label",
    "render_case_rows",
    "render_case_schema",
    "render_difference",
    "render_matrix",
    "render_pipeline",
]
