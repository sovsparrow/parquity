from __future__ import annotations

import html
import re
from urllib.parse import quote

from . import (
    ArtifactRef,
    DetailView,
    EvidenceKind,
    EvidenceReportView,
    FailureRowView,
    FindingEvidenceView,
    InputView,
    ReproductionStep,
    RunReportView,
    TableView,
    failure_headers,
    failure_rows,
)


def render_run_report(view: RunReportView) -> bytes:
    lines = [
        f"# Parquity {_text(view.command)} report",
        "",
        f"**{_text(view.summary)}**",
    ]
    if view.findings:
        lines.extend(("", "## Failures", "", *_failure_table(view)))
    lines.extend(("", "## Run details", ""))
    if view.command_line is not None:
        lines.extend(("### Command", "", *_fenced_block(view.command_line, "console"), ""))
    details: list[DetailView] = []
    if view.command_line is None:
        details.append(DetailView("Command", view.command))
    if view.writers:
        details.append(DetailView("Writers", ", ".join(view.writers)))
    details.append(DetailView("Readers", ", ".join(view.readers)))
    details.extend((*view.bounds, *view.environment))
    lines.extend(_details(tuple(details)))
    if view.replay_observations:
        lines.extend(("", "### New replay observations", "", *_details(view.replay_observations)))
    if view.machine_record is not None:
        lines.append(f"- **Machine record:** {_link(view.machine_record)}")
    return _document(lines)


def render_evidence_report(view: EvidenceReportView) -> bytes:
    lines = [f"# {_text(view.title)}", "", _text(view.summary)]
    if view.facts:
        lines.extend(("", *_details(view.facts)))
    if view.evidence_kind is EvidenceKind.GENERATED:
        lines.extend(("", "## Reproduce", "", *_reproduction(view.reproduce)))
        lines.extend(("", "## Table", "", *_input(view.input)))
        lines.extend(("", "## Outcomes", "", *_table(view.outcomes)))
    else:
        lines.extend(("", "## File", "", *_input(view.input)))
        lines.extend(("", "## Failures", ""))
        for finding in view.finding_evidence:
            lines.extend((*_finding_evidence(finding), ""))
        if lines[-1] == "":
            lines.pop()
        lines.extend(("", "## Outcomes", "", *_table(view.outcomes)))
        lines.extend(("", "## Reproduce", "", *_reproduction(view.reproduce)))
    lines.extend(("", "## Environment", "", *_details(view.environment)))
    lines.append(f"- **Machine record:** {_link(view.machine_record)}")
    if view.replay_observations:
        lines.extend(("", "## New replay observations", "", *_details(view.replay_observations)))
    return _document(lines)


def _failure_table(view: RunReportView) -> tuple[str, ...]:
    headers = failure_headers(view)
    lines = [
        "| " + " | ".join(_cell(value) for value in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in failure_rows(view):
        cells = (
            _cell(row.participants),
            _technical_lines(row.failure),
            _source_cell(row.source),
            _reproduce_cell(row),
        )
        lines.append("| " + " | ".join(cells) + " |")
    return tuple(lines)


def _reproduce_cell(row: FailureRowView) -> str:
    if row.reference is None:
        return _cell(row.reproduce)
    suffix = row.reproduce.removeprefix("open")
    return f"{_link(ArtifactRef('open', row.reference.relative_path, row.reference.anchor))}{_text(suffix)}"


def _finding_evidence(view: FindingEvidenceView) -> tuple[str, ...]:
    return (
        f'<a id="{view.anchor}"></a>',
        f"### {_text(view.summary)}",
        "",
        *_details(view.facts),
    )


def _input(view: InputView) -> tuple[str, ...]:
    lines: list[str] = []
    if view.facts:
        lines.extend(_details(view.facts))
    if lines:
        lines.append("")
    lines.append("Artifacts: " + " · ".join(_link(item) for item in view.artifacts))
    if view.schema is not None:
        lines.extend(("", "### Schema", "", *_table(view.schema)))
    if view.data is not None:
        lines.extend(("", "### Data", ""))
        lines.extend(_table(view.data) if view.data.rows else ("_No rows._",))
    if view.omission_note is not None:
        lines.extend(("", _text(view.omission_note)))
    return tuple(lines)


def _reproduction(steps: tuple[ReproductionStep, ...]) -> tuple[str, ...]:
    lines: list[str] = []
    for step in steps:
        if lines:
            lines.append("")
        lines.extend(
            (
                f"### {_text(step.label)}",
                "",
                _text(step.purpose),
                "",
                "```console",
                step.command,
                "```",
            )
        )
    return tuple(lines)


def _details(details: tuple[DetailView, ...]) -> tuple[str, ...]:
    lines: list[str] = []
    for item in details:
        label = _text(item.label)
        if _technical_detail(item) and "\n" in item.value:
            lines.extend((f"- **{label}:**", "", *_code_block(item.value), ""))
        elif _technical_detail(item):
            lines.append(f"- **{label}:** {_code(item.value)}")
        else:
            lines.append(f"- **{label}:** {_text(item.value)}")
    while lines and lines[-1] == "":
        lines.pop()
    return tuple(lines)


def _technical_detail(item: DetailView) -> bool:
    return item.label.startswith("Captured detail") or item.label == "Captured stderr"


def _code_block(value: str) -> tuple[str, ...]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    longest = max((len(match.group()) for match in re.finditer(r"`+", normalized)), default=0)
    fence = "`" * max(3, longest + 1)
    return (f"    {fence}text", *(f"    {line}" for line in normalized.split("\n")), f"    {fence}")


def _fenced_block(value: str, language: str) -> tuple[str, ...]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    longest = max((len(match.group()) for match in re.finditer(r"`+", normalized)), default=0)
    fence = "`" * max(3, longest + 1)
    return (f"{fence}{language}", *normalized.split("\n"), fence)


def _table(view: TableView) -> tuple[str, ...]:
    header = "| " + " | ".join(_cell(value) for value in view.headers) + " |"
    divider = "|" + "|".join("---" for _ in view.headers) + "|"
    rows = tuple("| " + " | ".join(_code(value) for value in row) + " |" for row in view.rows)
    return (header, divider, *rows)


def _link(reference: ArtifactRef) -> str:
    target = quote(reference.relative_path, safe="/._-")
    if reference.anchor is not None:
        target += f"#{reference.anchor}"
    return f"[{_text(reference.label)}]({target})"


def _cell(value: str) -> str:
    return _text(value).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _technical_lines(value: str) -> str:
    return "<br>".join(_code(line) for line in value.splitlines())


def _source_cell(value: str) -> str:
    source, *notes = value.splitlines()
    rendered = _code(source)
    if notes:
        rendered += "<br>" + "<br>".join(_text(note) for note in notes)
    return rendered


def _code(value: str) -> str:
    normalized = " ".join(value.replace("\r", "\n").splitlines())
    longest = max((len(match.group()) for match in re.finditer(r"`+", normalized)), default=0)
    fence = "`" * (longest + 1)
    escaped = normalized.replace("|", "&#124;")
    padding = " " if escaped.startswith("`") or escaped.endswith("`") else ""
    return f"{fence}{padding}{escaped}{padding}{fence}"


def _text(value: str) -> str:
    escaped = html.escape(value, quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "#", "!", ">"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("|", "&#124;")


def _document(lines: list[str]) -> bytes:
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines) + "\n").encode()


__all__ = ["render_evidence_report", "render_run_report"]
