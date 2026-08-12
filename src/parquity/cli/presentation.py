from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import cast

from ..reporting import (
    DetailView,
    EvidenceKind,
    EvidenceReportView,
    RunReportView,
    failure_headers,
    failure_rows,
)
from .style import Style

_V1_SAVED_EVIDENCE_LIMIT = "FINDING_CAP_REACHED"


def _table(headers: tuple[str, ...], rows: Sequence[tuple[str, ...]], style: Style) -> str:
    headers = tuple(_terminal_text(value) for value in headers)
    rows = tuple(tuple(_terminal_text(value) for value in row) for row in rows)
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    rendered = [
        "  ".join(style.bold(header.ljust(widths[index])) for index, header in enumerate(headers))
    ]
    for row in rows:
        cells: list[str] = []
        for index, value in enumerate(row):
            padded = value.ljust(widths[index])
            if index == 0:
                padded = style.accent(padded)
            elif value in ("yes", "PASS"):
                padded = style.good(padded)
            elif value in ("no", "FAIL", "WRITE_ERROR", "READ_ERROR"):
                padded = style.warn(padded)
            elif value == "—":
                padded = style.dim(padded)
            cells.append(padded)
        rendered.append("  ".join(cells))
    return "\n".join(rendered)


def _status(value: str, status_name: str, style: Style) -> str:
    if status_name in (
        "PASS",
        "NO_FINDING",
        "AGREEMENT",
        "NOT_REPRODUCED",
        "OK",
    ):
        return style.good(value)
    if status_name in ("RUN_PUBLISHED", _V1_SAVED_EVIDENCE_LIMIT):
        return style.accent(value)
    return style.warn(value)


def _records(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    items = cast(Sequence[object], value)
    return tuple(cast(Mapping[str, object], item) for item in items if isinstance(item, Mapping))


def _string(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


def render(document: Mapping[str, object], *, controls: bool) -> str:
    style = Style(controls)
    command = _string(document.get("command"), "parquity")
    if command == "version":
        return f"parquity {_string(document.get('version'))}\n"
    if command == "engines":
        return _render_engines(document, style)
    if command == "smoke":
        return _render_smoke(document, style)
    status = _string(document.get("status"), "UNKNOWN")
    if status in ("CONFIGURATION_ERROR", "INTERNAL_ERROR"):
        return ""
    return _render_operation(command, status, document, style)


def render_report(
    view: RunReportView,
    *,
    command: str,
    status: str,
    controls: bool,
    output: object = None,
) -> str:
    style = Style(controls)
    title = _title(command, status)
    lines = [
        _status(title, status, style),
        _terminal_text(view.summary),
    ]
    if view.findings:
        lines.extend(("", _report_table(view, style)))
    if view.replay_observations:
        lines.extend(("", style.bold("New replay observations")))
        lines.extend(
            f"  {style.dim(item.label)}  {_terminal_text(item.value)}"
            for item in view.replay_observations
        )
    if output is not None:
        lines.append(f"Output: {output}")
    return "\n".join(lines) + "\n"


def render_evidence(
    view: EvidenceReportView,
    *,
    command: str,
    status: str,
    controls: bool,
) -> str:
    style = Style(controls)
    lines = [
        _status(_title(command, status), status, style),
        style.accent(_terminal_text(view.title)),
        _terminal_text(view.summary),
    ]
    lines.extend(_terminal_details(view.facts, style))
    source_heading = "Table" if view.evidence_kind is EvidenceKind.GENERATED else "File"
    lines.extend(("", style.bold(source_heading)))
    lines.extend(_terminal_details(view.input.facts, style))
    if view.finding_evidence:
        lines.extend(("", style.bold("Failures")))
        for item in view.finding_evidence:
            lines.append(f"  {style.accent(_terminal_text(item.summary))}")
            lines.extend(_terminal_details(item.facts, style, indent="    "))
    lines.extend(
        ("", style.bold("Outcomes"), _table(view.outcomes.headers, view.outcomes.rows, style))
    )
    if view.replay_observations:
        lines.extend(("", style.bold("New replay observations")))
        lines.extend(_terminal_details(view.replay_observations, style))
    return "\n".join(lines) + "\n"


def _terminal_details(
    details: tuple[DetailView, ...], style: Style, *, indent: str = "  "
) -> list[str]:
    return [
        f"{indent}{style.dim(_terminal_text(item.label))}  {_terminal_text(item.value)}"
        for item in details
    ]


def _report_table(view: RunReportView, style: Style) -> str:
    rows = tuple(
        (
            _terminal_clip(row.participants, 24),
            _terminal_clip(row.failure, 56),
            _terminal_source(row.source),
            row.reproduce,
        )
        for row in failure_rows(view)
    )
    return _table(failure_headers(view), rows, style)


def _terminal_source(value: str) -> str:
    source, *notes = value.splitlines()
    rendered = _terminal_clip(source, 44)
    if notes:
        rendered += " · " + " · ".join(_terminal_text(note) for note in notes)
    return rendered


def _terminal_text(value: str) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())


def _terminal_clip(value: str, limit: int) -> str:
    value = _terminal_text(value)
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def _render_engines(document: Mapping[str, object], style: Style) -> str:
    engines = _records(document.get("engines"))
    rows = tuple(
        (
            _string(engine.get("name")),
            _string(engine.get("tier")),
            "yes" if engine.get("available") is True else "no",
            "yes" if engine.get("reader") is True else "—",
            "yes" if engine.get("writer") is True else "—",
            _string(engine.get("version"), "—"),
        )
        for engine in engines
    )
    available = sum(engine.get("available") is True for engine in engines)
    lines = [_table(("Engine", "Tier", "Available", "Reader", "Writer", "Version"), rows, style)]
    summary = f"{available}/{len(rows)} providers available"
    if python_range := _python_range(document.get("python_support")):
        summary += f" · Python {python_range}"
    lines.append(style.dim(summary))
    return "\n".join(lines) + "\n"


def _render_smoke(document: Mapping[str, object], style: Style) -> str:
    results = _records(document.get("results"))
    writers = _ordered(_string(item.get("writer")) for item in results)
    readers = _ordered(_string(item.get("reader")) for item in results)
    cells = {
        (_string(item.get("writer")), _string(item.get("reader"))): _string(
            item.get("verdict"), "?"
        )
        for item in results
    }
    rows = tuple(
        (writer, *(cells.get((writer, reader), "—") for reader in readers)) for writer in writers
    )
    table = _table(("Writer \\ Reader", *readers), rows, style)
    passed = sum(value == "PASS" for value in cells.values())
    status = _string(document.get("status"), "UNKNOWN")
    summary = f"{status} · {passed}/{len(cells)} cells passed"
    return f"{table}\n{_status(summary, status, style)}\n"


def _render_operation(
    command: str,
    status: str,
    document: Mapping[str, object],
    style: Style,
) -> str:
    lines = [_status(_title(command, status), status, style)]
    pairs = _operation_pairs(command, document)
    output = document.get("output")
    width = max((len(label) for label, _ in pairs), default=0)
    width = max(width, len("Output")) if output else width
    lines.extend(f"  {style.dim(label.ljust(width))}  {value}" for label, value in pairs)
    if output is not None:
        lines.append(f"  {style.dim('Output'.ljust(width))}  {output}")
    return "\n".join(lines) + "\n"


def _operation_pairs(command: str, document: Mapping[str, object]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if command == "check":
        _pair(pairs, "Case", document.get("case_id"))
    if command in ("check", "fuzz"):
        _pair(pairs, "Run", document.get("run_id"))
        _pair(pairs, "Failures", document.get("finding_count"))
        _pair(pairs, "Additional", document.get("overflow_count"))
    elif command == "scan":
        _pair(pairs, "Scan", document.get("scan_id"))
        _pair(pairs, "Readers", _engine_names(document.get("readers")))
        _pair(pairs, "Failures", document.get("finding_count"))
        _pair(pairs, "Not evaluated", document.get("overflow_count"))
    elif command == "replay":
        _pair(pairs, "Run", document.get("run_id"))
        _pair(pairs, "Failure", document.get("finding_id"))
        _pair(pairs, "Scan", document.get("scan_id"))
        _pair(pairs, "Reproducers", _replay_target_count(document))
    return pairs


def _title(command: str, status: str) -> str:
    titles = {
        ("check", "NO_FINDING"): "Check complete",
        ("fuzz", "NO_FINDING"): "Fuzz complete",
        ("scan", "AGREEMENT"): "Readers agree",
        ("check", "RUN_PUBLISHED"): "Check run saved",
        ("fuzz", "RUN_PUBLISHED"): "Fuzz run saved",
        ("scan", "RUN_PUBLISHED"): "Scan run saved",
        ("replay", "REPRODUCED"): "Recorded failures reproduced",
        ("replay", "RELATED_FAILURE"): "Reproduction found related failures",
        ("replay", "NOT_REPRODUCED"): "Recorded failures not reproduced",
    }
    return titles.get((command, status), status.replace("_", " ").title())


def _engine_names(value: object) -> str | None:
    if not isinstance(value, (list, tuple)):
        return None
    names = (
        item
        if isinstance(item, str)
        else _string(cast(Mapping[str, object], item).get("name"))
        if isinstance(item, Mapping)
        else ""
        for item in cast(Sequence[object], value)
    )
    return ", ".join(name for name in names if name) or None


def _python_range(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    support = cast(Mapping[object, object], value)
    versions = {
        tuple(item for item in cast(Sequence[object], raw) if isinstance(item, str))
        for raw in support.values()
        if isinstance(raw, (list, tuple))
    }
    if len(versions) != 1 or not (ordered := next(iter(versions))):
        return None
    return ordered[0] if len(ordered) == 1 else f"{ordered[0]}-{ordered[-1]}"


def _ordered(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _replay_target_count(document: Mapping[str, object]) -> int | None:
    if isinstance(results := document.get("results"), (list, tuple)):
        return len(cast(Sequence[object], results))
    counts = tuple(document.get(name) for name in ("exact", "related", "absent"))
    return (
        sum(cast(tuple[int, int, int], counts))
        if all(isinstance(item, int) for item in counts)
        else None
    )


def _pair(pairs: list[tuple[str, str]], label: str, value: object) -> None:
    if value is not None and not any(existing == label for existing, _ in pairs):
        pairs.append((label, str(value)))


__all__ = ["render", "render_evidence", "render_report"]
