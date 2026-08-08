from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import cast

from .style import Style


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


def _render_engines(document: Mapping[str, object], style: Style) -> str:
    rows: list[tuple[str, ...]] = []
    available = 0
    for engine in _records(document.get("engines")):
        is_available = engine.get("available") is True
        available += int(is_available)
        rows.append(
            (
                _string(engine.get("name")),
                _string(engine.get("tier")),
                "yes" if is_available else "no",
                _direction(engine.get("reader")),
                _direction(engine.get("writer")),
                _string(engine.get("version"), "—"),
            )
        )
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
    if (
        command in ("check", "fuzz")
        and status == "RUN_PUBLISHED"
        and _records(document.get("findings"))
    ):
        return _render_finding_run(command, document, style)
    lines = [_status(_title(command, status), status, style)]
    pairs = _operation_pairs(command, document)
    output = document.get("output")
    width = max((len(label) for label, _ in pairs), default=0)
    if output:
        width = max(width, len("Report"))
    if pairs:
        lines.extend(f"  {style.dim(label.ljust(width))}  {value}" for label, value in pairs)
    if command == "triage" and (families := _triage_rows(document.get("symptom_families"))):
        lines.extend(("", _table(("Signal", "Count", "State", "Family"), families, style)))
    if output:
        lines.append(f"  {style.dim('Report'.ljust(width))}  {_report(output, style)}")
    return "\n".join(lines) + "\n"


def _operation_pairs(command: str, document: Mapping[str, object]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if command == "check":
        _pair(pairs, "Case", document.get("case_id"))
        _pair(pairs, "Writers", _engine_names(document.get("writers")))
        _pair(pairs, "Readers", _engine_names(document.get("readers")))
    elif command == "fuzz":
        examples = document.get("discovery_bound")
        _pair(pairs, "Examples", None if examples is None else f"{examples} max")
        _pair(pairs, "Seed", document.get("seed"))
    elif command == "scan":
        _pair(pairs, "Readers", _engine_names(document.get("readers")))
        _pair(pairs, "Findings", document.get("finding_count"))
        _pair(pairs, "Scope", document.get("run_status"))
    elif command == "replay":
        _pair(pairs, "Run", document.get("run_id"))
        _pair(pairs, "Finding", document.get("finding_id"))
        _pair(pairs, "Scan", document.get("scan_id"))
        _pair(pairs, "Targets", _length(document.get("results")))
        _pair(pairs, "Version drift", _length(document.get("version_drift")))
    elif command == "triage":
        _pair(pairs, "Findings", document.get("finding_bundle_count"))
        _pair(pairs, "Occurrences", document.get("occurrence_count"))
        _pair(pairs, "Families", document.get("symptom_family_count"))
        _pair(pairs, "Displayed", document.get("displayed_symptom_family_count"))
        _pair(pairs, "Replay", document.get("replay_status"))
    if command != "fuzz":
        _pair(pairs, "Findings", document.get("finding_count"))
        _pair(pairs, "Overflow", document.get("overflow_count"))
    return pairs


def _render_finding_run(command: str, document: Mapping[str, object], style: Style) -> str:
    findings = _records(document.get("findings"))
    discovery: Mapping[str, object] = {}
    if isinstance(raw_discovery := document.get("discovery"), Mapping):
        discovery = cast(Mapping[str, object], raw_discovery)
    capped = document.get("run_status") == "FINDING_CAP_REACHED"
    suffix = " (finding limit reached)" if capped else ""
    lines = [_status(f"FINDINGS · {len(findings)} saved{suffix}", "RUN_PUBLISHED", style)]
    if command == "fuzz":
        checked, requested = discovery.get("evaluated_cases"), discovery.get("examples")
        lines.append(f"Checked {checked} of up to {requested} generated Cases.")
    else:
        lines.append("Checked the supplied Case.")
    rows = tuple((str(index), *_finding_row(item)) for index, item in enumerate(findings[:8], 1))
    lines.extend(("", _table(("#", "Result", "Route", "Evidence"), rows, style)))
    if len(findings) > len(rows):
        remaining = len(findings) - len(rows)
        subject = "finding is" if remaining == 1 else "findings are"
        lines.extend(("", f"{remaining} more saved {subject} in the report."))
    overflow = document.get("overflow_count")
    if isinstance(overflow, int) and overflow:
        limit = discovery.get("max_findings", len(findings))
        lines.extend(
            (
                "",
                f"{overflow} more distinct observations are recorded in run.json.",
                f"Run again with --max-findings above {limit} to save more individual reports.",
            )
        )
    if output := document.get("output"):
        lines.extend(("", f"{style.dim('Next:')} {_report(output, style)}"))
    return "\n".join(lines) + "\n"


def _finding_row(item: Mapping[str, object]) -> tuple[str, str, str]:
    writer = _string(item.get("writer"), "?")
    reader = _string(item.get("reader"), "?")
    route = f"{writer} · write" if reader == "*" else f"{writer} → {reader}"
    location = _string(item.get("schema_path"), "?")
    if location == "$":
        location = "whole table"
    elif location.startswith("$schema."):
        location = location.removeprefix("$schema.")
    detail = _brief(item.get("detail")) or _string(item.get("diagnostic_kind"))
    evidence = location if not detail else f"{location} · {detail}"
    return _string(item.get("verdict"), "?"), route, evidence


def _brief(value: object, *, limit: int = 80) -> str:
    text = " ".join(_string(value).split())
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}…"


def _table(headers: tuple[str, ...], rows: Sequence[tuple[str, ...]], style: Style) -> str:
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


def _status(value: str, status: str, style: Style) -> str:
    if status in ("PASS", "NO_FINDING", "AGREEMENT", "TRIAGED", "NOT_REPRODUCED", "OK"):
        return style.good(value)
    if status in ("RUN_PUBLISHED", "FINDING_CAP_REACHED"):
        return style.accent(value)
    return style.warn(value)


def _title(command: str, status: str) -> str:
    titles = {
        ("check", "NO_FINDING"): "No finding",
        ("fuzz", "NO_FINDING"): "No finding",
        ("scan", "AGREEMENT"): "Readers agree",
        ("check", "RUN_PUBLISHED"): "Check run saved",
        ("fuzz", "RUN_PUBLISHED"): "Fuzz run saved",
        ("scan", "RUN_PUBLISHED"): "Scan run saved",
        ("replay", "REPRODUCED"): "Recorded behavior reproduced",
        ("replay", "RELATED_FAILURE"): "Related behavior observed",
        ("replay", "NOT_REPRODUCED"): "Recorded behavior not reproduced",
        ("triage", "TRIAGED"): "Triage complete",
    }
    return titles.get((command, status), status.replace("_", " ").title())


def _report(value: object, style: Style) -> str:
    report = Path(_string(value)) / "REPORT.md"
    label = str(report)
    try:
        uri = report.expanduser().resolve().as_uri()
    except (OSError, ValueError):
        return label
    return style.link(label, uri)


def _records(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        cast(Mapping[str, object], item)
        for item in cast(Sequence[object], value)
        if isinstance(item, Mapping)
    )


def _engine_names(value: object) -> str | None:
    if not isinstance(value, (list, tuple)):
        return None
    names: list[str] = []
    for item in cast(Sequence[object], value):
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, Mapping):
            record = cast(Mapping[str, object], item)
            if isinstance(name := record.get("name"), str):
                names.append(name)
    return ", ".join(names) if names else None


def _python_range(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    support = cast(Mapping[object, object], value)
    versions = {
        tuple(item for item in cast(Sequence[object], raw) if isinstance(item, str))
        for raw in support.values()
        if isinstance(raw, (list, tuple))
    }
    if len(versions) != 1:
        return None
    ordered = next(iter(versions))
    if not ordered:
        return None
    return ordered[0] if len(ordered) == 1 else f"{ordered[0]}-{ordered[-1]}"


def _direction(value: object) -> str:
    return "yes" if value is True else "—"


def _triage_rows(value: object) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (
            _string(family.get("signal"), "?"),
            str(family.get("occurrence_count", "?")),
            _string(family.get("representative_reproduction_state"), "?"),
            _string(family.get("family_id"), "?")[:12],
        )
        for family in _records(value)
    )


def _ordered(values: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    for value in values:
        if value and value not in ordered:
            ordered.append(value)
    return tuple(ordered)


def _length(value: object) -> int | None:
    return len(cast(Sequence[object], value)) if isinstance(value, (list, tuple)) else None


def _pair(pairs: list[tuple[str, str]], label: str, value: object) -> None:
    if value is not None and not any(existing == label for existing, _ in pairs):
        pairs.append((label, str(value)))


def _string(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


__all__ = ["render"]
