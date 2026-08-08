from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..findings import json_codec as codec
from ..reporting import human_location, markdown_literal
from ..triage.adapters import scan_child_occurrences
from ..triage.model import Family, group_occurrences
from ..triage.normalization import detail_sha256_v1
from ..verdicts import EngineVersion
from . import records, symptoms

if TYPE_CHECKING:
    from .bundle import ValidatedScanFinding


def render_reproduce() -> bytes:
    return _template("reproduce").encode()


def render_upstream_repro(engines: tuple[EngineVersion, ...]) -> bytes:
    return (
        _template("upstream_repro")
        .replace("__ENGINES__", repr(tuple(item.name for item in engines)))
        .encode()
    )


def render_finding_report(record: records.ScanFindingRecord) -> bytes:
    outcomes = records.mappings(record.data["outcomes"], "outcomes")
    groups = records.mappings(record.data["observation_groups"], "groups")
    comparisons = records.mappings(record.data["comparisons"], "comparisons")
    occurrences = symptoms.extract(record, detail_sha256_v1)
    group_index = dict(records.group_members(group) for group in groups)
    lines = [
        "## Summary",
        "",
        _finding_summary(record.source_path, outcomes, comparisons),
        "",
        "Parquity compared independent reader observations.",
        "No reader is treated as the reference answer, and this evidence does not assign",
        "provider fault.",
        "",
        "## Source file",
        "",
        f"- Original path: {markdown_literal(record.source_path)}",
        f"- Size: `{record.input_bytes}` bytes",
        f"- SHA-256: `{record.input_sha256}`",
        "- Retained input: [`input.parquet`](input.parquet)",
        "",
        "## Reader outcomes",
        "",
        *_outcome_table(outcomes, group_index),
        "",
        *_comparison_section(comparisons, group_index),
        "",
        "## Reproduce",
        "",
        "Run `python reproduce.py` in this directory to validate the bundle and repeat the",
        "full reader comparison.",
        "",
        *(
            f"- `python upstream_repro.py {engine.name}` runs the direct `{engine.name}` reader."
            for engine in record.engines
        ),
        "",
        "Inspect both scripts before running them. Direct scripts emit provider evidence and",
        "do not apply Parquity's semantic comparison.",
        "",
        "## What this evidence establishes",
        "",
        "- Established: the recorded readers produced these outcomes for these exact bytes in",
        "  the recorded environment.",
        "- Not established: which observation is correct, root cause, provider fault, or",
        "  behavior on untested versions.",
        "",
        "## Occurrence index",
        "",
        *_occurrence_table(occurrences),
        "",
        "## Technical evidence",
        "",
        f"- Finding identity: `{record.finding_id}`",
        f"- Signature SHA-256: `{record.signature_sha256}`",
        f"- Timeout per reader: `{record.timeout_seconds}` seconds",
        f"- Occurrences extracted: `{len(occurrences)}`",
        "- Canonical manifest: [`finding.json`](finding.json)",
        "",
        "This bundle contains source bytes and diagnostics that may reveal sensitive data.",
        "Inspect every file before sharing it.",
    ]
    return _template("finding_report").format(body="\n".join(lines)).encode()


def render_run_report(
    record: records.ScanRunRecord,
    children: tuple[ValidatedScanFinding, ...],
) -> bytes:
    data = record.data
    discovery = codec.mapping(data["discovery"], "discovery")
    files = records.mappings(discovery["files"], "files")
    overflow = tuple(
        codec.string(item, "overflow path") for item in codec.sequence(data["overflow"], "overflow")
    )
    engines = records.engine_versions(data["engines"])
    child_by_id = {child.record.finding_id: child for child in children}
    indexes = records.mappings(data["findings"], "findings")
    occurrences = scan_child_occurrences(children)
    families = group_occurrences(occurrences)
    lines = [
        "## Summary",
        "",
        _run_summary(records.text(data, "status"), len(indexes), len(overflow)),
        "",
        "A scan finding is one source file with at least one reader failure or disagreement.",
        "It is not a count of upstream defects.",
        "",
        "## Run scope",
        "",
        *_scan_scope(data, discovery, files, indexes, overflow),
        "",
        "## Files with observed problems",
        "",
        *_finding_index(indexes, child_by_id),
    ]
    if overflow:
        lines.extend(("", *_unevaluated_files(overflow)))
    lines.extend(
        (
            "",
            *_family_section(families),
            "",
            "## Replay and triage",
            "",
            "- `parquity replay .` validates and replays every retained file finding.",
            "- `parquity replay --json . > replay.json` writes canonical replay evidence.",
            "- `parquity triage .` groups repeated symptom shapes across files.",
            "",
            "## Coverage and limits",
            "",
            "- Results cover only discovered files that were evaluated before the finding cap.",
            "- Symlinks are skipped; discovery and retained-byte limits remain bounded.",
            "- Reader agreement does not prove that an observation is specification-correct.",
            "",
            "## Environment and exact evidence",
            "",
            f"- Parquity: `{records.text(data, 'parquity_version')}`",
            f"- Readers: `{_engines(engines)}`",
            f"- Timeout per reader: `{codec.integer(data['timeout_seconds'], 'timeout')}` seconds",
            "- Canonical manifest: [`scan.json`](scan.json)",
            "",
            "Each finding contains source bytes and diagnostics that may reveal sensitive data.",
            "Inspect every child before sharing it.",
        )
    )
    return _template("run_report").format(body="\n".join(lines)).encode()


def _finding_summary(
    source: str,
    outcomes: tuple[Mapping[str, object], ...],
    comparisons: tuple[Mapping[str, object], ...],
) -> str:
    failures = sum(records.text(item, "kind") != "SUCCESS" for item in outcomes)
    return (
        f"For {markdown_literal(source)}, **{failures}** readers failed and "
        f"**{len(comparisons)}** pairwise observation differences were recorded."
    )


def _outcome_table(
    outcomes: tuple[Mapping[str, object], ...],
    groups: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    lines = [
        "| Reader | Outcome | Shape | Observation group | Diagnostic |",
        "|---|---|---|---|---|",
    ]
    for item in outcomes:
        engine = f"{records.text(item, 'engine')} {records.text(item, 'version')}"
        kind = records.text(item, "kind")
        group = cast(str | None, item["observation_group"])
        if kind == "SUCCESS":
            shape = f"{item['row_count']} rows by {item['column_count']} columns"
            diagnostic = "—"
        else:
            shape = "no table returned"
            detail = records.text(item, "detail")
            rendered_detail = (
                markdown_literal(detail) if detail else "No diagnostic text was captured."
            )
            diagnostic = f"{markdown_literal(records.text(item, 'diagnostic_kind'))}: "
            diagnostic += rendered_detail
        member_group = "—" if group is None else f"`{group}` ({', '.join(groups[group])})"
        lines.append(f"| `{engine}` | `{kind}` | {shape} | {member_group} | {diagnostic} |")
    return tuple(lines)


def _comparison_section(
    comparisons: tuple[Mapping[str, object], ...],
    groups: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    lines = [
        "## Observed differences",
        "",
        "The left and right columns name reader groups, not expected and observed truth.",
        "",
    ]
    if not comparisons:
        lines.append(
            "No pairwise semantic difference was recorded; the finding comes from a reader failure."
        )
        return tuple(lines)
    lines.extend(
        (
            "| Kind | Readers A | Readers B | Where | Detail |",
            "|---|---|---|---|---|",
        )
    )
    for item in comparisons:
        left = ", ".join(groups[records.text(item, "left_group")])
        right = ", ".join(groups[records.text(item, "right_group")])
        lines.append(
            f"| `{records.text(item, 'kind')}` | `{left}` | `{right}` | "
            f"{human_location(records.text(item, 'path'))} | "
            f"{markdown_literal(records.text(item, 'detail'))} |"
        )
    return tuple(lines)


def _occurrence_table(values: tuple[symptoms.ScanSymptom, ...]) -> tuple[str, ...]:
    lines = [
        "| Signal | Reader | Location | Occurrence identity |",
        "|---|---|---|---|",
    ]
    for item in values:
        reader = "reader groups" if item.target_reader is None else item.target_reader
        location = (
            "no table returned"
            if item.normalized_location is None
            else human_location(str(item.normalized_location))
        )
        lines.append(f"| `{item.signal}` | `{reader}` | {location} | `{item.occurrence_id}` |")
    return tuple(lines)


def _run_summary(status: str, finding_count: int, overflow_count: int) -> str:
    summary = f"Parquity retained **{finding_count}** file findings."
    if overflow_count:
        summary += f" **{overflow_count}** later files were not evaluated after the finding cap."
        summary += " This run is incomplete and not exhaustive."
    return f"{summary} Run status: `{status}`."


def _scan_scope(
    data: Mapping[str, object],
    discovery: Mapping[str, object],
    files: tuple[Mapping[str, object], ...],
    findings: tuple[Mapping[str, object], ...],
    overflow: tuple[str, ...],
) -> tuple[str, ...]:
    return (
        "| Measure | Value |",
        "|---|---:|",
        f"| Parquet files discovered | {len(files)} |",
        f"| Files evaluated | {len(files) - len(overflow)} |",
        f"| Files with retained findings | {len(findings)} |",
        f"| Files not evaluated after cap | {len(overflow)} |",
        f"| Symlinks skipped | {codec.integer(discovery['skipped_symlinks'], 'skipped')} |",
        "| Filesystem entries visited | "
        f"{codec.integer(discovery['visited_entries'], 'visited')} |",
        f"| Finding limit | {codec.integer(data['max_findings'], 'finding cap')} |",
        f"| Stop reason | `{records.text(data, 'stop_reason')}` |",
    )


def _finding_index(
    indexes: tuple[Mapping[str, object], ...],
    children: dict[str, ValidatedScanFinding],
) -> tuple[str, ...]:
    lines = [
        "| Source file | Reader failures | Semantic differences | Signals | Report |",
        "|---|---:|---:|---|---|",
    ]
    for item in indexes:
        finding_id = records.text(item, "finding_id")
        child = children[finding_id]
        outcomes = records.mappings(child.record.data["outcomes"], "outcomes")
        comparisons = records.mappings(child.record.data["comparisons"], "comparisons")
        failures = sum(records.text(outcome, "kind") != "SUCCESS" for outcome in outcomes)
        signals = Counter(value.signal.value for value in scan_child_occurrences((child,)))
        signal_text = ", ".join(f"{name}: {count}" for name, count in sorted(signals.items()))
        lines.append(
            f"| {markdown_literal(child.record.source_path)} | {failures} | {len(comparisons)} | "
            f"{signal_text} | [open finding](findings/{finding_id}/REPORT.md) |"
        )
    return tuple(lines)


def _unevaluated_files(paths: tuple[str, ...]) -> tuple[str, ...]:
    return (
        "## Files not evaluated after the finding cap",
        "",
        "These are files, not additional findings. Parquity did not run readers on them:",
        "",
        *(f"- {markdown_literal(path)}" for path in paths),
    )


def _family_section(families: tuple[Family, ...]) -> tuple[str, ...]:
    occurrences = sum(len(family.occurrences) for family in families)
    lines = [
        "## Symptom families",
        "",
        f"Parquity grouped **{occurrences}** occurrences into **{len(families)}** conservative",
        "families. Families help navigate repetition; they do not claim root-cause identity.",
        "",
        "| Signal | Occurrences | Representative file | Representative report |",
        "|---|---:|---|---|",
    ]
    for family in families:
        representative = family.representative
        lines.append(
            f"| `{family.signal.value}` | {len(family.occurrences)} | "
            f"{markdown_literal(representative.reference_value)} | "
            f"[open finding](findings/{representative.finding_id}/REPORT.md) |"
        )
    return tuple(lines)


def _engines(engines: tuple[EngineVersion, ...]) -> str:
    return ", ".join(f"{engine.name} {engine.version}" for engine in engines)


def _template(name: str) -> str:
    return Path(__file__).with_name(f"{name}.tmpl").read_text(encoding="utf-8")
