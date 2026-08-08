from __future__ import annotations

from typing import cast

from ..findings.bundle import ValidatedBundle
from ..findings.evidence import DISCOVERY_OVERFLOW
from ..model import Case
from ..reporting import (
    human_location,
    markdown_literal,
    profile_label,
    render_case_rows,
    render_case_schema,
)
from ..triage.adapters import generated_child_occurrences
from ..triage.model import Family, group_occurrences
from ..verdicts import EngineVersion
from .model import RunRecord


def render_run_report(run: RunRecord, children: tuple[ValidatedBundle, ...]) -> bytes:
    child_by_finding = {child.finding.finding_id: child for child in children}
    generation = children[0].finding.generation if children else None
    case_labels, grouped_cases = _case_index(run, child_by_finding)
    families = group_occurrences(generated_child_occurrences(children))
    lines = [
        f"# Parquity {run.command} run",
        "",
        *_opening(run),
        "",
        "## Run scope",
        "",
        *_scope_table(run, children),
        "",
        "A finding is one reproducible symptom, not a count of upstream defects.",
        "One generated Case can produce several findings or other observations.",
        "",
        "## Inputs with observed problems",
        "",
    ]
    for label, case, finding_ids in grouped_cases:
        lines.extend(_case_section(label, case, finding_ids, child_by_finding))
    if run.overflow:
        lines.extend(("", *_overflow_section(run, case_labels)))
    lines.extend(
        (
            "",
            *_family_section(families),
            "",
            "## Replay and triage",
            "",
            "- `parquity replay .` validates the run and re-executes every exact target.",
            "- `parquity replay --json . > replay.json` writes canonical replay evidence.",
            "- `parquity triage .` groups repeated symptom shapes without treating families as",
            "  confirmed upstream bugs.",
            "",
            "Replay exits 1 when at least one exact target reproduces. Exit 0 means no exact",
            "target reproduced; related or unevaluable outcomes remain separately classified.",
            "",
            "## Coverage and limits",
            "",
            *_coverage_lines(run),
            "",
            "## Environment and exact evidence",
            "",
            f"- Command: `{_command(run, schema=generation is not None)}`",
            f"- Run identity: `{run.run_id}`",
            f"- Writers: `{_engines(run.writers)}`",
            f"- Readers: `{_engines(run.readers)}`",
            f"- Parquity: `{run.environment.parquity_version}`",
            f"- Hypothesis: `{run.environment.hypothesis_version}`",
            f"- Python: `{run.environment.python_version}`",
            f"- Platform: `{run.environment.platform}`",
            *(
                ()
                if generation is None
                else (
                    f"- Generation profile: `{generation.profile}`",
                    f"- Schema Case identity: `{generation.schema_case_id}`",
                )
            ),
            "- Canonical run manifest: [`run.json`](run.json)",
            "",
        )
    )
    return "\n".join(lines).encode()


def _opening(run: RunRecord) -> tuple[str, ...]:
    retained = len(run.findings)
    finding_word = "finding" if retained == 1 else "findings"
    overflow_word = "observation" if len(run.overflow) == 1 else "observations"
    if run.overflow:
        return (
            f"Parquity saved **{retained}** reproducible {finding_word} with individual reports.",
            f"It also recorded **{len(run.overflow)}** other distinct {overflow_word} in "
            "`run.json` after reaching the `--max-findings` limit.",
            "This run is intentionally bounded and is not exhaustive.",
        )
    return (f"Parquity saved **{retained}** reproducible {finding_word}.",)


def _scope_table(run: RunRecord, children: tuple[ValidatedBundle, ...]) -> tuple[str, ...]:
    discovery = run.discovery
    requested = "1" if run.command == "check" else str(discovery.examples)
    evaluated = "1" if run.command == "check" else _count(discovery.evaluated_cases)
    cells = _count(discovery.evaluated_cells)
    if run.command == "check":
        cells = str(len(children[0].matrix.results))
    return (
        "| Measure | Value |",
        "|---|---:|",
        f"| {'Supplied Case' if run.command == 'check' else '`--examples` requested'} | "
        f"{requested} |",
        f"| Cases actually checked | {evaluated} |",
        f"| Writer-reader cells actually checked | {cells} |",
        f"| Findings with individual reports | {len(run.findings)} |",
        f"| Other observations without individual reports | {len(run.overflow)} |",
        f"| Why the run stopped | {_stop_reason(discovery.stop_reason)} |",
    )


def _case_index(
    run: RunRecord,
    children: dict[str, ValidatedBundle],
) -> tuple[dict[str, str], tuple[tuple[str, Case, tuple[str, ...]], ...]]:
    labels: dict[str, str] = {}
    cases: dict[str, Case] = {}
    findings: dict[str, list[str]] = {}
    for item in run.findings:
        case = children[item.finding_id].case
        if case.case_id not in labels:
            labels[case.case_id] = f"C{len(labels) + 1}"
            cases[case.case_id] = case
            findings[case.case_id] = []
        findings[case.case_id].append(item.finding_id)
    grouped = tuple(
        (labels[case_id], cases[case_id], tuple(findings[case_id])) for case_id in labels
    )
    return labels, grouped


def _case_section(
    label: str,
    case: Case,
    finding_ids: tuple[str, ...],
    children: dict[str, ValidatedBundle],
) -> tuple[str, ...]:
    first = finding_ids[0]
    row_word = "row" if len(case.rows) == 1 else "rows"
    column_word = "column" if len(case.fields) == 1 else "columns"
    lines = [
        f"### {label} · {len(case.rows)} {row_word} · {len(case.fields)} {column_word}",
        "",
        f"Case identity: `{case.case_id}` · [open canonical Case](findings/{first}/case.json)",
        "",
        "#### Schema",
        "",
        *render_case_schema(case),
        "",
        "#### Data",
        "",
        *render_case_rows(case),
        "",
        "#### Findings from this Case",
        "",
        "| # | Route | Result | Where | Detail | Evidence |",
        "|---:|---|---|---|---|---|",
    ]
    profiled = children[first].finding.writer_profiles is not None
    for index, finding_id in enumerate(finding_ids, start=1):
        child = children[finding_id]
        target = child.finding.result
        writer = target.writer + profile_label(target.writer_profile, profiled=profiled)
        reader = "write stage" if target.reader == "*" else target.reader
        lines.append(
            f"| {index} | `{writer}` → `{reader}` | `{target.verdict.value}` | "
            f"{human_location(target.schema_path, case)} | {_brief(target.detail)} | "
            f"[open finding](findings/{finding_id}/REPORT.md) |"
        )
    return (*lines, "")


def _overflow_section(run: RunRecord, case_labels: dict[str, str]) -> tuple[str, ...]:
    unknown: dict[str, str] = {}
    unknown_cases: dict[str, Case] = {}
    lines = [
        "## Other observations without individual reports",
        "",
        "After reaching the requested finding limit, Parquity stopped creating individual",
        "finding directories. The exact observations below remain recorded in `run.json`.",
        "They are not extra generated Cases or confirmed upstream bugs.",
        "",
        "`Discovery` means an evaluated generated Case exposed the observation. `Minimization`",
        "means simplifying a saved finding's Case exposed a sibling observation.",
        "",
        "| Input | Origin | Route | Result | Location | Detail |",
        "|---|---|---|---|---|---|",
    ]
    profiled = run.writer_profiles is not None
    for item in run.overflow:
        fingerprint = item.fingerprint
        writer = fingerprint.writer + profile_label(fingerprint.writer_profile, profiled=profiled)
        label = case_labels.get(item.case_id)
        if label is None:
            label = unknown.setdefault(item.case_id, f"U{len(unknown) + 1}")
            unknown_cases.setdefault(label, item.case)
        origin = "Discovery" if item.origin == DISCOVERY_OVERFLOW else "Minimization"
        reader = "write stage" if fingerprint.reader == "*" else fingerprint.reader
        location = human_location(fingerprint.schema_path, item.case)
        lines.append(
            f"| {label} | {origin} | `{writer}` → `{reader}` | "
            f"`{fingerprint.verdict.value}` | {location} | "
            f"{_brief(item.result.detail)} |"
        )
    lines.extend(("", "Exact records are preserved in [`run.json`](run.json)."))
    if unknown_cases:
        lines.extend(
            (
                "",
                "### Inputs represented only in `run.json`",
                "",
                "`U1`, `U2`, and so on identify Cases without individual finding directories.",
            )
        )
    for label, case in unknown_cases.items():
        row_word = "row" if len(case.rows) == 1 else "rows"
        column_word = "column" if len(case.fields) == 1 else "columns"
        lines.extend(
            (
                "",
                f"#### {label} · {len(case.rows)} {row_word} · {len(case.fields)} {column_word}",
                "",
                *render_case_schema(case),
                "",
                *render_case_rows(case),
            )
        )
    return tuple(lines)


def _family_section(families: tuple[Family, ...]) -> tuple[str, ...]:
    occurrences = sum(len(family.occurrences) for family in families)
    occurrence_word = "occurrence" if occurrences == 1 else "occurrences"
    family_word = "family" if len(families) == 1 else "families"
    lines = [
        "## Symptom families",
        "",
        f"Parquity grouped **{occurrences}** {occurrence_word} into **{len(families)}**",
        f"conservative {family_word}. A family is a navigation aid, not a confirmed root cause",
        "or bug count.",
        "",
        "| Signal | Source cell result | Route | Diagnostic kind | Detail | "
        "Occurrences | Replay state | Evidence |",
        "|---|---|---|---|---|---:|---|---|",
    ]
    for family in families:
        representative = family.representative
        diagnostics = cast(list[dict[str, str]], family.projection["diagnostics"])
        lines.append(
            f"| `{family.signal.value}` | `{_source_verdict(family)}` | "
            f"`{_family_route(family)}` | {_brief(diagnostics[0]['diagnostic_kind'])} | "
            f"{_brief(representative.detail)} | "
            f"{len(family.occurrences)} | `{representative.reproduction_state.value}` | "
            f"[open finding](findings/{representative.finding_id}/REPORT.md) |"
        )
    return tuple(lines)


def _coverage_lines(run: RunRecord) -> tuple[str, ...]:
    discovery = run.discovery
    lines = [
        f"- The run stopped because: {_stop_reason(discovery.stop_reason)}.",
        "- Results cover only the selected providers, versions, profiles, seed, and bounds.",
        "- A finding proves recorded behavior; it does not assign provider fault.",
    ]
    if discovery.examples is not None:
        lines.extend(
            (
                f"- Requested example bound: `{discovery.examples}`; seed: `{discovery.seed}`.",
                f"- Finding-report limit: `{discovery.max_findings}`.",
            )
        )
    return tuple(lines)


def _command(run: RunRecord, *, schema: bool) -> str:
    suffix = _selection_suffix(run)
    if run.command == "check":
        return f"parquity check CASE.json --out RUN_DIR{suffix}"
    discovery = run.discovery
    profile = " --schema SCHEMA_CASE.json" if schema else ""
    return (
        f"parquity fuzz --examples {discovery.examples} --seed {discovery.seed} "
        f"--max-findings {discovery.max_findings}{profile} --out RUN_DIR{suffix}"
    )


def _selection_suffix(run: RunRecord) -> str:
    writers = ",".join(engine.name for engine in run.writers)
    readers = ",".join(engine.name for engine in run.readers)
    profiles = ""
    if run.writer_profiles is not None:
        profiles = f" --writer-profiles {','.join(run.writer_profiles.requested_profiles)}"
    return f" --writers {writers} --readers {readers}{profiles}"


def _count(value: int | None) -> str:
    return "not recorded" if value is None else str(value)


def _stop_reason(value: str) -> str:
    if value == "FINDING_CAP_REACHED":
        return "the `--max-findings` limit was reached"
    if value == "EXAMPLE_BOUND_REACHED":
        return "the requested generated-Case bound was reached"
    return "the supplied Case was checked"


def _source_verdict(family: Family) -> str:
    provider = "WRITE_ERROR" if family.projection["operation"] == "write" else "READ_ERROR"
    return {
        "PROVIDER_ERROR": provider,
        "ROW_COUNT_DIFFERENCE": "ROW_COUNT_MISMATCH",
        "VALUE_DIFFERENCE": "VALUE_MISMATCH",
        "SCHEMA_DIFFERENCE": "SCHEMA_MISMATCH",
    }[family.signal.value]


def _family_route(family: Family) -> str:
    entries = cast(list[dict[str, str]], family.projection["engine_roles"])
    roles = {item["role"]: item["engine"] for item in entries}
    writer = roles.get("writer", "?") + profile_label(
        family.representative.writer_profile,
        profiled=family.representative.writer_profiles is not None,
    )
    return f"{writer} → {roles.get('reader', 'write stage')}"


def _brief(value: str) -> str:
    limit = 120
    return markdown_literal(value if len(value) <= limit else f"{value[: limit - 1]}…")


def _engines(engines: tuple[EngineVersion, ...]) -> str:
    return ", ".join(f"{engine.name} {engine.version}" for engine in engines)


__all__ = ["render_run_report"]
