from __future__ import annotations

import json

from ..model import Case
from ..reporting import (
    human_location,
    markdown_literal,
    profile_label,
    render_case_rows,
    render_case_schema,
    render_difference,
    render_matrix,
    render_pipeline,
)
from ..verdicts import CellResult, EngineVersion, Verdict
from .evidence import DependencyVersion, DiscoveryEvidence, GenerationEvidence, ReductionEvidence
from .matrix import MatrixRecord
from .model import FindingRecord


def render_finding_report(
    finding: FindingRecord,
    case: Case,
    matrix: MatrixRecord,
) -> bytes:
    target = finding.result
    lines = [
        f"# Parquity finding · {_headline(target.verdict)}",
        "",
        _summary(target, profiled=finding.writer_profiles is not None),
        "",
        "This is reproducible interoperability evidence. It does not by itself identify which",
        "provider is at fault.",
        "",
        "## What happened",
        "",
        *render_pipeline(target),
        "",
        *render_difference(target, case),
        "",
        "## Input Case",
        "",
        "The Case is the table Parquity asked the writer to encode. It is also the expected",
        "schema and data for semantic comparison.",
        "",
        "### Schema",
        "",
        *render_case_schema(case),
        "",
        "### Data",
        "",
        *render_case_rows(case),
        "",
        "Open [`case.json`](case.json) for the complete canonical input.",
        "",
        "## Reproduce",
        "",
        "Run `python reproduce.py` in this directory. Exit 1 means this exact target",
        "reproduced; exit 0 means it did not. Exit 2 means required evidence or providers are",
        "unavailable; exit 3 means Parquity itself failed.",
        "",
        "Run `python upstream_repro.py` for direct provider output without Parquity's semantic",
        "comparison. Inspect the script before running it.",
        "",
        "## Complete writer-reader matrix",
        "",
        "Every requested cell is shown. `PASS` means that cell matched the Case; another cell",
        "may still disagree.",
        "",
        *render_matrix(
            matrix.results,
            profiled=finding.writer_profiles is not None,
            case=case,
        ),
        "",
        "Open [`matrix.json`](matrix.json) for complete diagnostics for every cell.",
        "",
        "## What this evidence establishes",
        "",
        *_claim_lines(target),
        "",
        *_discovery_section(finding.discovery, finding.reduction, finding.generation),
        "",
        "## Technical evidence",
        "",
        f"- Finding identity: `{finding.finding_id}`",
        f"- Final Case identity: `{case.case_id}`",
        f"- Target location: {human_location(target.schema_path, case)}",
        f"- Diagnostic kind: {markdown_literal(target.diagnostic_kind)}",
        f"- Normalized detail SHA-256: `{matrix.target.normalized_detail_sha256}`",
        "- Input Parquet artifact: "
        + ("[`input.parquet`](input.parquet)" if finding.input_parquet else "not retained"),
        "- Canonical manifest: [`finding.json`](finding.json)",
        *(
            ()
            if finding.writer_profiles is None
            else (
                "- Writer profile plan: `"
                + json.dumps(
                    finding.writer_profiles.to_data(), sort_keys=True, separators=(",", ":")
                )
                + "`",
            )
        ),
        "",
        "### Environment",
        "",
        f"- Parquity: `{finding.environment.parquity_version}`",
        f"- Hypothesis: `{finding.environment.hypothesis_version}`",
        f"- Python: `{finding.environment.python_version}`",
        f"- Platform: `{finding.environment.platform}`",
        "- Dependencies: " + _dependencies(finding.environment.dependencies),
        "- Selected writers: " + _engines(matrix.writers),
        "- Selected readers: " + _engines(matrix.readers),
        "",
    ]
    return "\n".join(lines).encode()


def _headline(verdict: Verdict) -> str:
    labels = {
        Verdict.WRITE_ERROR: "write error",
        Verdict.READ_ERROR: "read error",
        Verdict.SCHEMA_MISMATCH: "schema disagreement",
        Verdict.ROW_COUNT_MISMATCH: "row-count disagreement",
        Verdict.VALUE_MISMATCH: "value disagreement",
        Verdict.PASS: "agreement",
    }
    return labels[verdict]


def _summary(target: CellResult, *, profiled: bool) -> str:
    profile = profile_label(target.writer_profile, profiled=profiled)
    writer = f"`{target.writer}{profile}`"
    if target.reader == "*":
        return f"{writer} could not write the generated Case."
    reader = f"`{target.reader}`"
    if target.operation == "read":
        if target.writer == target.reader:
            return f"{reader} could not read back the file it wrote."
        return f"{writer} wrote the file, but {reader} could not read it."
    return f"{writer} wrote the file and {reader} read it, but the result disagreed with the Case."


def _claim_lines(target: CellResult) -> tuple[str, ...]:
    if target.operation == "write":
        claim = "the selected writer raised the recorded provider diagnostic for this Case"
    elif target.operation == "read":
        claim = "the writer completed and the selected reader raised the recorded diagnostic"
    else:
        claim = "the writer and reader completed, then semantic comparison found this difference"
    return (
        f"- Established: {claim} in the recorded environment.",
        "- Not established: root cause, provider fault, behavior on untested versions, or",
        "  exhaustiveness beyond the recorded bounds.",
    )


def _discovery_section(
    discovery: DiscoveryEvidence,
    reduction: ReductionEvidence,
    generation: GenerationEvidence | None,
) -> tuple[str, ...]:
    lines = [
        "## Discovery and minimization",
        "",
        f"- Stop reason: `{discovery.stop_reason}`",
        f"- Discovered Case identity: `{reduction.discovered_case_id}`",
        f"- Minimized Case identity: `{reduction.minimized_case_id}`",
        f"- Successful deterministic reductions: `{reduction.total}`",
        "- Reduction breakdown: "
        f"fields `{reduction.fields}`, rows `{reduction.rows}`, nullability "
        f"`{reduction.nullability}`, containers `{reduction.containers}`, scalars "
        f"`{reduction.scalars}`.",
    ]
    if discovery.examples is not None:
        lines.extend(
            (
                f"- `--examples` requested: `{discovery.examples}`",
                "- Cases actually evaluated during discovery: "
                f"`{_count(discovery.evaluated_cases)}`",
                "- Matrix cells actually evaluated during discovery: "
                f"`{_count(discovery.evaluated_cells)}`",
                f"- Seed: `{discovery.seed}`",
                f"- `--max-findings`: `{discovery.max_findings}`",
            )
        )
    if generation is not None:
        lines.extend(
            (
                f"- Generation profile: `{generation.profile}`",
                f"- Schema Case identity: `{generation.schema_case_id}`",
            )
        )
    return tuple(lines)


def _count(value: int | None) -> str:
    return "not recorded" if value is None else str(value)


def _engines(engines: tuple[EngineVersion, ...]) -> str:
    return ", ".join(f"`{engine.name}` `{engine.version}`" for engine in engines)


def _dependencies(dependencies: tuple[DependencyVersion, ...]) -> str:
    return ", ".join(f"`{item.package}` `{item.version}`" for item in dependencies)


__all__ = ["render_finding_report"]
