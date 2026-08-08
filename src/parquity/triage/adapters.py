from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, cast

from ..reporting import markdown_literal
from ..scans import symptoms
from ..verdicts import Verdict
from .model import FAMILY_FORMAT, Occurrence, Signal, canonical_bytes
from .normalization import detail_sha256_v1, normalize_generated_path

if TYPE_CHECKING:
    from ..findings.bundle import ValidatedBundle
    from ..runs.bundle import ValidatedRun
    from ..scans.bundle import ValidatedScanFinding, ValidatedScanRun
    from ..verdicts import EngineVersion

_GENERATED_SIGNALS = {
    Verdict.WRITE_ERROR: Signal.PROVIDER_ERROR,
    Verdict.READ_ERROR: Signal.PROVIDER_ERROR,
    Verdict.ROW_COUNT_MISMATCH: Signal.ROW_COUNT_DIFFERENCE,
    Verdict.VALUE_MISMATCH: Signal.VALUE_DIFFERENCE,
    Verdict.SCHEMA_MISMATCH: Signal.SCHEMA_DIFFERENCE,
}


def generated_occurrences(validated: ValidatedRun) -> tuple[Occurrence, ...]:
    return tuple(_generated_occurrence(child) for child in validated.children)


def scan_occurrences(validated: ValidatedScanRun) -> tuple[Occurrence, ...]:
    return scan_child_occurrences(validated.children)


def generated_child_occurrences(
    children: tuple[ValidatedBundle, ...],
) -> tuple[Occurrence, ...]:
    return tuple(_generated_occurrence(child) for child in children)


def scan_child_occurrences(
    children: tuple[ValidatedScanFinding, ...],
) -> tuple[Occurrence, ...]:
    return tuple(item for child in children for item in _scan_occurrences(child))


def _generated_occurrence(child: ValidatedBundle) -> Occurrence:
    finding = child.finding
    result = finding.result
    signal = _GENERATED_SIGNALS[result.verdict]
    engine_roles: list[dict[str, object]] = [{"role": "writer", "engine": result.writer}]
    if result.reader != "*":
        engine_roles.append({"role": "reader", "engine": result.reader})
    location = normalize_generated_path(result.schema_path, child.case)
    detail_sha256 = detail_sha256_v1(result.detail)
    diagnostic = {
        "verdict": result.verdict.value,
        "diagnostic_kind": result.diagnostic_kind,
        "path": location,
        "detail_sha256": detail_sha256,
    }
    projection: dict[str, object] = {
        "projection_version": FAMILY_FORMAT,
        "evidence_regime": "generated",
        "signal": signal.value,
        "engine_roles": _canonical_values(engine_roles),
        "operation": result.operation,
        "diagnostics": [diagnostic],
    }
    identity: dict[str, object] = {
        "occurrence_format": symptoms.OCCURRENCE_FORMAT,
        "evidence_regime": "generated",
        "finding_id": finding.finding_id,
        "signal": signal.value,
        "operation": result.operation,
        "evidence": [diagnostic],
    }
    if result.writer_profile is not None:
        profile_data = result.writer_profile.to_data()
        projection["writer_profile"] = profile_data
        identity["writer_profile"] = profile_data
    artifact_name = "input.parquet" if finding.input_parquet else "case.json"
    artifact = next(item for item in finding.artifacts if item.name == artifact_name)
    reduction = finding.reduction
    reduced = (
        reduction.discovered_case_id != reduction.minimized_case_id
        or reduction.hypothesis_reduced
        or reduction.total > 0
    )
    providers = (
        *(("writer", item.name, item.version) for item in finding.writers),
        *(("reader", item.name, item.version) for item in finding.readers),
    )
    packages = (
        ("hypothesis", finding.environment.hypothesis_version),
        ("parquity", finding.environment.parquity_version),
        *((item.package, item.version) for item in finding.environment.dependencies),
    )
    return Occurrence(
        symptoms.occurrence_id(identity),
        finding.finding_id,
        "generated",
        signal,
        projection,
        "case_id",
        finding.case_id,
        artifact_name,
        artifact.sha256,
        artifact.byte_count,
        reduced,
        tuple(sorted(packages)),
        tuple(sorted(providers)),
        location,
        result.detail,
        detail_sha256,
        writer_profiles=finding.writer_profiles,
        writer_profile=result.writer_profile,
    )


def _scan_occurrences(child: ValidatedScanFinding) -> tuple[Occurrence, ...]:
    record = child.record
    providers = tuple(("reader", item.name, item.version) for item in record.engines)
    return tuple(
        Occurrence(
            item.occurrence_id,
            record.finding_id,
            "scan",
            Signal(item.signal),
            _scan_projection(item, record.timeout_seconds),
            "source_path",
            record.source_path,
            "input.parquet",
            record.input_sha256,
            record.input_bytes,
            None,
            (("parquity", record.parquity_version),),
            tuple(sorted(providers)),
            item.normalized_location,
            item.detail,
            item.detail_sha256,
            related_id=item.related_id,
        )
        for item in symptoms.extract(record, detail_sha256_v1)
    )


def _scan_projection(item: symptoms.ScanSymptom, timeout: int) -> dict[str, object]:
    projection: dict[str, object] = {
        "projection_version": FAMILY_FORMAT,
        "evidence_regime": "scan",
        "signal": item.signal,
        "operation": "read",
        "reader_roster": list(item.reader_roster),
    }
    if item.target_reader is not None:
        evidence = item.evidence[0]
        projection.update(
            engine_roles=[{"role": "reader", "engine": item.target_reader}],
            outcome_kind=evidence["outcome_kind"],
            diagnostic_kind=evidence["diagnostic_kind"],
            detail_sha256=evidence["detail_sha256"],
        )
        if item.signal == Signal.TIMEOUT:
            projection["timeout_seconds"] = timeout
    else:
        projection.update(
            engine_roles=[{"role": "reader", "engine": engine} for engine in item.reader_roster],
            normalized_location=item.normalized_location,
            comparisons=[dict(value) for value in item.evidence],
        )
    return projection


def render_scan_finding_summary(
    source_path: str,
    outcomes: tuple[Mapping[str, object], ...],
    comparisons: tuple[Mapping[str, object], ...],
    occurrences: tuple[symptoms.ScanSymptom, ...],
) -> str:
    lines = [
        "- Operation: read existing Parquet file",
        f"- Source: {markdown_literal(source_path)}",
        "- Readers (canonical order):",
    ]
    execution = {
        item.evidence_indexes[0]: item for item in occurrences if item.target_reader is not None
    }
    for index, outcome in enumerate(outcomes):
        group = ""
        observation_group = outcome["observation_group"]
        if isinstance(observation_group, str):
            group = f"; observation group {markdown_literal(observation_group)}"
        engine = cast(str, outcome["engine"])
        version = cast(str, outcome["version"])
        kind = cast(str, outcome["kind"])
        lines.append(f"  - {markdown_literal(engine)} {markdown_literal(version)}: {kind}{group}")
        if kind != "SUCCESS":
            raw_detail = cast(str, outcome["detail"])
            detail = markdown_literal(raw_detail)
            if kind == "PROCESS_CRASH" and not raw_detail:
                detail = "No diagnostic text was captured."
            lines.append(f"    Occurrence ID: `{execution[index].occurrence_id}`")
            diagnostic = markdown_literal(cast(str, outcome["diagnostic_kind"]))
            lines.append(f"    Diagnostic kind: {diagnostic}; detail: {detail}")
            lines.append("    No comparison path exists because this reader returned no table.")
    semantic = tuple(item for item in occurrences if item.normalized_location is not None)
    lines.append("- Semantic symptom occurrences:" if semantic else "- Semantic symptoms: none")
    lines.extend(
        f"  - `{item.occurrence_id}`; signal `{item.signal}`; location "
        f"{markdown_literal(str(item.normalized_location))}; "
        f"comparisons `{len(item.evidence_indexes)}`"
        for item in semantic
    )
    lines.append("- Comparisons:" if comparisons else "- Comparisons: none")
    lines.extend(
        f"  - {cast(str, item['kind'])}; path {markdown_literal(cast(str, item['path']))}; "
        f"groups {markdown_literal(cast(str, item['left_group']))} vs "
        f"{markdown_literal(cast(str, item['right_group']))}; "
        f"detail {markdown_literal(cast(str, item['detail']))}"
        for item in comparisons
    )
    return "\n".join(lines)


def render_scan_run_summary(
    status: str,
    file_count: int,
    skipped: int,
    engines: tuple[EngineVersion, ...],
    findings: tuple[tuple[str, str], ...],
    overflow_count: int,
) -> str:
    lines = [
        f"- Status: {markdown_literal(status)}",
        f"- Discovered files: {file_count}",
        f"- Evaluated files: {file_count - overflow_count}",
        f"- Skipped symlinks: {skipped}",
        "- Readers (canonical order):",
        *(
            f"  - {markdown_literal(item.name)} {markdown_literal(item.version)}"
            for item in engines
        ),
        f"- Retained finding bundles: {len(findings)}",
        *(
            f"  - Source {markdown_literal(path)}; child {markdown_literal(finding_id)}"
            for path, finding_id in findings
        ),
        f"- Overflow files not evaluated: {overflow_count}",
        "- Evaluation scope: incomplete; the finding cap stopped evaluation."
        if status == "FINDING_CAP_REACHED"
        else "- Evaluation scope: complete for all discovered files.",
    ]
    return "\n".join(lines)


def _canonical_values(values: Sequence[Mapping[str, object]]) -> list[Mapping[str, object]]:
    return sorted(values, key=canonical_bytes)


__all__ = [
    "generated_child_occurrences",
    "generated_occurrences",
    "render_scan_finding_summary",
    "render_scan_run_summary",
    "scan_child_occurrences",
    "scan_occurrences",
]
