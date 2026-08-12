from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..case import encode_value, type_label
from ..evidence import ReplayClassification, is_sha256
from ..evidence import json_codec as codec
from ..generation.search.identity import FindingKey, finding_key
from ..model import Case
from ..reporting import (
    FULL_INLINE_MAX_CELL_CHARS,
    FULL_INLINE_MAX_COLUMNS,
    FULL_INLINE_MAX_ROWS,
    FULL_INLINE_MAX_UTF8_BYTES,
    MAX_SUMMARY_CHARS,
    PREVIEW_CELL_CHARS,
    PREVIEW_COLUMNS,
    PREVIEW_ROWS,
    ArtifactRef,
    DetailView,
    EvidenceKind,
    EvidenceReportView,
    InputView,
    ReplayState,
    ReportValidationError,
    ReproductionStep,
    TableView,
    bounded_text,
)
from ..verdicts import CellResult, FailureFingerprint
from .matrix import MatrixRecord
from .model import ReductionEvidence, finding_id_for

if TYPE_CHECKING:
    from .bundle import FindingSource, ValidatedBundle


@dataclass(frozen=True, slots=True)
class FindingReportContext:
    targets: tuple[tuple[str, FailureFingerprint], ...]

    def __post_init__(self) -> None:
        if not self.targets or len(self.targets) != len(set(self.targets)):
            raise ReportValidationError("generated report targets must be non-empty and unique")
        if any(not is_sha256(case_id) for case_id, _ in self.targets):
            raise ReportValidationError("generated report target has a malformed Input ID")
        expected = tuple(sorted(self.targets, key=_target_sort_key))
        if self.targets != expected or len({finding_key(item[1]) for item in self.targets}) != 1:
            raise ReportValidationError(
                "generated report targets must be canonical members of one Finding"
            )

    @property
    def key(self) -> FindingKey:
        return finding_key(self.targets[0][1])

    @property
    def occurrence_count(self) -> int:
        return len(self.targets)

    @property
    def distinct_input_count(self) -> int:
        return len({case_id for case_id, _ in self.targets})


def build_evidence_report_view(
    source: FindingSource,
    finding_id: str,
    matrix: MatrixRecord,
    selected: CellResult,
    context: FindingReportContext,
    replay: ReplayClassification | None = None,
) -> EvidenceReportView:
    expected_id = finding_id_for(source.case.case_id, source.fingerprint)
    if finding_id != expected_id:
        raise ReportValidationError("generated report Finding ID conflicts with its target")
    if (
        selected.fingerprint != source.fingerprint
        or matrix.target != source.fingerprint
        or context.key != finding_key(source.fingerprint)
    ):
        raise ReportValidationError("generated report target conflicts with evidence")
    participants = _participants(source.fingerprint)
    outcome = (
        selected.verdict.value
        if selected.diagnostic_kind == selected.verdict.value
        else f"{selected.verdict.value} · {selected.diagnostic_kind}"
    )
    return EvidenceReportView(
        evidence_kind=EvidenceKind.GENERATED,
        title=bounded_text(f"{participants} · {selected.operation} · {outcome}", MAX_SUMMARY_CHARS),
        summary=bounded_text(
            selected.detail.strip() or selected.diagnostic_kind, MAX_SUMMARY_CHARS
        ),
        facts=_facts(source, context, replay),
        reproduce=_reproduction_steps(),
        input=_input_view(source.case, selected.operation != "write"),
        finding_evidence=(),
        outcomes=_outcomes(matrix),
        environment=_environment(source),
        machine_record=ArtifactRef("finding.json", "finding.json"),
    )


def _facts(
    source: FindingSource,
    context: FindingReportContext,
    replay: ReplayClassification | None,
) -> tuple[DetailView, ...]:
    facts: list[DetailView] = []
    if context.occurrence_count > 1:
        tables = context.distinct_input_count
        table_kind = "supplied" if source.command == "check" else "generated"
        if tables == context.occurrence_count:
            repeated = f"Seen on {tables} {table_kind} tables"
        elif tables == 1:
            repeated = f"Seen {context.occurrence_count} times on this {table_kind} table"
        else:
            repeated = f"Seen {context.occurrence_count} times across {tables} {table_kind} tables"
        facts.append(DetailView("Repeated", f"{repeated}; this reproducer uses one of them"))
    if replay is not None:
        facts.append(DetailView("Last replay", ReplayState(replay.value).display_label))
    facts.append(
        DetailView("Table provenance", _input_provenance(source.command, source.reduction))
    )
    return tuple(facts)


def _input_view(case: Case, has_writer_artifact: bool) -> InputView:
    encoded = _encoded_cells(case)
    full = _can_inline_full(case, encoded)
    row_limit = len(case.rows) if full else min(len(case.rows), PREVIEW_ROWS)
    column_limit = len(case.fields) if full else min(len(case.fields), PREVIEW_COLUMNS)
    cell_limit = FULL_INLINE_MAX_CELL_CHARS if full else PREVIEW_CELL_CHARS
    headers = ("Row", *(field.name for field in case.fields[:column_limit]))
    rows = tuple(
        (
            str(index + 1),
            *(_cell_text(encoded[index][column], cell_limit) for column in range(column_limit)),
        )
        for index in range(row_limit)
    )
    artifacts = [ArtifactRef("canonical table", "case.json")]
    if has_writer_artifact:
        artifacts.append(ArtifactRef("writer-produced Parquet", "input.parquet"))
    omitted_rows = len(case.rows) - row_limit
    omitted_columns = len(case.fields) - column_limit
    omitted_cells = len(case.rows) * len(case.fields) - row_limit * column_limit
    truncated_cells = sum(
        len(encoded[row][column]) > cell_limit
        for row in range(row_limit)
        for column in range(column_limit)
    )
    note = None
    if not full:
        note = (
            f"Preview only: {omitted_rows} rows, {omitted_columns} columns, and "
            f"{omitted_cells} cells omitted; "
            f"{truncated_cells} shown cells shortened. Open case.json for the complete table."
        )
    return InputView(
        identity=case.case_id,
        facts=(
            DetailView("Rows", str(len(case.rows))),
            DetailView("Columns", str(len(case.fields))),
        ),
        artifacts=tuple(artifacts),
        schema=TableView(
            ("Column", "Type", "Nullable"),
            tuple(
                (field.name, type_label(field.type_spec), "yes" if field.nullable else "no")
                for field in case.fields[:column_limit]
            ),
        ),
        data=TableView(headers, rows),
        omission_note=note,
    )


def _input_provenance(command: str, reduction: ReductionEvidence) -> str:
    origin = "Supplied table" if command == "check" else "Generated table"
    hypothesis = (
        "Hypothesis shrink applied" if reduction.hypothesis_reduced else "no Hypothesis shrink"
    )
    deterministic = (
        f"{reduction.total} deterministic "
        f"{'reduction' if reduction.total == 1 else 'reductions'} applied"
        if reduction.total
        else "no deterministic reductions"
    )
    return f"{origin}; {hypothesis}; {deterministic}"


def _reproduction_steps() -> tuple[ReproductionStep, ...]:
    return (
        ReproductionStep(
            "Parquity replay",
            "python reproduce.py",
            "Replays this reproducer. Exit 1 means reproduced; exit 0 means not reproduced.",
        ),
        ReproductionStep(
            "Provider-only reproduction",
            "python upstream_repro.py",
            "Runs the provider path directly and prints JSON. Provider errors exit 1; "
            "semantic differences can exit 0 and remain in the output.",
        ),
    )


def _encoded_cells(case: Case) -> tuple[tuple[str, ...], ...]:
    return tuple(
        tuple(
            codec.canonical_bytes(encode_value(field.type_spec, value)).decode("utf-8")
            for field, value in zip(case.fields, row, strict=True)
        )
        for row in case.rows
    )


def _target_sort_key(value: tuple[str, FailureFingerprint]) -> tuple[str, bytes]:
    return value[0], value[1].canonical_bytes()


def _can_inline_full(case: Case, cells: tuple[tuple[str, ...], ...]) -> bool:
    return (
        len(case.rows) <= FULL_INLINE_MAX_ROWS
        and len(case.fields) <= FULL_INLINE_MAX_COLUMNS
        and len(case.canonical_bytes()) <= FULL_INLINE_MAX_UTF8_BYTES
        and all(len(value) <= FULL_INLINE_MAX_CELL_CHARS for row in cells for value in row)
    )


def _cell_text(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _outcomes(matrix: MatrixRecord) -> TableView:
    return TableView(
        ("Writer", "Reader", "Stage", "Result", "Location", "Diagnostic"),
        tuple(
            (
                _writer_label(item),
                "—" if item.reader == "*" else item.reader,
                item.operation,
                item.verdict.value,
                item.schema_path,
                item.detail,
            )
            for item in matrix.results
        ),
    )


def _writer_label(result: CellResult) -> str:
    profile = result.writer_profile
    return result.writer if profile is None else f"{result.writer} [{profile.name}]"


def _participants(fingerprint: FailureFingerprint) -> str:
    writer = fingerprint.writer
    if fingerprint.writer_profile is not None:
        writer += f" [{fingerprint.writer_profile.name}]"
    return f"{writer} (write)" if fingerprint.reader == "*" else f"{writer} → {fingerprint.reader}"


def _environment(source: FindingSource) -> tuple[DetailView, ...]:
    environment = source.environment
    providers = ", ".join(sorted(f"{item.name} {item.version}" for item in environment.providers))
    dependencies = ", ".join(f"{item.package} {item.version}" for item in environment.dependencies)
    values = (
        DetailView("Parquity", environment.parquity_version),
        DetailView("Hypothesis", environment.hypothesis_version),
        DetailView("Python", environment.python_version),
        DetailView("Platform", environment.platform),
        DetailView("Providers", providers),
    )
    return values if not dependencies else (*values, DetailView("Dependencies", dependencies))


def build_standalone_report_view(
    validated: ValidatedBundle,
    replay: ReplayClassification,
) -> EvidenceReportView:
    from .bundle import FindingSource  # noqa: PLC0415 - adapter avoids a bundle/report cycle.

    finding = validated.finding
    source = FindingSource(
        case=validated.case,
        discovered_case=validated.discovered_case,
        fingerprint=finding.fingerprint,
        command=finding.command,
        writers=finding.writers,
        readers=finding.readers,
        discovery=finding.discovery,
        environment=finding.environment,
        reduction=finding.reduction,
        generation=finding.generation,
        writer_profiles=finding.writer_profiles,
    )
    context = FindingReportContext(((finding.reduction.discovered_case_id, finding.fingerprint),))
    return build_evidence_report_view(
        source,
        finding.finding_id,
        validated.matrix,
        finding.result,
        context,
        replay,
    )


__all__ = [
    "FindingReportContext",
    "build_evidence_report_view",
    "build_standalone_report_view",
]
