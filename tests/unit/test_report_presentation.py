from __future__ import annotations

from pathlib import Path

import pyarrow as pa
import pytest

from parquity.cli.presentation import render
from parquity.compare import compare_case
from parquity.findings.evidence import (
    DISCOVERY_OVERFLOW,
    EXAMPLE_BOUND_REACHED,
    FINDING_CAP_REACHED,
    MINIMIZATION_OVERFLOW,
    DiscoveryEvidence,
)
from parquity.generation.search import OverflowObservation
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.reporting import (
    describe_type,
    human_location,
    profile_label,
    render_case_rows,
    render_case_schema,
    render_difference,
    render_matrix,
    render_pipeline,
)
from parquity.result_evidence import DifferenceEvidence
from parquity.runs.entries import OverflowEvidence
from parquity.scans import symptoms
from parquity.triage.adapters import render_scan_finding_summary, render_scan_run_summary
from parquity.verdicts import CellResult, EngineVersion, Verdict
from parquity.writer_profiles import WriterProfileIdentity


def test_case_presentation_explains_empty_data_and_nested_shape() -> None:
    nested = TypeSpec(
        Kind.FIXED_LIST,
        item=TypeSpec(Kind.BINARY),
        item_nullable=False,
        size=1,
    )
    case = Case((Field("payload", nested, nullable=False),), ())
    schema = "\n".join(render_case_schema(case))
    rows = "\n".join(render_case_rows(case))
    assert "fixed-size list" in schema and "item type binary" in schema
    assert "exactly 1 item" in schema and "exactly 1 items" not in schema
    assert "payload" in schema
    assert len(schema.splitlines()) == 3
    assert "This Case has no rows" in rows


def test_generated_and_scan_locations_have_human_and_canonical_forms() -> None:
    case = Case((Field("value_with_syntax", TypeSpec(Kind.INT32)),), ((1,),))

    generated = human_location("$rows[0].value_with_syntax", case)
    scanned = human_location("$.rows[1].columns[2]")

    assert "row 1" in generated and "column 1" in generated
    assert "$rows[0].value_with_syntax" in generated
    assert "row 2" in scanned and "column 3" in scanned and "$.rows[1].columns[2]" in scanned


def test_provider_error_presentation_does_not_invent_expected_or_observed_values() -> None:
    result = CellResult(
        "writer",
        "1",
        "reader",
        "2",
        "read",
        Verdict.READ_ERROR,
        "$",
        "provider rejected the file",
        "ProviderError",
    )
    rendered = "\n".join(render_difference(result))

    assert "Provider diagnostic" in rendered and "provider rejected the file" in rendered
    assert "Expected from the Case" not in rendered
    assert "Observed from the reader" not in rendered
    passed = CellResult("writer", "1", "reader", "2", "compare", Verdict.PASS, "$", "match")
    matrix = "\n".join(render_matrix((passed, result), profiled=False))
    assert "PASS</code> | — |" in matrix and "whole table" in matrix


def test_schema_row_and_value_disagreements_carry_typed_presentation_evidence() -> None:
    schema_case = Case((Field("expected", TypeSpec(Kind.INT32)),), ((1,),))
    row_case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,), (2,)))
    list_case = Case(
        (Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.INT32))),),
        (([1, 2],),),
    )
    struct_case = Case(
        (
            Field(
                "record",
                TypeSpec(Kind.STRUCT, fields=(Field("expected", TypeSpec(Kind.INT32)),)),
            ),
        ),
        (({"expected": 1},),),
    )
    struct_schema = pa.schema([pa.field("record", pa.struct([pa.field("renamed", pa.int32())]))])
    results = (
        compare_case(schema_case, pa.table({"observed": pa.array([1], type=pa.int32())})),
        compare_case(row_case, pa.table({"value": pa.array([1], type=pa.int32())})),
        compare_case(list_case, pa.table({"items": pa.array([[1, 3]], type=pa.list_(pa.int32()))})),
        compare_case(
            struct_case,
            pa.Table.from_pylist([{"record": {"renamed": 1}}], schema=struct_schema),
        ),
    )

    assert tuple(result.verdict for result in results) == (
        Verdict.SCHEMA_MISMATCH,
        Verdict.ROW_COUNT_MISMATCH,
        Verdict.VALUE_MISMATCH,
        Verdict.SCHEMA_MISMATCH,
    )
    assert tuple(result.difference for result in results) == (
        DifferenceEvidence('["expected"]', '["observed"]'),
        DifferenceEvidence("2", "1"),
        DifferenceEvidence("2", "3"),
        DifferenceEvidence('"expected"', '"renamed"'),
    )


def test_discovery_counts_and_overflow_origins_are_strict_typed_evidence() -> None:
    evidence = DiscoveryEvidence(10, 7, 3, EXAMPLE_BOUND_REACHED, 4, 28)
    failure = CellResult("writer", "1", "*", "*", "write", Verdict.WRITE_ERROR, "$", "failed")
    fingerprint = failure.fingerprint or pytest.fail("fingerprint missing")
    case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))

    assert DiscoveryEvidence.from_data(evidence.to_data()) == evidence
    assert {
        OverflowObservation(case.case_id, fingerprint, case, failure).origin,
        OverflowObservation(
            case.case_id, fingerprint, case, failure, origin=MINIMIZATION_OVERFLOW
        ).origin,
    } == {DISCOVERY_OVERFLOW, MINIMIZATION_OVERFLOW}
    overflow = OverflowEvidence(case, failure, FINDING_CAP_REACHED)
    assert OverflowEvidence.from_data(overflow.to_data()) == overflow
    with pytest.raises(ValueError):
        OverflowEvidence.from_data({**overflow.to_data(), "case_id": "0" * 64})
    with pytest.raises(ValueError):
        DiscoveryEvidence(10, 7, 3, EXAMPLE_BOUND_REACHED, 1, None)
    with pytest.raises(ValueError):
        DifferenceEvidence.from_data({"expected": "value"})
    with pytest.raises(ValueError):
        DifferenceEvidence("", "observed")
    with pytest.raises(ValueError):
        DifferenceEvidence.from_data({"expected": 1, "observed": "value"})


def test_terminal_fuzz_summary_leads_with_findings_and_actual_search_scope() -> None:
    document: dict[str, object] = {
        "command": "fuzz",
        "status": "RUN_PUBLISHED",
        "run_status": "FINDING_CAP_REACHED",
        "finding_count": 1,
        "overflow_count": 2,
        "discovery": {
            "examples": 50,
            "evaluated_cases": 7,
            "max_findings": 1,
        },
        "findings": [
            {
                "writer": "writer-a",
                "reader": "reader-b",
                "verdict": "SCHEMA_MISMATCH",
                "schema_path": "$schema.payload",
                "diagnostic_kind": "SchemaError",
                "detail": "expected nested type, observed scalar type",
            }
        ],
        "output": "result",
    }

    output = render(document, controls=False)

    assert output.startswith("FINDINGS · 1 saved (finding limit reached)")
    assert "Checked 7 of up to 50 generated Cases." in output
    assert "SCHEMA_MISMATCH" in output and "writer-a → reader-b" in output
    assert "payload · expected nested type, observed scalar type" in output
    assert "SchemaError" not in output
    assert "2 more distinct observations" in output and "--max-findings above 1" in output
    assert "Overflow" not in output and "materialized" not in output
    assert output.count("result/REPORT.md") == 1


def test_case_preview_pipeline_and_locations_explain_the_evidence_contract() -> None:
    fields = tuple(Field(f"field_{index}", TypeSpec(Kind.INT32)) for index in range(9))
    case = Case(fields, tuple(tuple(range(9)) for _ in range(4)))
    rows = render_case_rows(case)
    assert len(rows) == 35
    assert rows[-1] == "| … | … | 4 more cells; see `case.json` |"

    profile = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    write = CellResult(
        "writer",
        "1",
        "*",
        "*",
        "write",
        Verdict.WRITE_ERROR,
        "$",
        "failed",
        writer_profile=profile,
    )
    read = CellResult("writer", "1", "reader", "2", "read", Verdict.READ_ERROR, "$", "failed")
    compared = CellResult("writer", "1", "reader", "2", "compare", Verdict.PASS, "$", "match")
    assert "writer raised an error" in "\n".join(render_pipeline(write))
    assert "reader raised an error" in "\n".join(render_pipeline(read))
    assert "Compare with the Case" in "\n".join(render_pipeline(compared))
    assert "Structured expected/observed evidence is unavailable" in "\n".join(
        render_difference(compared)
    )
    assert profile_label(None, profiled=True) == " [default]"
    assert profile_label(profile, profiled=False) == ""
    with pytest.raises(TypeError):
        profile_label(object(), profiled=True)

    assert "table schema" in human_location("$schema")
    assert "row count" in human_location("$rows")
    assert "schema field" in human_location("$schema.")
    assert "nested path" in human_location("$rows[2].items[0]")
    assert "nested path" in human_location("$rows[0].field_0.child", case)
    assert "canonical path" in human_location("$unknown")


def test_type_descriptions_cover_nested_temporal_decimal_and_map_shapes() -> None:
    descriptions = (
        describe_type(TypeSpec(Kind.LIST, item=TypeSpec(Kind.STRING), item_nullable=True)),
        describe_type(TypeSpec(Kind.STRUCT, fields=(Field("value", TypeSpec(Kind.INT64)),))),
        describe_type(
            TypeSpec(
                Kind.MAP,
                key=TypeSpec(Kind.STRING),
                value=TypeSpec(Kind.INT32),
                value_nullable=False,
            )
        ),
        describe_type(TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC")),
        describe_type(TypeSpec(Kind.TIMESTAMP, unit="us")),
        describe_type(TypeSpec(Kind.DECIMAL128, precision=8, scale=2)),
    )
    rendered = "\n".join(f"{item.name}: {item.shape}" for item in descriptions)
    for expected in (
        "items may be null",
        "value: int64",
        "values are required",
        "timezone UTC",
        "no timezone",
        "precision 8; scale 2",
    ):
        assert expected in rendered


def test_terminal_check_summary_bounds_rows_and_uses_diagnostic_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        {
            "writer": "writer-a",
            "reader": "*" if index == 0 else "reader-b",
            "verdict": "WRITE_ERROR" if index == 0 else "VALUE_MISMATCH",
            "schema_path": "$" if index == 0 else "$schema.value",
            "diagnostic_kind": "ProviderError",
            "detail": "" if index == 0 else "x" * 100,
        }
        for index in range(9)
    ]
    output = render(
        {
            "command": "check",
            "status": "RUN_PUBLISHED",
            "findings": findings,
            "output": "result",
        },
        controls=False,
    )
    assert "Checked the supplied Case." in output
    assert "writer-a · write" in output and "whole table · ProviderError" in output
    assert "value · " in output and "…" in output
    assert "1 more saved finding is in the report." in output

    without_report = render(
        {
            "command": "check",
            "status": "RUN_PUBLISHED",
            "findings": [{**findings[1], "schema_path": "$rows"}],
        },
        controls=False,
    )
    assert "$rows · " in without_report and "Next:" not in without_report

    def fail_resolve(_path: Path) -> Path:
        raise OSError

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert "result/REPORT.md" in render(
        {"command": "scan", "status": "RUN_PUBLISHED", "output": "result"}, controls=True
    )

    for python_support in (None, {"engine-a": list[str]()}):
        document: dict[str, object] = {
            "command": "engines",
            "engines": [None, {"name": "engine-a", "reader": False, "writer": True}],
            "python_support": python_support,
        }
        engines = render(document, controls=False)
        assert "Python" not in engines and "engine-a" in engines


def test_scan_summaries_explain_execution_semantics_and_evaluation_scope() -> None:
    roster = ("reader-a", "reader-b")

    def occurrence(
        signal: str, target: str | None, location: str | None, index: int
    ) -> symptoms.ScanSymptom:
        identity = (f"occurrence-{index}", "finding", signal, target, location)
        evidence = ((), (index,), ("detail",), "detail", "a" * 64, roster, f"related-{index}")
        return symptoms.ScanSymptom._make(identity + evidence)

    execution = occurrence("PROCESS_CRASH", "reader-b", None, 1)
    semantic = occurrence("VALUE_DIFFERENCE", None, "$.rows[*].columns[0]", 0)
    success = {"engine": "reader-a", "version": "1", "kind": "SUCCESS", "observation_group": "g"}
    crash = {
        "engine": "reader-b",
        "version": "2",
        "kind": "PROCESS_CRASH",
        "observation_group": None,
        "diagnostic_kind": "PROCESS_CRASH",
        "detail": "",
    }
    finding = render_scan_finding_summary(
        "input.parquet", (success, crash), (), (execution, semantic)
    )
    assert "observation group" in finding and "No diagnostic text was captured" in finding
    assert "occurrence-1" in finding and "occurrence-0" in finding
    crash["detail"] = "captured diagnostic"
    assert "captured diagnostic" in render_scan_finding_summary(
        "input.parquet", (success, crash), (), (execution, semantic)
    )
    engines = tuple(EngineVersion(name, str(index)) for index, name in enumerate(roster, 1))
    capped = render_scan_run_summary("FINDING_CAP_REACHED", 3, 1, engines, (("a", "f"),), 1)
    complete = render_scan_run_summary("FINDINGS_FOUND", 1, 0, engines, (), 0)
    assert "Evaluation scope: incomplete" in capped and 'Source "a"; child "f"' in capped
    assert "Evaluation scope: complete" in complete and "Retained finding bundles: 0" in complete
