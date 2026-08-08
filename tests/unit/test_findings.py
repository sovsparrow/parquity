from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace

import pytest

from parquity.findings import OPTIONAL_INPUT, REQUIRED_ARTIFACTS
from parquity.findings import json_codec as codec
from parquity.findings.evidence import (
    CHECK_COMPLETE,
    EXAMPLE_BOUND_REACHED,
    DependencyVersion,
    DiscoveryEvidence,
    EnvironmentEvidence,
    ReductionEvidence,
)
from parquity.findings.matrix import MatrixRecord
from parquity.findings.model import (
    ArtifactDigest,
    FindingRecord,
    FindingValidationError,
    ReplaySignature,
    finding_id_for,
)
from parquity.findings.observation import fingerprint_from_data
from parquity.findings.report import render_finding_report
from parquity.findings.scripts import render_reproduce
from parquity.findings.upstream_script import render_upstream_repro
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.result_evidence import DifferenceEvidence
from parquity.verdicts import CellResult, EngineVersion, Verdict
from tests.support.report_fragments import report_fragments


def _case() -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))


def _result(
    *,
    writer_version: str = "1",
    reader_version: str = "2",
    detail: str = "expected 1, got 2",
    diagnostic_kind: str = "VALUE_MISMATCH",
) -> CellResult:
    identity = ("pyarrow", writer_version, "duckdb", reader_version)
    outcome = ("compare", Verdict.VALUE_MISMATCH, "$rows[0].value", detail, diagnostic_kind)
    return CellResult(*identity, *outcome, difference=DifferenceEvidence("1", "2"))


def _environment() -> EnvironmentEvidence:
    providers = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    dependencies = (DependencyVersion("pyarrow", "1"),)
    return EnvironmentEvidence(
        "0.1.0", "6.165.1", "3.12.0", "controlled-platform", providers, dependencies
    )


def _reduction() -> ReductionEvidence:
    case_id = _case().case_id
    return ReductionEvidence(case_id, case_id, False, 0, 0, 0, 0, 0)


def _record(result: CellResult | None = None) -> FindingRecord:
    result = _result() if result is None else result
    fingerprint = result.fingerprint
    assert fingerprint is not None
    names = tuple(sorted((*REQUIRED_ARTIFACTS, OPTIONAL_INPUT)))
    artifacts = tuple(ArtifactDigest(name, "0" * 64, index) for index, name in enumerate(names))
    return FindingRecord(
        finding_id=finding_id_for(_case().case_id, fingerprint),
        case_id=_case().case_id,
        command="fuzz",
        writers=(EngineVersion("pyarrow", "1"),),
        readers=(EngineVersion("duckdb", "2"),),
        discovery=DiscoveryEvidence(25, 7, 8, EXAMPLE_BOUND_REACHED),
        environment=_environment(),
        reduction=_reduction(),
        fingerprint=fingerprint,
        replay_signature=ReplaySignature.from_fingerprint(fingerprint),
        result=result,
        input_parquet=True,
        artifacts=artifacts,
    )


def _matrix(result: CellResult | None = None) -> MatrixRecord:
    result = _result() if result is None else result
    fingerprint = result.fingerprint
    assert fingerprint is not None
    engines = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    return MatrixRecord(
        _case().case_id, engines[:1], engines[1:], fingerprint, (fingerprint,), (result,)
    )


def _imports(payload: bytes) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(payload.decode())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module)
    return names


def test_full_fingerprint_binds_kind_and_normalized_detail_while_replay_excludes_versions() -> None:
    original = _result(detail="expected   1,\n got 2")
    whitespace = _result(detail="expected 1, got 2")
    drifted = _result(writer_version="9", reader_version="8")
    changed_number = _result(detail="expected 1, got 3")
    changed_kind = _result(diagnostic_kind="ArrowInvalid")
    assert original.fingerprint == whitespace.fingerprint
    assert original.fingerprint != drifted.fingerprint
    assert original.fingerprint != changed_number.fingerprint
    assert original.fingerprint != changed_kind.fingerprint
    assert ReplaySignature.from_result(original) == ReplaySignature.from_result(drifted)
    assert ReplaySignature.from_result(original) != ReplaySignature.from_result(changed_number)
    assert ReplaySignature.from_result(original).related_shape() == (
        "pyarrow",
        "duckdb",
        "compare",
        Verdict.VALUE_MISMATCH,
        "$rows[0].value",
        "VALUE_MISMATCH",
    )


def test_finding_bytes_are_independently_canonical_and_additive_top_level_fields_decode() -> None:
    finding = _record()
    identity = json.dumps(
        {"case_id": _case().case_id, "fingerprint": finding.fingerprint.to_data()},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    assert finding.finding_id == hashlib.sha256(identity).hexdigest()
    expected = json.dumps(
        finding.to_data(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    assert finding.canonical_bytes() == expected
    assert FindingRecord.from_json(expected) == finding
    additive = finding.to_data()
    additive["additional_evidence"] = {"producer": "compatible-reader"}
    assert FindingRecord.from_data(additive) == finding


def test_finding_rejects_identity_signature_selection_and_inventory_conflicts() -> None:
    finding = _record()
    with pytest.raises(FindingValidationError):
        replace(finding, finding_id="0" * 64)
    with pytest.raises(FindingValidationError):
        replace(
            finding,
            replay_signature=replace(finding.replay_signature, diagnostic_kind="different"),
        )
    with pytest.raises(FindingValidationError):
        replace(finding, writers=(EngineVersion("duckdb", "2"),))
    with pytest.raises(FindingValidationError):
        replace(finding, artifacts=finding.artifacts[:-1])
    with pytest.raises(FindingValidationError):
        FindingRecord.from_json(b'{"format":"parquity.finding.v1","format":"duplicate"}')
    inventories = (
        (EngineVersion("pyarrow", "1"),),
        (*finding.environment.providers, EngineVersion("polars", "3")),
        (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "9")),
    )
    for providers in inventories:
        environment = replace(finding.environment, providers=providers)
        with pytest.raises(FindingValidationError):
            replace(finding, environment=environment)
        data = {**finding.to_data(), "environment": environment.to_data()}
        with pytest.raises(FindingValidationError):
            FindingRecord.from_json(json.dumps(data))
    shared_result = replace(finding.result, reader="pyarrow", reader_version="1")
    shared_fingerprint = shared_result.fingerprint
    assert shared_fingerprint is not None
    shared = replace(
        finding,
        finding_id=finding_id_for(finding.case_id, shared_fingerprint),
        readers=finding.writers,
        environment=replace(finding.environment, providers=finding.writers),
        fingerprint=shared_fingerprint,
        replay_signature=ReplaySignature.from_fingerprint(shared_fingerprint),
        result=shared_result,
    )
    assert FindingRecord.from_json(shared.canonical_bytes()) == shared
    with pytest.raises(FindingValidationError):
        replace(shared, readers=(EngineVersion("pyarrow", "9"),))
    conflict = {**shared.to_data(), "readers": [{"name": "pyarrow", "version": "9"}]}
    with pytest.raises(FindingValidationError):
        FindingRecord.from_json(json.dumps(conflict))


def test_reproduce_script_uses_current_python_module_execution_without_path_lookup() -> None:
    payload = render_reproduce()
    assert _imports(payload) == {"subprocess", "sys", "pathlib"}
    assert b"sys.executable" in payload
    assert b'"-m", "parquity", "replay"' in payload
    assert b'["parquity", "replay"' not in payload


@pytest.mark.parametrize(
    ("writer", "reader", "expected_imports"),
    (
        ("duckdb", "datafusion", {"duckdb", "datafusion"}),
        ("fastparquet", "pyarrow", {"fastparquet", "pandas", "pyarrow.parquet"}),
        ("pyarrow", "polars", {"pyarrow.parquet", "polars"}),
        ("pyarrow", "fastparquet", {"pyarrow.parquet", "fastparquet"}),
    ),
)
def test_upstream_script_is_provider_direct_and_target_only(
    writer: str,
    reader: str,
    expected_imports: set[str],
) -> None:
    result = replace(_result(), writer=writer, reader=reader, diagnostic_kind="VALUE_MISMATCH")
    payload = render_upstream_repro(_case(), result)
    ast.parse(payload.decode())
    imports = _imports(payload)
    assert "parquity" not in imports
    assert expected_imports <= imports
    assert b"WRITE_COMPLETED" in payload
    assert b"READ_COMPLETED" in payload


def test_report_progressively_discloses_case_problem_reproduction_and_exact_evidence() -> None:
    kind = "kind`\n# injected\n[link](https://invalid)|<tag>\n```"
    detail = "detail `code`\n## injected\n[detail](https://invalid)|<html>\n```"
    result = _result(diagnostic_kind=kind, detail=detail)
    report = render_finding_report(_record(result), _case(), _matrix(result)).decode()
    ordered = report_fragments(
        "## What happened;## Input Case;## Reproduce;## Complete writer-reader matrix;"
        "## What this evidence establishes;## Discovery and minimization;## Technical evidence"
    )
    positions = tuple(map(report.index, ordered))
    assert positions == tuple(sorted(positions))
    required = report_fragments(
        "| Step | Stage | Outcome |;| # | Column | Type | Nullable | Shape |;"
        "| Row | Column | Value |;| Expected from the Case | Observed from the reader |;"
        "| Writer output | Reader | Stage | Result | Location |;[`case.json`](case.json);"
        "[`matrix.json`](matrix.json);[`finding.json`](finding.json);python reproduce.py;"
        "python upstream_repro.py"
    )
    assert all(value in report for value in required)
    for forbidden in ("evaluator", "authorization", "owner seam", "gate"):
        assert forbidden not in report.lower()
    for hostile in (
        "\n# injected",
        "\n## injected",
        "[link](https://invalid)",
        "[detail](https://invalid)",
        "<tag>",
        "<html>",
        "|<",
        "\\n```",
    ):
        assert hostile not in report
    assert "<code>1</code>" in report and "<code>2</code>" in report


@pytest.mark.parametrize(
    "invalid",
    (
        lambda: DiscoveryEvidence(1, 0, 1, CHECK_COMPLETE),
        lambda: DiscoveryEvidence(1, 0, 1, "UNKNOWN"),
        lambda: DiscoveryEvidence(0, 0, 1, EXAMPLE_BOUND_REACHED),
        lambda: DiscoveryEvidence(1, -1, 1, EXAMPLE_BOUND_REACHED),
        lambda: DiscoveryEvidence(1, 0, 65, EXAMPLE_BOUND_REACHED),
        lambda: replace(_environment(), parquity_version=""),
        lambda: replace(_environment(), providers=(_environment().providers[0],) * 2),
        lambda: ReductionEvidence("bad", "0" * 64, False, 0, 0, 0, 0, 0),
        lambda: ReductionEvidence("0" * 64, "0" * 64, False, -1, 0, 0, 0, 0),
        lambda: ArtifactDigest("unknown", "0" * 64, 0),
        lambda: ArtifactDigest("REPORT.md", "bad", 0),
        lambda: ArtifactDigest("REPORT.md", "0" * 64, -1),
        lambda: ReplaySignature.from_result(
            replace(_result(), verdict=Verdict.PASS, difference=None)
        ),
        lambda: replace(_matrix(), selection_order=()),
        lambda: replace(_matrix(), writers=()),
        lambda: replace(_record(), command="bad"),
        lambda: replace(_record(), command="check"),
        lambda: replace(_record(), readers=()),
        lambda: replace(_record(), result=replace(_result(), detail="different")),
        lambda: replace(_record(), reduction=replace(_reduction(), minimized_case_id="0" * 64)),
        lambda: replace(_record(), input_parquet=False),
        lambda: FindingRecord.from_json(b"[]"),
        lambda: FindingRecord.from_json(b"{"),
        lambda: MatrixRecord.from_json(b"[]"),
        lambda: MatrixRecord.from_json(b"{"),
        lambda: MatrixRecord.from_data({**_matrix().to_data(), "results": []}),
        lambda: codec.required({}, "missing"),
        lambda: codec.require_exact_keys({"extra": 1}, set(), "value"),
        lambda: codec.mapping([], "value"),
        lambda: codec.mapping({1: "value"}, "value"),
        lambda: codec.sequence("value", "value"),
        lambda: codec.string(1, "value"),
        lambda: codec.integer(True, "value"),
        lambda: codec.boolean(1, "value"),
        lambda: fingerprint_from_data({**_matrix().target.to_data(), "verdict": "UNKNOWN"}),
        lambda: fingerprint_from_data({**_matrix().target.to_data(), "writer": ""}),
        lambda: fingerprint_from_data({**_matrix().target.to_data(), "operation": "write"}),
        lambda: fingerprint_from_data(
            {**_matrix().target.to_data(), "normalized_detail_sha256": "bad"}
        ),
    ),
)
def test_malformed_finding_evidence_is_rejected(invalid: Callable[[], object]) -> None:
    with pytest.raises(FindingValidationError):
        invalid()


def test_reduction_evidence_rejects_an_inconsistent_total() -> None:
    data = _reduction().to_data()
    counts = data["successful_reductions"]
    assert isinstance(counts, dict)
    counts["total"] = 1
    with pytest.raises(FindingValidationError):
        ReductionEvidence.from_data(data)


def test_upstream_script_renders_nested_types_and_rejects_unknown_providers() -> None:
    case = Case(
        (
            Field("items", TypeSpec(Kind.LIST, item=TypeSpec(Kind.STRING))),
            Field("fixed", TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=2)),
            Field("record", TypeSpec(Kind.STRUCT, fields=(Field("value", TypeSpec(Kind.INT64)),))),
        ),
        ((["x"], [True, False], {"value": 1}),),
    )
    payload = render_upstream_repro(case, _result()).decode()
    assert "pa.list_(" in payload
    assert "list_size=2" in payload
    assert "pa.struct([" in payload
    with pytest.raises(ValueError):
        render_upstream_repro(case, replace(_result(), writer="unknown"))
    with pytest.raises(ValueError):
        render_upstream_repro(case, replace(_result(), reader="unknown"))
