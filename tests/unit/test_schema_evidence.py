from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.findings.bundle import BundleValidationError, validate_bundle
from parquity.findings.model import FindingRecord, FindingValidationError, finding_id_for
from parquity.generation.evidence import (
    CHECK_COMPLETE,
    EXAMPLE_BOUND_REACHED,
    DiscoveryEvidence,
    GenerationEvidence,
)
from parquity.generation.reduce import ReductionCounts
from parquity.generation.search.records import SearchFinding
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs.bundle import (
    RunBundleValidationError,
    RunSource,
    publish_run,
    validate_run,
)
from parquity.runs.formats.v1 import RunFindingIndex, RunRecord, calculate_run_id
from parquity.verdicts import CellResult, MatrixRun, Verdict

_WRITERS = (EngineVersion("pyarrow", "1"),)
_READERS = (EngineVersion("duckdb", "1"),)


def _case(name: str = "value", value: int = 1) -> Case:
    return Case((Field(name, TypeSpec(Kind.INT32), nullable=False),), ((value,),))


def _result(case: Case) -> CellResult:
    name = case.fields[0].name
    return CellResult(
        "pyarrow",
        "1",
        "*",
        "*",
        "write",
        Verdict.WRITE_ERROR,
        "$",
        f"controlled {name} {case.rows[0][0]}",
        "Controlled",
    )


def _evaluate(case: Case, directory: Path) -> MatrixRun:
    del directory
    return MatrixRun(case.case_id, (_result(case),), (), _WRITERS, _READERS)


def _finding(case: Case, *, discovered: Case | None = None) -> SearchFinding:
    result = _result(case)
    fingerprint = result.fingerprint
    assert fingerprint is not None
    original = case if discovered is None else discovered
    run = MatrixRun(case.case_id, (result,), (), _WRITERS, _READERS)
    return SearchFinding(original, case, fingerprint, result, run, 4, False, ReductionCounts())


def _source(cases: tuple[Case, ...], generation: GenerationEvidence | None = None) -> RunSource:
    return RunSource(
        command="fuzz",
        findings=tuple(_finding(case) for case in cases),
        overflow=(),
        writers=_WRITERS,
        readers=_READERS,
        discovery=DiscoveryEvidence(
            4,
            1,
            8,
            EXAMPLE_BOUND_REACHED,
            evaluated_cases=len(cases),
            evaluated_cells=len(cases),
        ),
        environment=EnvironmentEvidence(
            "0.1.0",
            "6.165.1",
            "3.12",
            "controlled",
            (*_WRITERS, *_READERS),
            (DependencyVersion("pyarrow", "1"),),
        ),
        generation=generation,
    )


def _publish(
    root: Path,
    name: str,
    cases: tuple[Case, ...],
    generation: GenerationEvidence | None = None,
) -> Path:
    destination = root / name
    assert publish_run(_source(cases, generation), destination, _evaluate) is not None
    return destination


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _rewrite_child(
    run_directory: Path,
    child_name: str,
    generation: Mapping[str, object] | None,
    *,
    reseal_parent: bool,
) -> None:
    manifest = run_directory / "findings" / child_name / "finding.json"
    data = cast(dict[str, object], json.loads(manifest.read_bytes()))
    if generation is None:
        data.pop("generation", None)
    else:
        data["generation"] = generation
    payload = _canonical(data)
    manifest.write_bytes(payload)
    if reseal_parent:
        _reseal_parent(run_directory, child_name, payload)


def _reseal_parent(run_directory: Path, child_name: str, payload: bytes) -> None:
    path = run_directory / "run.json"
    run = RunRecord.from_json(path.read_bytes())
    indexes = tuple(
        _updated_index(item, payload) if item.finding_id == child_name else item
        for item in run.findings
    )
    run_id = calculate_run_id(
        run.command,
        run.status,
        run.writers,
        run.readers,
        run.discovery,
        run.environment,
        indexes,
        run.overflow,
    )
    path.write_bytes(replace(run, findings=indexes, run_id=run_id).canonical_bytes())


def _updated_index(index: RunFindingIndex, payload: bytes) -> RunFindingIndex:
    return replace(
        index,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
    )


def test_generation_evidence_has_one_exact_shape_and_check_rejects_it(tmp_path: Path) -> None:
    case = _case()
    identity = Case(case.fields, ()).case_id
    generation = GenerationEvidence("schema", identity)
    assert generation.to_data() == {"profile": "schema", "schema_case_id": identity}
    assert GenerationEvidence.from_data(generation.to_data()) == generation
    invalid = (
        {"profile": "generic", "schema_case_id": identity},
        {"profile": "schema", "schema_case_id": "bad"},
        {"profile": "schema", "schema_case_id": identity, "extra": True},
    )
    for data in invalid:
        with pytest.raises(FindingValidationError):
            GenerationEvidence.from_data(data)
    directory = _publish(tmp_path, "schema", (case,), generation)
    finding = validate_run(directory).children[0].finding
    check = DiscoveryEvidence(None, None, None, CHECK_COMPLETE)
    with pytest.raises(FindingValidationError):
        replace(finding, command="check", discovery=check)
    for category in ("fields", "nullability"):
        reduction = replace(finding.reduction, **{category: 1})
        with pytest.raises(FindingValidationError):
            replace(finding, reduction=reduction)
    malformed = finding.to_data()
    malformed["generation"] = None
    with pytest.raises(FindingValidationError):
        FindingRecord.from_data(malformed)


def test_schema_publication_binds_children_and_preserves_run_shape(
    tmp_path: Path,
) -> None:
    cases = (_case(value=1), _case(value=2))
    schema_id = Case(cases[0].fields, ()).case_id
    generation = GenerationEvidence("schema", schema_id)
    directory = _publish(tmp_path, "run", cases, generation)
    validated = validate_run(directory)
    root = cast(dict[str, object], json.loads((directory / "run.json").read_bytes()))
    assert set(root) == {
        "format",
        "run_id",
        "command",
        "status",
        "writers",
        "readers",
        "discovery",
        "environment",
        "findings",
        "overflow",
        "report",
    }
    assert {child.finding.generation for child in validated.children} == {generation}
    for child in validated.children:
        assert child.finding.finding_id == finding_id_for(
            child.finding.case_id, child.finding.fingerprint
        )
        assert generation.binds(child.case, child.discovered_case)
    extracted = tmp_path / "extracted"
    shutil.copytree(validated.children[0].directory, extracted)
    assert validate_bundle(extracted).finding.generation == generation


def test_standalone_binding_checks_final_and_retained_discovered_cases(tmp_path: Path) -> None:
    final = _case("value", 1)
    discovered = _case("other", 1)
    generation = GenerationEvidence("schema", Case(final.fields, ()).case_id)
    source = _source((final,), generation)
    source = replace(source, findings=(_finding(final, discovered=discovered),))
    with pytest.raises(BundleValidationError):
        publish_run(source, tmp_path / "foreign-discovered", _evaluate)


def test_aggregate_rejects_partial_mixed_foreign_and_incorrectly_resealed_evidence(
    tmp_path: Path,
) -> None:
    same_schema = (_case(value=1), _case(value=2))
    schema_id = Case(same_schema[0].fields, ()).case_id
    evidence = {"profile": "schema", "schema_case_id": schema_id}

    partial = _publish(tmp_path, "partial", same_schema)
    child_names = tuple(item.name for item in (partial / "findings").iterdir())
    _rewrite_child(partial, child_names[0], evidence, reseal_parent=True)
    with pytest.raises(RunBundleValidationError):
        validate_run(partial)

    unsealed = _publish(tmp_path, "unsealed", same_schema)
    child = next((unsealed / "findings").iterdir()).name
    _rewrite_child(unsealed, child, evidence, reseal_parent=False)
    with pytest.raises(RunBundleValidationError):
        validate_run(unsealed)

    mixed_cases = (_case("alpha", 1), _case("beta", 1))
    mixed = _publish(tmp_path, "mixed", mixed_cases)
    for child in validate_run(mixed).children:
        generation = {
            "profile": "schema",
            "schema_case_id": Case(child.case.fields, ()).case_id,
        }
        _rewrite_child(mixed, child.directory.name, generation, reseal_parent=True)
    with pytest.raises(RunBundleValidationError):
        validate_run(mixed)

    foreign = _publish(tmp_path, "foreign", same_schema)
    child = next((foreign / "findings").iterdir()).name
    wrong = {"profile": "schema", "schema_case_id": "0" * 64}
    _rewrite_child(foreign, child, wrong, reseal_parent=True)
    with pytest.raises(RunBundleValidationError):
        validate_run(foreign)


def test_all_absent_generic_children_remain_valid(tmp_path: Path) -> None:
    directory = _publish(tmp_path, "generic", (_case(value=1), _case(value=2)))
    validated = validate_run(directory)
    assert all(child.finding.generation is None for child in validated.children)
