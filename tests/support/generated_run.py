from __future__ import annotations

from pathlib import Path

import pytest

from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.generation import evidence
from parquity.generation import reduce as reduction
from parquity.generation.search.records import (
    GeneratedOccurrence,
    OverflowObservation,
    SearchFinding,
)
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.profiles import WriterProfileIdentity
from parquity.runs import bundle
from parquity.runs import source as source_model
from parquity.runs.formats import v1 as model
from parquity.verdicts import CellResult, MatrixRun, Verdict

CASE = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))
ENGINES = tuple(map(EngineVersion, ("pyarrow", "duckdb", "polars"), ("1", "2", "3")))
CHECK = evidence.DiscoveryEvidence(None, None, None, evidence.CHECK_COMPLETE)
CAPPED = evidence.DiscoveryEvidence(10, 0, 3, evidence.SAVED_EVIDENCE_LIMIT_REACHED, 1, 7)
FAILURES = (
    CellResult(
        "pyarrow",
        "1",
        "duckdb",
        "2",
        "compare",
        Verdict.VALUE_MISMATCH,
        "$",
        "value mismatch",
        "VALUE_MISMATCH",
    ),
    CellResult("duckdb", "2", "pyarrow", "1", "compare", Verdict.SCHEMA_MISMATCH, "$", "schema"),
    CellResult(
        "polars", "3", "*", "*", "write", Verdict.WRITE_ERROR, "$", "failure", "ComputeError"
    ),
)


def pass_result(
    writer: EngineVersion,
    reader: EngineVersion,
    profile: WriterProfileIdentity | None = None,
) -> CellResult:
    engines = (writer.name, writer.version, reader.name, reader.version)
    return CellResult(*engines, "compare", Verdict.PASS, "$", "", writer_profile=profile)


def results(failures: tuple[CellResult, ...]) -> tuple[CellResult, ...]:
    cells = {(item.writer, item.reader): item for item in failures if item.operation != "write"}
    write_errors = {item.writer: item for item in failures if item.operation == "write"}
    values: list[CellResult] = []
    for writer in ENGINES:
        if writer.name in write_errors:
            values.append(write_errors[writer.name])
            continue
        values.extend(
            cells.get((writer.name, reader.name), pass_result(writer, reader)) for reader in ENGINES
        )
    return tuple(values)


def finding(result: CellResult, run: MatrixRun) -> SearchFinding:
    fingerprint = result.fingerprint or pytest.fail("failure fingerprint missing")
    counts = reduction.ReductionCounts()
    return SearchFinding(CASE, CASE, fingerprint, result, run, 0, False, counts)


def evaluate(case: Case, directory: Path) -> MatrixRun:
    directory.mkdir(parents=True)
    files = [(writer, directory / f"{writer}.parquet") for writer in ("pyarrow", "duckdb")]
    for writer, path in files:
        path.write_bytes(f"PAR1{writer}PAR1".encode())
    return MatrixRun(case.case_id, results(FAILURES), tuple(files), ENGINES, ENGINES)


def source(
    command: str = "check",
    stops: tuple[OverflowObservation, ...] = (),
    items: tuple[SearchFinding, ...] | None = None,
    version: str = "0.1.0",
) -> bundle.RunSource:
    discovery = CHECK if command == "check" else CAPPED
    run = MatrixRun(CASE.case_id, results(FAILURES), (), ENGINES, ENGINES)
    selected = tuple(finding(result, run) for result in FAILURES) if items is None else items
    environment = EnvironmentEvidence(
        version,
        "h",
        "3",
        "x",
        ENGINES,
        (DependencyVersion("pyarrow", "1"),),
    )
    return bundle.RunSource(command, selected, stops, ENGINES, ENGINES, discovery, environment)


REDUCED = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((7,),))


def sibling_source() -> source_model.RunV2Source:
    """A check run whose second finding was first seen while reducing the first.

    Its occurrence is bound to the REDUCED Case, which the caller never supplied — the shape that
    made the report count two affected inputs for a run with one evaluated input.
    """
    fingerprints = tuple(
        item.fingerprint or pytest.fail("failure fingerprint missing") for item in FAILURES
    )
    run = MatrixRun(REDUCED.case_id, results(FAILURES), (), ENGINES, ENGINES)
    counts = reduction.ReductionCounts(rows=1)

    # The last finding is the sibling: reduction produced REDUCED while minimizing the others, and
    # this failure was seen there first.
    findings = tuple(
        SearchFinding(
            *((REDUCED, REDUCED) if index == len(FAILURES) - 1 else (CASE, CASE)),
            fingerprints[index],
            FAILURES[index],
            run,
            0,
            False,
            counts,
        )
        for index in range(len(FAILURES))
    )
    occurrences = tuple(
        GeneratedOccurrence(
            REDUCED.case_id if index == len(FAILURES) - 1 else CASE.case_id,
            fingerprints[index],
            evidence.MINIMIZATION_OVERFLOW
            if index == len(FAILURES) - 1
            else evidence.DISCOVERY_OVERFLOW,
        )
        for index in range(len(FAILURES))
    )
    return source_model.RunV2Source(
        command="check",
        findings=findings,
        overflow=(),
        writers=ENGINES,
        readers=ENGINES,
        discovery=CHECK,
        environment=EnvironmentEvidence(
            "0.1.0", "h", "3", "x", ENGINES, (DependencyVersion("pyarrow", "1"),)
        ),
        occurrences=occurrences,
        evaluated_inputs=1,
        executed_checks=9,
    )


def published_run(
    root: Path,
    name: str = "run",
    run_source: bundle.RunSource | None = None,
) -> tuple[model.RunRecord, Path]:
    destination = root / name
    validated = bundle.publish_run(
        source() if run_source is None else run_source, destination, evaluate
    )
    value = validated or pytest.fail("run publication returned no evidence")
    assert value.directory == destination and all(
        child.directory.is_dir() for child in value.children
    )
    return value.run, destination


__all__ = [
    "CAPPED",
    "CASE",
    "CHECK",
    "ENGINES",
    "FAILURES",
    "REDUCED",
    "evaluate",
    "finding",
    "pass_result",
    "published_run",
    "results",
    "sibling_source",
    "source",
]
