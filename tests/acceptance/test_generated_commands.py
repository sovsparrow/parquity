from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from importlib import import_module, metadata
from pathlib import Path
from typing import cast

from pytest import CaptureFixture, MonkeyPatch

import parquity.cli as cli
from parquity.engines import EngineSelection
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.result_evidence import DifferenceEvidence
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict


def _case() -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))


def _write_case(path: Path) -> Case:
    case = _case()
    path.write_bytes(case.canonical_bytes())
    return case


def _run_generated_script(
    script: Path, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - absolute interpreter executes generated script.
        [sys.executable, str(script)],
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _versions(
    selection: EngineSelection,
) -> tuple[tuple[EngineVersion, ...], tuple[EngineVersion, ...]]:
    writers = tuple(
        EngineVersion(engine.identity.name, engine.identity.version) for engine in selection.writers
    )
    readers = tuple(
        EngineVersion(engine.identity.name, engine.identity.version) for engine in selection.readers
    )
    return writers, readers


def _cell(
    writer: EngineVersion, reader: EngineVersion, verdict: Verdict, path: str, detail: str
) -> CellResult:
    difference = None if verdict is Verdict.PASS else DifferenceEvidence("expected", "observed")
    return CellResult(
        writer.name,
        writer.version,
        reader.name,
        reader.version,
        "compare",
        verdict,
        path,
        detail,
        difference=difference,
    )


def _write_failure(writer: EngineVersion) -> CellResult:
    return CellResult(
        writer.name,
        writer.version,
        "*",
        "*",
        "write",
        Verdict.WRITE_ERROR,
        "$",
        "third controlled failure",
        "ControlledWriteError",
    )


def _three_failures(selection: EngineSelection) -> tuple[CellResult, ...]:
    writers, readers = _versions(selection)
    if not writers or not readers:
        raise ValueError("test selection requires at least one writer and reader")
    first_writer = next(iter(writers))
    first_reader = next(iter(readers))
    value = Verdict.VALUE_MISMATCH
    if len(writers) < 3:
        return (_cell(first_writer, first_reader, value, "$rows[0].value", "controlled mismatch"),)
    return (
        _cell(first_writer, first_reader, value, "$rows[0].value", "first controlled mismatch"),
        _cell(
            writers[1],
            first_reader,
            Verdict.SCHEMA_MISMATCH,
            "$schema.value",
            "second controlled mismatch",
        ),
        _write_failure(writers[2]),
    )


def _complete(
    selection: EngineSelection, failures: tuple[CellResult, ...]
) -> tuple[CellResult, ...]:
    writers, readers = _versions(selection)
    cells = {(item.writer, item.reader): item for item in failures if item.operation != "write"}
    write_errors = {item.writer: item for item in failures if item.operation == "write"}
    results: list[CellResult] = []
    for writer in writers:
        if writer.name in write_errors:
            results.append(write_errors[writer.name])
            continue
        results.extend(
            cells.get((writer.name, reader.name), _cell(writer, reader, Verdict.PASS, "$", "match"))
            for reader in readers
        )
    return tuple(results)


def _failure_evaluator(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    directory.mkdir(parents=True)
    failures = _three_failures(selection)
    failed_writers = {item.writer for item in failures if item.operation == "write"}
    files: list[tuple[str, Path]] = []
    for engine in selection.writers:
        if engine.identity.name in failed_writers:
            continue
        path = directory / f"{engine.identity.name}.parquet"
        path.write_bytes(f"PAR1{engine.identity.name}PAR1".encode())
        files.append((engine.identity.name, path))
    writers, readers = _versions(selection)
    return MatrixRun(case.case_id, _complete(selection, failures), tuple(files), writers, readers)


def _pass_evaluator(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    del directory
    writers, readers = _versions(selection)
    return MatrixRun(case.case_id, _complete(selection, ()), (), writers, readers)


def _payload(captured: CaptureFixture[str]) -> tuple[dict[str, object], str]:
    streams = captured.readouterr()
    payload = cast(dict[str, object], json.loads(streams.out))
    assert payload["format"] == "parquity.cli.v1"
    return payload, streams.err


def _patch_evaluator(
    monkeypatch: MonkeyPatch,
    evaluator: Callable[[Case, Path, EngineSelection], MatrixRun],
) -> None:
    workflow = import_module("parquity.generation.workflow")
    monkeypatch.setattr(workflow, "evaluate_selected_case", evaluator)


def test_check_no_finding(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    case_path = tmp_path / "case.json"
    case = _write_case(case_path)
    destination = tmp_path / "no-finding"
    _patch_evaluator(monkeypatch, _pass_evaluator)
    exit_code = cli.main(["check", str(case_path), "--out", str(destination)])
    payload, stderr = _payload(capsys)
    assert exit_code == 0
    assert stderr == ""
    assert payload["status"] == "NO_FINDING"
    assert payload["case_id"] == case.case_id
    assert payload["writers"] == ["pyarrow", "duckdb", "polars"]
    assert not destination.exists()


def test_check_and_replay(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    destination = tmp_path / "run"
    _patch_evaluator(monkeypatch, _failure_evaluator)
    assert cli.main(["check", str(case_path), "--out", str(destination)]) == 1
    published, stderr = _payload(capsys)
    assert stderr == ""
    assert published["status"] == "RUN_PUBLISHED"
    assert published["finding_count"] == 3
    assert len(tuple((destination / "findings").iterdir())) == 3
    assert cli.main(["replay", str(destination)]) == 1
    exact, stderr = _payload(capsys)
    assert stderr == ""
    assert exact["status"] == "REPRODUCED"
    assert exact["run_id"] == published["run_id"]
    assert (exact["exact"], exact["related"], exact["absent"]) == (3, 0, 0)
    child = next((destination / "findings").iterdir())
    assert cli.main(["replay", str(child)]) == 1
    child_payload, stderr = _payload(capsys)
    assert child_payload["status"] == "REPRODUCED"
    assert child_payload["finding_id"] == child.name
    assert stderr == ""

    def related(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
        run = _failure_evaluator(case, directory, selection)
        changed = tuple(
            CellResult(
                result.writer,
                result.writer_version,
                result.reader,
                result.reader_version,
                result.operation,
                result.verdict,
                result.schema_path,
                f"{result.detail} changed",
                result.diagnostic_kind,
            )
            for result in run.results
        )
        return MatrixRun(run.case_id, changed, run.files, run.writers, run.readers)

    _patch_evaluator(monkeypatch, related)
    assert cli.main(["replay", str(destination)]) == 0
    related_payload, _ = _payload(capsys)
    assert (related_payload["exact"], related_payload["related"], related_payload["absent"]) == (
        0,
        3,
        0,
    )
    _patch_evaluator(monkeypatch, _pass_evaluator)
    assert cli.main(["replay", str(destination)]) == 0
    absent, _ = _payload(capsys)
    assert (absent["exact"], absent["related"], absent["absent"]) == (0, 0, 3)


def test_extracted_reproduce(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    destination = tmp_path / "run"
    _patch_evaluator(monkeypatch, _failure_evaluator)
    assert cli.main(["check", str(case_path), "--out", str(destination)]) == 1
    _payload(capsys)
    child = next((destination / "findings").iterdir())
    working = tmp_path / "external"
    working.mkdir()
    environment = os.environ.copy()
    environment["PATH"] = ""
    completed = _run_generated_script(child / "reproduce.py", working, environment)
    assert completed.returncode == 0
    assert cast(dict[str, object], json.loads(completed.stdout))["status"] in (
        "RELATED_FAILURE",
        "NOT_REPRODUCED",
    )
    assert completed.stderr == ""


def test_fuzz_evidence(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    destination = tmp_path / "fuzz-run"
    _patch_evaluator(monkeypatch, _failure_evaluator)
    exit_code = cli.main(["fuzz", "--examples", "4", "--seed", "23", "--out", str(destination)])
    payload, stderr = _payload(capsys)
    assert exit_code == 1
    assert stderr == ""
    assert payload["status"] == "RUN_PUBLISHED"
    run = cast(dict[str, object], json.loads((destination / "run.json").read_bytes()))
    discovery = cast(dict[str, object], run["discovery"])
    environment = cast(dict[str, object], run["environment"])
    assert discovery == {
        "examples": 4,
        "seed": 23,
        "max_findings": 8,
        "stop_reason": "EXAMPLE_BOUND_REACHED",
        "evaluated_cases": 4,
        "evaluated_cells": 28,
    }
    assert payload["discovery"] == discovery
    finding_summaries = cast(list[dict[str, object]], payload["findings"])
    assert len(finding_summaries) == payload["finding_count"]
    expected_keys = {"finding_id", "case_id", "writer", "reader", "verdict", "detail"}
    assert all(expected_keys <= item.keys() for item in finding_summaries)
    assert environment["parquity_version"] == metadata.version("parquity")
    assert environment["hypothesis_version"] == metadata.version("hypothesis")
    assert environment["python_version"]
    assert environment["platform"]


def test_cli_failure_exits(
    monkeypatch: MonkeyPatch, capsys: CaptureFixture[str], tmp_path: Path
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"format":"different"}')
    assert cli.main(["check", str(invalid), "--out", str(tmp_path / "invalid-run")]) == 2
    invalid_payload, invalid_stderr = _payload(capsys)
    invalid_error = cast(dict[str, object], invalid_payload["error"])
    assert invalid_error["kind"] == "INVALID_CASE"
    assert "case fields" in cast(str, invalid_error["detail"])
    assert cast(str, invalid_error["detail"]) in invalid_stderr

    missing = tmp_path / "missing-case.json"
    assert cli.main(["check", str(missing), "--out", str(tmp_path / "missing-run")]) == 2
    missing_payload, missing_stderr = _payload(capsys)
    missing_error = cast(dict[str, object], missing_payload["error"])
    assert missing_error["kind"] == "CASE_UNREADABLE"
    assert missing.name in cast(str, missing_error["detail"])
    assert cast(str, missing_error["detail"]) in missing_stderr

    case_path = tmp_path / "case.json"
    _write_case(case_path)
    destination = tmp_path / "run"
    _patch_evaluator(monkeypatch, _failure_evaluator)
    assert cli.main(["check", str(case_path), "--out", str(destination)]) == 1
    _payload(capsys)
    child = next((destination / "findings").iterdir())
    (child / "REPORT.md").write_text("tampered")
    assert cli.main(["replay", str(destination)]) == 2
    tampered, _ = _payload(capsys)
    assert cast(dict[str, object], tampered["error"])["kind"] == "INVALID_BUNDLE"

    def fail(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
        del case, directory, selection
        raise RuntimeError("private detail")

    _patch_evaluator(monkeypatch, fail)
    assert cli.main(["check", str(case_path), "--out", str(tmp_path / "failed")]) == 3
    failed, stderr = _payload(capsys)
    assert cast(dict[str, object], failed["error"]) == {"kind": "RuntimeError"}
    assert "private detail" not in stderr
