from __future__ import annotations

import json
import os
from hashlib import sha256
from importlib import import_module, metadata
from pathlib import Path
from shlex import join as shell_join
from typing import cast

from pytest import CaptureFixture, MonkeyPatch

import parquity.cli as cli
from parquity.engines import EngineSelection
from parquity.evidence import DifferenceEvidence, EngineVersion
from parquity.generation.search.identity import finding_key
from parquity.model import Case
from parquity.runs.bundle import ValidatedRunV2, validate_run
from parquity.verdicts import CellResult, MatrixRun, Verdict
from tests.support.cli_output import captured_payload as _payload
from tests.support.cli_output import run_python_script
from tests.support.generated_cli import patch_evaluator as _patch_evaluator
from tests.support.generated_cli import selection_versions as _versions
from tests.support.generated_cli import write_case as _write_case


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


def _inventory(directory: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        (path.relative_to(directory).as_posix(), sha256(path.read_bytes()).hexdigest())
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    )


def _assert_v2_partition(run: ValidatedRunV2) -> None:
    saved = {finding_key(item.fingerprint) for item in run.run.saved_evidence}
    manifest_only = {finding_key(item.fingerprint) for item in run.run.manifest_only_evidence}
    occurrences = {item.key for item in run.run.occurrences}
    assert saved.isdisjoint(manifest_only)
    assert saved | manifest_only == occurrences


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
    assert cli.main(arguments := ["check", str(case_path), "--out", str(destination)]) == 1
    published, stderr = _payload(capsys)
    assert stderr == ""
    assert published["status"] == "RUN_PUBLISHED"
    assert published["finding_count"] == 3
    summaries = cast(list[dict[str, object]], published["findings"])
    assert [item["writer"] for item in summaries] == ["pyarrow", "duckdb", "polars"]
    validated = validate_run(destination)
    assert isinstance(validated, ValidatedRunV2)
    _assert_v2_partition(validated)
    report = (destination / "REPORT.md").read_text(encoding="utf-8")
    assert (
        "3 of 7 engine paths failed on the supplied table. A reproducer was saved for each."
        in report
        and report.count("```console") == 1
        and f"```console\n{shell_join(('parquity', *arguments))}\n```" in report
        and all(value not in report for value in ("CASE_FILE", "FILE_OR_DIR", "OUTPUT_DIR"))
    )
    assert "**Writers:**" in report and "**Readers:**" in report
    assert "| Writer → reader | Failure | Table / location | Reproduce |" in report
    assert "1 column · int32" in report
    assert all(child.case.case_id[:12] not in report for child in validated.children)
    failure_rows = report.split("## Failures", 1)[1].split("## Run details", 1)[0]
    assert sum(line.startswith("| ") for line in failure_rows.splitlines()) - 1 == 3
    assert "polars (write)" in failure_rows and "[open](" in failure_rows
    assert all((child.directory / "REPORT.md").read_bytes() for child in validated.children)
    child_report = validated.children[0].directory.joinpath("REPORT.md").read_text(encoding="utf-8")
    assert child_report.startswith("# pyarrow → pyarrow · compare · VALUE\\_MISMATCH")
    assert "**Table provenance:** Supplied table; no Hypothesis shrink;" in child_report
    assert "canonical table" in child_report and "canonical Input" not in child_report
    assert "## Table" in child_report
    assert "### Parquity replay" in child_report
    assert "### Provider-only reproduction" in child_report
    assert "Exit 1 means reproduced; exit 0 means not reproduced" in child_report
    assert "- **Machine record:** [finding.json](finding.json)" in child_report
    for hidden in (
        "Finding ID",
        "Normalized detail SHA-256",
        "Discovered Input",
        "Minimized Input",
        "Successful reductions",
        "Occurrence",
        "Saved replay targets",
        "Saved target replay",
        "Evidence basis",
    ):
        assert hidden not in child_report
    assert len(tuple((destination / "findings").iterdir())) == 3
    before_replay = _inventory(destination)
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
    assert _inventory(destination) == before_replay


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
    completed = run_python_script(child / "reproduce.py", working, environment=environment)
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
    arguments = ["fuzz", "--examples", "4", "--seed", "23", "--out", str(destination)]
    exit_code = cli.main(arguments)
    payload, stderr = _payload(capsys)
    assert exit_code == 1
    assert stderr == ""
    assert payload["status"] == "RUN_PUBLISHED"
    run = cast(dict[str, object], json.loads((destination / "run.json").read_bytes()))
    assert run["format"] == "parquity.run.v2"
    discovery = cast(dict[str, object], run["discovery"])
    environment = cast(dict[str, object], run["environment"])
    assert discovery == {
        "examples": 4,
        "seed": 23,
        "max_saved": 8,
        "stop_reason": "EXAMPLE_BOUND_REACHED",
    }
    assert (run["evaluated_inputs"], run["executed_checks"]) == (4, 28)
    assert payload["discovery"] == {
        "examples": 4,
        "seed": 23,
        "max_findings": 8,
        "stop_reason": "EXAMPLE_BOUND_REACHED",
        "evaluated_cases": 4,
        "evaluated_cells": 28,
    }
    validated = validate_run(destination)
    assert isinstance(validated, ValidatedRunV2)
    _assert_v2_partition(validated)
    report = (destination / "REPORT.md").read_text(encoding="utf-8")
    expected_command = shell_join(("parquity", *arguments))
    assert report.count("```console") == 1
    assert f"```console\n{expected_command}\n```" in report
    assert all(value not in report for value in ("CASE_FILE", "FILE_OR_DIR", "OUTPUT_DIR"))
    assert (
        "Parquity tested 4 generated tables and found 3 distinct failures. "
        "A reproducer was saved for each." in report
    )
    assert "| Writer → reader | Failure | Example table / location | Reproduce |" in report
    assert "&lt;" not in report and "&gt;" not in report
    failure_rows = report.split("## Failures", 1)[1].split("## Run details", 1)[0]
    assert sum(line.startswith("| ") for line in failure_rows.splitlines()) - 1 == 3
    assert "Seen on 4 generated tables" in failure_rows
    child_report = validated.children[0].directory.joinpath("REPORT.md").read_text(encoding="utf-8")
    assert "**Table provenance:** Generated table;" in child_report
    assert "Hypothesis shrink" in child_report
    assert (
        "**Repeated:** Seen on 4 generated tables; this reproducer uses one of them" in child_report
    )
    empty_reports = tuple(
        child.directory.joinpath("REPORT.md").read_text(encoding="utf-8")
        for child in validated.children
        if not child.case.rows
    )
    assert empty_reports
    assert all("### Data\n\n_No rows._" in value for value in empty_reports)
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
    invalid.write_text('{"format":"different"}', encoding="utf-8")
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
    replay_inputs = (
        (tmp_path / "missing-evidence", "does not exist"),
        (tmp_path / "evidence-file", "must be an evidence directory"),
        (tmp_path / "incomplete-evidence", "contains no run.json, scan.json, or finding.json"),
        (tmp_path / "conflicting-evidence", "conflicting run.json and scan.json"),
        (tmp_path / "malformed-finding", "finding.json is malformed"),
        (tmp_path / "unreadable-finding", "finding.json could not be read"),
        (tmp_path / "unsupported-finding", "finding format is not supported"),
    )
    replay_inputs[1][0].write_text("not a directory", encoding="utf-8")
    replay_inputs[2][0].mkdir()
    for index, payloads in ((3, ("run.json", "scan.json")), (4, ("finding.json",))):
        replay_inputs[index][0].mkdir()
        for name in payloads:
            (replay_inputs[index][0] / name).write_text("{", encoding="utf-8")
    replay_inputs[5][0].mkdir()
    (replay_inputs[5][0] / "finding.json").mkdir()
    replay_inputs[6][0].mkdir()
    (replay_inputs[6][0] / "finding.json").write_text('{"format":"unknown"}', encoding="utf-8")
    main_module = import_module("parquity.cli.main")

    def unexpected_selection(*_: object) -> object:
        raise AssertionError("invalid replay target reached engine resolution")

    with monkeypatch.context() as guard:
        guard.setattr(main_module, "resolve_engine_selection", unexpected_selection)
        for replay_input, expected in replay_inputs:
            assert cli.main(["replay", str(replay_input)]) == 2
            rejected, rejected_stderr = _payload(capsys)
            rejected_error = cast(dict[str, object], rejected["error"])
            detail = cast(str, rejected_error["detail"])
            assert rejected_error["kind"] == "INVALID_BUNDLE"
            assert expected in detail and detail in rejected_stderr
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    destination = tmp_path / "run"
    _patch_evaluator(monkeypatch, _failure_evaluator)
    assert cli.main(["check", str(case_path), "--out", str(destination)]) == 1
    _payload(capsys)
    child = next((destination / "findings").iterdir())
    (child / "REPORT.md").write_text("tampered", encoding="utf-8")
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
