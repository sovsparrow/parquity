from __future__ import annotations

import json
import os
import shutil
from importlib import import_module
from pathlib import Path
from shlex import join as shell_join
from typing import Protocol, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import parquity.cli as cli
from parquity.reporting.markdown import render_run_report
from parquity.scans.bundle import validate_run
from parquity.scans.report import build_run_report_view
from tests.support.cli_output import captured_payload as _payload
from tests.support.cli_output import run_json_script


class _ParquetWriter(Protocol):
    def write_table(self, table: pa.Table, where: Path) -> None: ...


_PQ = cast(_ParquetWriter, cast(object, pq))


@pytest.mark.parametrize(
    "arguments",
    (
        ["scan"],
        ["scan", "input"],
        ["scan", "input", "--out", "unused", "--timeout", "0"],
        ["scan", "input", "--out", "unused", "--timeout", "301"],
        ["scan", "input", "--out", "unused", "--timeout", "bad"],
        ["scan", "input", "--out", "unused", "--max-saved", "0"],
        ["scan", "input", "--out", "unused", "--max-saved", "65"],
        ["scan", "input", "--out", "unused", "--max-findings", "1"],
    ),
)
def test_scan_usage_and_bounds_are_exit_two(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(arguments) == 2
    payload, stderr = _payload(capsys)
    assert payload["status"] == "CONFIGURATION_ERROR"
    assert cast(dict[str, object], payload["error"])["kind"] == "USAGE_ERROR"
    assert stderr.startswith("parquity:")


@pytest.mark.parametrize(
    ("option", "value"),
    (("--timeout", "1"), ("--timeout", "300"), ("--max-saved", "1"), ("--max-saved", "64")),
)
def test_scan_valid_bound_endpoints_reach_input_validation(
    option: str,
    value: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "unused"
    arguments = [
        "scan",
        str(tmp_path / "missing.parquet"),
        "--out",
        str(destination),
        option,
        value,
    ]
    assert cli.main(arguments) == 2
    payload, _ = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "INVALID_INPUT"
    assert not destination.exists()


def test_scan_default_core_readers_agree_without_publishing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "arbitrary-name"
    _PQ.write_table(pa.table({"value": [1, 2, None]}), source)
    absent_parent = tmp_path / "absent" / "nested"
    destination = absent_parent / "must-not-exist"
    assert cli.main(["scan", str(source), "--out", str(destination)]) == 0
    payload, stderr = _payload(capsys)
    assert stderr == ""
    assert payload["status"] == "AGREEMENT"
    assert payload["readers"] == ["pyarrow", "duckdb", "polars"]
    assert (payload["discovered_files"], payload["evaluated_files"]) == (1, 1)
    assert payload["visited_entries"] == 1
    assert "output" not in payload
    assert not destination.exists()
    assert not absent_parent.exists() and not absent_parent.parent.exists()


def test_scan_saved_limit_publishes_scripts_and_replays(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "scan source"
    source.mkdir()
    for name in ("a.parquet", "b.parquet"):
        (source / name).write_bytes(b"not parquet")
    destination = tmp_path / "scan run"
    arguments = [
        "scan",
        str(source),
        "--engines",
        "pyarrow,duckdb,polars",
        "--max-saved",
        "1",
        "--out",
        str(destination),
    ]
    assert cli.main(arguments) == 1
    published, stderr = _payload(capsys)
    assert stderr == ""
    assert published["status"] == "RUN_PUBLISHED"
    assert published["run_status"] == "FINDING_CAP_REACHED"
    assert (published["finding_count"], published["overflow_count"]) == (1, 1)
    assert published["visited_entries"] == 3
    run = validate_run(destination)
    assert run.record.format_name == "parquity.scan-run.v2"
    assert run.record.environment is not None
    assert all(
        child.record.format_name == "parquity.scan-finding.v2"
        and child.record.environment == run.record.environment
        for child in run.children
    )
    view = build_run_report_view(run)
    assert published["finding_count"] == len(run.children)
    assert published["report_finding_count"] == view.finding_count
    assert published["occurrence_count"] == view.occurrence_count
    assert published["evidence_bundle_count"] == view.evidence_bundle_count
    assert published["affected_input_count"] == view.affected_input_count
    child = run.children[0].directory
    _assert_published_scan_reports(destination, child)
    report = (destination / "REPORT.md").read_text()
    assert report.count("```console") == 1
    assert f"```console\n{shell_join(('parquity', *arguments))}\n```" in report
    assert all(value not in report for value in ("CASE_FILE", "FILE_OR_DIR", "OUTPUT_DIR"))
    assert b"```console" not in render_run_report(view)
    assert cast(list[str], run.record.data["overflow"]) == ["b.parquet"]
    assert cast(dict[str, object], run.record.data["limits"])["max_visited_entries"] == 4096
    assert str(tmp_path) not in (destination / "scan.json").read_text()
    for relative in ("finding.json", "REPORT.md", "reproduce.py", "upstream_repro.py"):
        assert str(tmp_path) not in (child / relative).read_text()
    standalone = tmp_path / "standalone"
    shutil.copytree(child, standalone)
    assert cli.main(["replay", str(standalone)]) == 1
    replayed, replay_stderr = _payload(capsys)
    assert replay_stderr == ""
    assert replayed["status"] == "REPRODUCED"
    result = cast(list[dict[str, object]], replayed["results"])[0]
    assert cast(dict[str, object], result["package_version"])["drift"] is False
    assert cast(list[dict[str, object]], result["version_evidence"])[0]["drift"] is False
    occurrence_result = cast(list[dict[str, object]], result["occurrence_results"])[0]
    assert occurrence_result["classification"] == "REPRODUCED"
    assert result["new_observations"] == []

    assert cli.main(["replay", str(destination)]) == 1
    aggregate, _ = _payload(capsys)
    assert aggregate["status"] == "REPRODUCED"
    _assert_standalone_scan_scripts(standalone, tmp_path)

    _assert_scan_rejects_noncanonical_manifests(standalone, destination, monkeypatch, capsys)

    exact_source = tmp_path / "exact-cap.parquet"
    exact_source.write_bytes(b"not parquet")
    exact_destination = tmp_path / "exact-cap-run"
    exact_arguments = list(arguments)
    exact_arguments[1] = str(exact_source)
    exact_arguments[-1] = str(exact_destination)
    assert cli.main(exact_arguments) == 1
    exact, _ = _payload(capsys)
    assert exact["overflow_count"] == 0
    assert exact["run_status"] == "FINDINGS_FOUND"


def _assert_published_scan_reports(destination: Path, child: Path) -> None:
    report = (destination / "REPORT.md").read_text()
    assert (
        "Parquity scanned 1 file and found 3 distinct failures. It stopped after saving "
        "1 file for reproduction; 1 more file was not scanned." in report
    )
    assert "**Readers:**" in report and "**Writers:**" not in report
    assert "**Python:**" in report and "**Platform:**" in report
    assert "| Reader(s) | Failure | File / location | Reproduce |" in report
    assert "a.parquet · whole file" in report
    child_report = (child / "REPORT.md").read_text()
    root_findings = report.split("## Failures", 1)[1].split("## Run details", 1)[0]
    child_findings = child_report.split("## Failures", 1)[1].split("## Outcomes", 1)[0]
    outcomes = child_report.split("## Outcomes", 1)[1].split("## Reproduce", 1)[0]
    assert sum(line.startswith("| ") for line in root_findings.splitlines()) - 1 == 3
    for section in (root_findings, child_findings, outcomes):
        positions = tuple(section.index(provider) for provider in ("duckdb", "polars", "pyarrow"))
        assert positions == tuple(sorted(positions))
    assert "All 3 readers failed while reading the file." in child_report
    assert "**Python:**" in child_report and "**Platform:**" in child_report
    assert "**Location:** whole file" in child_report
    assert "**Observation:** No table was returned" in child_report
    assert "Semantic comparison" not in child_report
    assert "python upstream_repro.py pyarrow" in child_report
    assert "| Detail | Stderr |" not in child_report
    assert child_report.count("Parquet magic bytes not found in footer") == 1
    assert "&lt;" not in child_report and "'<PARQUITY_TEMP>" in child_report
    for hidden in (
        "Source bundle ID",
        "Occurrence ID",
        "SHA-256",
        "Evidence basis",
        "Saved target",
        "## Findings",
    ):
        assert hidden not in child_report


def _assert_standalone_scan_scripts(standalone: Path, tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    environment = os.environ.copy()
    environment["PATH"] = ""
    reproduced = run_json_script(
        standalone / "reproduce.py", external, environment=environment, returncode=1
    )
    assert reproduced["status"] == "REPRODUCED"
    direct = run_json_script(standalone / "upstream_repro.py", external, "pyarrow", returncode=1)
    assert direct["outcome"] == "ERROR"


def _assert_scan_rejects_noncanonical_manifests(
    standalone: Path,
    aggregate: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_module = import_module("parquity.cli.main")
    for directory, manifest_name in ((standalone, "finding.json"), (aggregate, "scan.json")):
        manifest = directory / manifest_name
        manifest.write_text(json.dumps(json.loads(manifest.read_bytes()), indent=2))

    def unexpected_resolution(readers: object) -> object:
        raise AssertionError(readers)

    monkeypatch.setattr(main_module, "resolve_reader_selection", unexpected_resolution)
    for malformed in (standalone, aggregate):
        assert cli.main(["replay", str(malformed)]) == 2
        rejected, rejected_stderr = _payload(capsys)
        assert rejected["status"] == "CONFIGURATION_ERROR"
        assert cast(dict[str, object], rejected["error"])["kind"] == "INVALID_BUNDLE"
        assert rejected_stderr.startswith("parquity:")
    monkeypatch.undo()


def test_scan_configuration_failures_publish_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_output = tmp_path / "missing-output"
    assert cli.main(["scan", str(tmp_path / "missing"), "--out", str(missing_output)]) == 2
    payload, _ = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "INVALID_INPUT"
    assert not missing_output.exists()

    source = tmp_path / "input.parquet"
    _PQ.write_table(pa.table({"value": [1]}), source)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    sentinel = occupied / "sentinel"
    sentinel.write_text("preserved")
    assert cli.main(["scan", str(source), "--out", str(occupied)]) == 2
    occupied_payload, _ = _payload(capsys)
    assert cast(dict[str, object], occupied_payload["error"])["kind"] == "OUTPUT_EXISTS"
    assert sentinel.read_text() == "preserved"

    unavailable = tmp_path / "unavailable"
    arguments = ["scan", str(source), "--engines", "unknown", "--out", str(unavailable)]
    assert cli.main(arguments) == 2
    selection, _ = _payload(capsys)
    assert cast(dict[str, object], selection["error"])["kind"] == "UNKNOWN_ENGINE"
    assert not unavailable.exists()
