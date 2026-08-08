from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

import parquity.cli as cli
from parquity.scans import records
from parquity.scans.bundle import ScanBundleError, validate_run


class _ParquetWriter(Protocol):
    def write_table(self, table: pa.Table, where: Path) -> None: ...


_PQ = cast(_ParquetWriter, cast(object, pq))


def _payload(captured: pytest.CaptureFixture[str]) -> tuple[dict[str, object], str]:
    streams = captured.readouterr()
    payload = cast(dict[str, object], json.loads(streams.out))
    assert payload["format"] == "parquity.cli.v1"
    return payload, streams.err


def _run_script(
    script: Path,
    cwd: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603 - generated script uses the current interpreter.
        [sys.executable, str(script), *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    return cast(dict[str, object], json.loads(completed.stdout))


def _invalid_documents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[dict[str, object], dict[str, object], Path]:
    source = tmp_path / "invalid.parquet"
    source.write_bytes(b"not parquet")
    destination = tmp_path / "invalid-run"
    arguments = [
        "scan",
        str(source),
        "--engines",
        "pyarrow,duckdb",
        "--out",
        str(destination),
    ]
    assert cli.main(arguments) == 1
    _payload(capsys)
    child = next((destination / "findings").iterdir())
    finding = cast(dict[str, object], json.loads((child / "finding.json").read_bytes()))
    run = cast(dict[str, object], json.loads((destination / "scan.json").read_bytes()))
    return finding, run, destination


@pytest.mark.parametrize(
    "arguments",
    (
        ["scan"],
        ["scan", "input"],
        ["scan", "input", "--out", "unused", "--timeout", "0"],
        ["scan", "input", "--out", "unused", "--timeout", "301"],
        ["scan", "input", "--out", "unused", "--timeout", "bad"],
        ["scan", "input", "--out", "unused", "--max-findings", "0"],
        ["scan", "input", "--out", "unused", "--max-findings", "65"],
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


def test_scan_finding_cap_reports_scripts_and_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.parquet", "b.parquet"):
        (source / name).write_bytes(b"not parquet")
    destination = tmp_path / "run"
    arguments = [
        "scan",
        str(source),
        "--engines",
        "pyarrow",
        "--max-findings",
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
    child = run.children[0].directory
    assert cast(list[str], run.record.data["overflow"]) == ["b.parquet"]
    assert cast(dict[str, object], run.record.data["limits"])["max_visited_entries"] == 4096
    run_report = (destination / "REPORT.md").read_text()
    assert "not exhaustive" in run_report
    assert "Files not evaluated after cap | 1" in run_report
    assert '"b.parquet"' in run_report
    finding_report = (child / "REPORT.md").read_text()
    assert "No reader is treated as the reference answer" in finding_report
    assert "python upstream_repro.py pyarrow" in finding_report
    assert "Inspect every file before sharing" in finding_report
    for relative in ("scan.json", "REPORT.md"):
        assert str(tmp_path) not in (destination / relative).read_text()
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
    replay_evidence = tmp_path / "aggregate-replay.json"
    replay_evidence.write_bytes(records.canonical_bytes(aggregate) + b"\n")
    assert cli.main(["triage", str(destination), "--replay-evidence", str(replay_evidence)]) == 0
    triaged, _ = _payload(capsys)
    assert (triaged["finding_bundle_count"], triaged["occurrence_count"]) == (1, 1)
    family = cast(list[dict[str, object]], triaged["symptom_families"])[0]
    assert family["representative_reproduction_state"] == "REPRODUCED"
    external = tmp_path / "external"
    external.mkdir()
    environment = os.environ.copy()
    environment["PATH"] = ""
    reproduced = _run_script(standalone / "reproduce.py", external, environment=environment)
    assert reproduced["status"] == "REPRODUCED"
    direct = _run_script(standalone / "upstream_repro.py", external, "pyarrow")
    assert direct["outcome"] == "ERROR"

    _assert_scan_replay_boundaries(standalone, destination, result, monkeypatch, capsys)

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
    exact_report = (exact_destination / "REPORT.md").read_text()
    assert "Parquet files discovered | 1" in exact_report
    assert "Files evaluated | 1" in exact_report
    assert "not exhaustive" not in exact_report


def _assert_scan_replay_boundaries(
    standalone: Path,
    aggregate: Path,
    result: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workflow = import_module("parquity.scans.workflow")
    main_module = import_module("parquity.cli.main")
    cases = (
        ("RELATED_FAILURE", ("RELATED_FAILURE",), 0),
        ("NOT_REPRODUCED", ("NOT_REPRODUCED",), 0),
        ("RELATED_FAILURE", ("REPRODUCED", "RELATED_FAILURE"), 1),
    )
    for classification, states, exit_code in cases:
        controlled = {**result, "classification": classification}
        controlled["occurrence_results"] = [{"classification": state} for state in states]

        def controlled_replay(*_: object, outcome: object = controlled) -> object:
            return outcome

        monkeypatch.setattr(workflow, "replay_finding", controlled_replay)
        assert cli.main(["replay", str(standalone)]) == exit_code
        replay_payload, _ = _payload(capsys)
        assert replay_payload["status"] == classification

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


def test_scan_finding_record_rejects_every_incomplete_identity_branch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    finding, _, _ = _invalid_documents(tmp_path, capsys)
    for mutation in (
        "artifacts",
        "status",
        "outcomes",
        "groups",
        "kind",
        "digest",
        "engines",
    ):
        changed = deepcopy(finding)
        if mutation == "artifacts":
            cast(list[object], changed["artifacts"]).reverse()
        elif mutation == "status":
            changed["scan_status"] = "AGREEMENT"
        elif mutation == "outcomes":
            cast(list[object], changed["outcomes"]).reverse()
        elif mutation == "groups":
            changed["observation_groups"] = [{"id": "wrong", "engines": []}]
        elif mutation == "kind":
            cast(list[dict[str, object]], changed["outcomes"])[0]["kind"] = "UNKNOWN"
        elif mutation == "digest":
            cast(list[dict[str, object]], changed["artifacts"])[0]["sha256"] = "bad"
        else:
            engines = cast(list[dict[str, object]], changed["engines"])
            engines.append(dict(engines[0]))
        with pytest.raises(records.ScanRecordError):
            records.ScanFindingRecord.from_json(records.canonical_bytes(changed))


def test_scan_run_record_rejects_reference_index_and_run_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, run, _ = _invalid_documents(tmp_path, capsys)
    for mutation in ("reference", "index", "input"):
        changed = deepcopy(run)
        if mutation == "reference":
            finding = cast(list[dict[str, object]], changed["findings"])[0]
            cast(dict[str, object], finding["manifest"])["path"] = "findings/other/finding.json"
        elif mutation == "index":
            changed["findings"] = []
        else:
            changed["input_kind"] = "unknown"
        with pytest.raises(records.ScanRecordError):
            records.validate_run(changed)


def test_scan_run_rejects_resealed_child_discovery_size_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, run, destination = _invalid_documents(tmp_path, capsys)
    discovery = cast(dict[str, object], run["discovery"])
    file = cast(list[dict[str, object]], discovery["files"])[0]
    file["bytes"] = cast(int, file["bytes"]) + 1
    discovery["total_bytes"] = cast(int, discovery["total_bytes"]) + 1
    run["scan_id"] = ""
    run["scan_id"] = records.scan_id(run)
    (destination / "scan.json").write_bytes(records.canonical_bytes(run))

    with pytest.raises(ScanBundleError):
        validate_run(destination)
