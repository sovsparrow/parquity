import hashlib
import json
import shutil
from collections.abc import Callable, Mapping
from importlib import metadata
from pathlib import Path
from shlex import split as _words
from typing import Any, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity.engines import ReaderSelection, resolve_reader_selection
from parquity.scans import records
from parquity.scans.bundle import (
    ScanBundleError,
    build_finding,
    build_run,
    digest_data,
    validate_finding,
    validate_run,
)
from parquity.scans.discovery import discover_input, snapshot_file
from parquity.scans.observations import ObservationDifference, ObservationGroup
from parquity.scans.records import SCAN_ARTIFACTS, ReaderOutcomeRecord
from parquity.scans.workflow import evaluate_snapshot, replay_finding
from parquity.triage.adapters import scan_child_occurrences
from parquity.verdicts import EngineVersion
from tests.support.report_fragments import report_fragments

_PQ = cast(Any, pq)
_CHILD_TAMPERS = _words("report input reproduce upstream manifest path symlink extra nonfinite")
_RUN_TAMPERS = _words("report reference child extra total-bool total-float total-text")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _inventory(root: Path) -> tuple[tuple[Path, bytes], ...]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    return tuple((path.relative_to(root), path.read_bytes()) for path in files)


def _success(engine: str, version: str, group: str, marker: str) -> ReaderOutcomeRecord:
    digest = marker * 64
    values = (engine, version, "SUCCESS", "SUCCESS", "", "", False, 1, 1, digest, digest, 16, group)
    return ReaderOutcomeRecord(*values)


def _disagreement(directory: Path, payload: bytes = b"PAR1controlled") -> str:
    engines = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    detail = "1 != 2 `code`\n## injected\n[link](https://invalid)|<tag>\n```"
    path = "$.rows[0].columns[0]"
    difference = ObservationDifference("group-1", "group-2", "VALUE_DIFFERENCE", path, detail)
    values = (("pyarrow", "1", "group-1", "a"), ("duckdb", "2", "group-2", "b"))
    outcomes = tuple(_success(*item) for item in values)
    groups = (ObservationGroup("group-1", ("pyarrow",)), ObservationGroup("group-2", ("duckdb",)))
    record = build_finding(
        directory,
        parquity_version="0.1.0",
        source_path="nested/input.parquet",
        input_payload=payload,
        engines=engines,
        timeout_seconds=30,
        outcomes=outcomes,
        groups=groups,
        comparisons=(difference,),
    )
    return record.finding_id


def _publish_finding(pending: Path) -> Path:
    child = pending.with_name(_disagreement(pending))
    pending.rename(child)
    return child


def _published_run(directory: Path) -> Path:
    pending = directory / "findings" / "pending"
    child = _publish_finding(pending)
    manifest, finding = (child / "finding.json").read_bytes(), validate_finding(child).record
    finding_id, source_path = finding.finding_id, finding.source_path
    manifest_digest = digest_data(f"findings/{finding_id}/finding.json", manifest)
    index = {"finding_id": finding_id, "source_path": source_path, "manifest": manifest_digest}
    build_run(
        directory,
        parquity_version="0.1.0",
        input_kind="directory",
        files=(("nested/input.parquet", len(b"PAR1controlled")), ("overflow.parquet", 4)),
        skipped_symlinks=2,
        visited_entries=6,
        engines=finding.engines,
        timeout_seconds=30,
        max_findings=1,
        findings=(index,),
        overflow=("overflow.parquet",),
    )
    return directory


def test_scan_child_is_canonical_standalone_and_binds_complete_evidence(tmp_path: Path) -> None:
    child = _publish_finding(tmp_path / "finding")
    validated = validate_finding(child)
    payload = (child / "finding.json").read_bytes()
    document = cast(dict[str, object], json.loads(payload))
    assert payload == _canonical(document)
    assert document["format"] == "parquity.scan-finding.v1"
    assert validated.record.source_path == "nested/input.parquet"
    assert validated.record.input_sha256 == hashlib.sha256(b"PAR1controlled").hexdigest()
    artifacts = cast(list[dict[str, object]], document["artifacts"])
    assert tuple(item["path"] for item in artifacts) == SCAN_ARTIFACTS
    for artifact in artifacts:
        artifact_payload = (child / cast(str, artifact["path"])).read_bytes()
        observed = (len(artifact_payload), hashlib.sha256(artifact_payload).hexdigest())
        assert (artifact["bytes"], artifact["sha256"]) == observed
    report = (child / "REPORT.md").read_text()
    assert report.index("## Summary") < report.index("## Technical evidence")
    required = report_fragments(
        '## Reader outcomes;## Observed differences;## Reproduce;"nested/input.parquet";'
        "`pyarrow 1`;`duckdb 2`;`group-1` (pyarrow);`group-2` (duckdb);"
        "`VALUE_DIFFERENCE`;row 1, column 1;python upstream_repro.py pyarrow"
    )
    assert all(value in report for value in required)
    assert scan_child_occurrences((validated,))[0].occurrence_id in report
    assert "\n## injected" not in report and "\n```" not in report
    assert "[link](https://invalid)" not in report and "<tag>" not in report
    assert "Inspect every file before sharing" in report
    assert "sys.executable" in (child / "reproduce.py").read_text()
    assert "parquity" not in (child / "upstream_repro.py").read_text().lower()
    assert str(tmp_path) not in payload.decode() + report


def test_scan_run_binds_report_children_and_standalone_copy(tmp_path: Path) -> None:
    run_directory = _published_run(tmp_path / "run")
    validated = validate_run(run_directory)
    payload = (run_directory / "scan.json").read_bytes()
    document = cast(dict[str, object], json.loads(payload))
    identity = {**document, "scan_id": ""}
    assert payload == _canonical(document)
    assert document["scan_id"] == hashlib.sha256(_canonical(identity)).hexdigest()
    assert document["status"] == "FINDING_CAP_REACHED"
    discovery = cast(dict[str, object], document["discovery"])
    assert (discovery["skipped_symlinks"], discovery["visited_entries"]) == (2, 6)
    assert cast(dict[str, object], document["limits"])["max_visited_entries"] == 4096
    assert len(validated.children) == 1
    child_copy = tmp_path / "standalone"
    shutil.copytree(validated.children[0].directory, child_copy)
    assert validate_finding(child_copy).record == validated.children[0].record
    report = (run_directory / "REPORT.md").read_text()
    headings = report_fragments(
        "## Summary;## Run scope;## Files with observed problems;"
        "## Files not evaluated after the finding cap;## Symptom families;"
        "## Replay and triage;## Coverage and limits;## Environment and exact evidence"
    )
    assert tuple(map(report.index, headings)) == tuple(sorted(map(report.index, headings)))
    required = report_fragments(
        "Parquet files discovered | 2;Files evaluated | 1;Files with retained findings | 1;"
        'Files not evaluated after cap | 1;Filesystem entries visited | 6;"nested/input.parquet";'
        "overflow.parquet;not exhaustive;Inspect every child before sharing"
    )
    assert all(item in report for item in required)
    assert validated.children[0].record.finding_id in report
    assert "\n## injected" not in report and "[link](https://invalid)" not in report


@pytest.mark.parametrize("tamper", _CHILD_TAMPERS)
def test_scan_child_tampering_is_rejected(tmp_path: Path, tamper: str) -> None:
    child = _publish_finding(tmp_path / tamper)
    keys = ("report", "input", "reproduce", "upstream")
    targets = cast(dict[str, str], dict(zip(keys, SCAN_ARTIFACTS, strict=True)))
    if tamper == "report":
        payload = b"# arbitrary but resealed\n"
        (child / "REPORT.md").write_bytes(payload)
        path = child / "finding.json"
        document = cast(dict[str, object], json.loads(path.read_bytes()))
        artifacts = cast(list[dict[str, object]], document["artifacts"])
        next(item for item in artifacts if item["path"] == "REPORT.md").update(
            digest_data("REPORT.md", payload)
        )
        path.write_bytes(_canonical(document))
    elif name := targets.get(tamper):
        (child / name).write_bytes((child / name).read_bytes() + b"tamper")
    elif tamper in ("manifest", "path"):
        path = child / "finding.json"
        document = cast(dict[str, object], json.loads(path.read_bytes()))
        if tamper == "manifest":
            path.write_text(json.dumps(document, indent=2))
        else:
            cast(list[dict[str, object]], document["artifacts"])[0]["path"] = "../REPORT.md"
            path.write_bytes(_canonical(document))
    elif tamper == "symlink":
        report = child / "REPORT.md"
        report.unlink()
        report.symlink_to(child / "input.parquet")
    elif tamper == "nonfinite":
        path = child / "finding.json"
        document = cast(dict[str, object], json.loads(path.read_bytes()))
        cast(list[dict[str, object]], document["outcomes"])[0]["detail"] = float("nan")
        with pytest.raises(ValueError):
            records.canonical_bytes(document)
        path.write_bytes(_canonical(document))
    else:
        (child / "unexpected").write_text("extra")
    with pytest.raises(ScanBundleError):
        validate_finding(child)


def test_scan_run_tampering_is_rejected(tmp_path: Path) -> None:
    for name in _RUN_TAMPERS:
        run = _published_run(tmp_path / name)
        if name == "child":
            finding = next((run / "findings").iterdir()) / "finding.json"
            finding.write_bytes(finding.read_bytes() + b"tamper")
        elif name == "extra":
            (run / "findings" / "extra").mkdir()
        else:
            path = run / "scan.json"
            document = cast(dict[str, object], json.loads(path.read_bytes()))
            if name == "report":
                payload = b"# arbitrary but resealed\n"
                (run / "REPORT.md").write_bytes(payload)
                document["report"] = digest_data("REPORT.md", payload)
            elif name == "reference":
                index = cast(list[dict[str, object]], document["findings"])[0]
                cast(dict[str, object], index["manifest"])["sha256"] = "0" * 64
            else:
                discovery = cast(dict[str, object], document["discovery"])
                total = cast(int, discovery["total_bytes"])
                values = {"total-bool": True, "total-float": float(total), "total-text": str(total)}
                discovery["total_bytes"] = values[name]
            document["scan_id"] = ""
            document["scan_id"] = records.scan_id(document)
            path.write_bytes(records.canonical_bytes(document))
        with pytest.raises(ScanBundleError):
            validate_run(run)


def _provider_finding(
    directory: Path,
    input_payload: bytes,
    alter: Callable[[ReaderOutcomeRecord], ReaderOutcomeRecord] | None = None,
    recorded_version: str | None = None,
) -> tuple[Path, ReaderSelection]:
    input_path = directory / "source.parquet"
    input_path.parent.mkdir(parents=True)
    input_path.write_bytes(input_payload)
    selection = resolve_reader_selection(("pyarrow",))
    source = discover_input(input_path).files[0]
    snapshot = snapshot_file(source, directory / "snapshot")
    evaluation = evaluate_snapshot(snapshot, selection, 30, directory)
    outcome = evaluation.outcomes[0]
    if alter is not None:
        outcome = alter(outcome)
    version = recorded_version or selection.reader_versions[0][1]
    outcome = outcome._replace(version=version)
    bundle = directory / "bundle"
    build_finding(
        bundle,
        parquity_version="0.0.0" if recorded_version else metadata.version("parquity"),
        source_path="source.parquet",
        input_payload=input_payload,
        engines=(EngineVersion("pyarrow", version),),
        timeout_seconds=30,
        outcomes=(outcome,),
        groups=evaluation.grouped.groups if outcome.kind == "SUCCESS" else (),
        comparisons=evaluation.grouped.differences if outcome.kind == "SUCCESS" else (),
    )
    return bundle, selection


def test_scan_replay_exact_related_absent_and_version_drift(tmp_path: Path) -> None:
    exact_path, selection = _provider_finding(tmp_path / "exact", b"not parquet")
    exact = replay_finding(validate_finding(exact_path), selection)
    assert exact["classification"] == "REPRODUCED"
    failure_summary = (exact_path / "REPORT.md").read_text()
    expected = ("PROVIDER_ERROR", "no table returned", "No pairwise semantic difference")
    assert all(value in failure_summary for value in expected)
    related_path, related_selection = _provider_finding(
        tmp_path / "related",
        b"not parquet",
        lambda item: item._replace(detail="changed\n## injected\n```"),
    )
    before = _inventory(related_path)
    related = replay_finding(validate_finding(related_path), related_selection)
    assert _inventory(related_path) == before and related["classification"] == "RELATED_FAILURE"
    occurrence = cast(list[Mapping[str, object]], related["occurrence_results"])[0]
    observation = cast(Mapping[str, object], occurrence["current_observation"])
    change = cast(list[Mapping[str, object]], observation["detail_changes"])[0]
    assert observation["signal"] == "PROVIDER_ERROR" and observation["target_reader"] == "pyarrow"
    assert observation["reader_roster"] == ["pyarrow"]
    assert change["original_detail"] == "changed ## injected ```"
    expected_sha256 = hashlib.sha256(b"changed ## injected ```").hexdigest()
    assert change["original_detail_sha256"] == expected_sha256
    assert change["current_detail_sha256"] != change["original_detail_sha256"]
    related_summary = (related_path / "REPORT.md").read_text()
    assert "\n## injected" not in related_summary and "\n```" not in related_summary
    table_path = tmp_path / "valid.parquet"
    _PQ.write_table(pa.table({"value": [1]}), table_path)
    absent_path, absent_selection = _provider_finding(
        tmp_path / "absent",
        table_path.read_bytes(),
        lambda item: ReaderOutcomeRecord(
            item.engine, item.version, "PROCESS_CRASH", "PROCESS_CRASH", "", "", False
        ),
    )
    absent = replay_finding(validate_finding(absent_path), absent_selection)
    assert absent["classification"] == "NOT_REPRODUCED"
    assert "No diagnostic text was captured." in (absent_path / "REPORT.md").read_text()
    drift_path, drift_selection = _provider_finding(
        tmp_path / "drift", b"not parquet", recorded_version="recorded-version"
    )
    drift = replay_finding(validate_finding(drift_path), drift_selection)
    assert drift["classification"] == "REPRODUCED"
    assert cast(list[Mapping[str, object]], drift["version_evidence"])[0]["drift"] is True
    assert cast(Mapping[str, object], drift["package_version"])["drift"] is True


@pytest.mark.parametrize(
    ("key", "value"),
    (("observation_group", None), ("stderr_truncated", "false")),
)
def test_scan_manifest_rejects_incomplete_outcome_evidence(
    tmp_path: Path, key: str, value: object
) -> None:
    child = _publish_finding(tmp_path / key)
    manifest = child / "finding.json"
    document = cast(dict[str, object], json.loads(manifest.read_bytes()))
    cast(list[dict[str, object]], document["outcomes"])[0][key] = value
    manifest.write_bytes(_canonical(document))
    with pytest.raises(ScanBundleError):
        validate_finding(child)


@pytest.mark.parametrize("mutation", ("members", "detail", "missing"))
def test_scan_manifest_rejects_incomplete_group_comparisons(tmp_path: Path, mutation: str) -> None:
    child = _publish_finding(tmp_path / mutation)
    manifest = child / "finding.json"
    document = cast(dict[str, object], json.loads(manifest.read_bytes()))
    if mutation == "members":
        cast(list[dict[str, object]], document["observation_groups"])[0]["engines"] = []
    elif mutation == "detail":
        cast(list[dict[str, object]], document["comparisons"])[0]["detail"] = "x" * 501
    else:
        document["comparisons"] = []
    manifest.write_bytes(_canonical(document))
    with pytest.raises(ScanBundleError):
        validate_finding(child)
