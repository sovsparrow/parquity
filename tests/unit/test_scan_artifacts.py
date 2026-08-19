import hashlib
import json
import shutil
from pathlib import Path
from shlex import split as _words
from typing import cast

import pytest

from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.scans import bundle, records
from parquity.scans.differences import DifferenceKind
from parquity.scans.observations import ObservationDifference, ObservationGroup
from parquity.scans.records import SCAN_ARTIFACTS, ReaderOutcomeKind, ReaderOutcomeRecord
from tests.support import symlinks_available

_CHILD_TAMPERS = _words("input manifest path symlink extra")
_RUN_TAMPERS = _words("child extra total-bool")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _success(engine: str, version: str, group: str, marker: str) -> ReaderOutcomeRecord:
    digest = marker * 64
    values = (
        engine,
        version,
        ReaderOutcomeKind.SUCCESS,
        "SUCCESS",
        "",
        "",
        False,
        1,
        1,
        digest,
        digest,
        16,
        group,
    )
    return ReaderOutcomeRecord(*values)


def _environment(engines: tuple[EngineVersion, ...], version: str = "0.1.0") -> EnvironmentEvidence:
    pyarrow = next(item.version for item in engines if item.name == "pyarrow")
    dependencies = (DependencyVersion("pyarrow", pyarrow),)
    return EnvironmentEvidence(
        version, "hypothesis", "3.12.0", "test-platform", engines, dependencies
    )


def _publish_scan_child(
    pending: Path,
    *,
    version: str,
    source_path: str,
    payload: bytes,
    engines: tuple[EngineVersion, ...],
    timeout: int,
    outcomes: tuple[ReaderOutcomeRecord, ...],
    groups: tuple[ObservationGroup, ...],
    comparisons: tuple[ObservationDifference, ...],
) -> tuple[records.ScanFindingRecord, Path, dict[str, object]]:
    record = bundle.build_finding(
        pending,
        environment=_environment(engines, version),
        source_path=source_path,
        input_payload=payload,
        engines=engines,
        timeout_seconds=timeout,
        outcomes=outcomes,
        groups=groups,
        comparisons=comparisons,
    )
    child = pending.with_name(record.finding_id)
    pending.rename(child)
    manifest = bundle.digest_data(
        f"findings/{record.finding_id}/finding.json",
        (child / "finding.json").read_bytes(),
    )
    index: dict[str, object] = {
        "finding_id": record.finding_id,
        "source_path": source_path,
        "manifest": manifest,
    }
    return record, child, index


def _published_finding(
    pending: Path, payload: bytes = b"PAR1controlled"
) -> tuple[records.ScanFindingRecord, Path, dict[str, object]]:
    engines = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    detail = "1 != 2 `code`\n## injected\n[link](https://invalid)|<tag>\n```"
    path = "$.rows[0].columns[0]"
    difference = ObservationDifference(
        "group-1", "group-2", DifferenceKind.VALUE_DIFFERENCE, path, detail
    )
    values = (("pyarrow", "1", "group-1", "a"), ("duckdb", "2", "group-2", "b"))
    outcomes = tuple(_success(*item) for item in values)
    groups = (ObservationGroup("group-1", ("pyarrow",)), ObservationGroup("group-2", ("duckdb",)))
    return _publish_scan_child(
        pending,
        version="0.1.0",
        source_path="nested/input.parquet",
        payload=payload,
        engines=engines,
        timeout=30,
        outcomes=outcomes,
        groups=groups,
        comparisons=(difference,),
    )


def _publish_finding(pending: Path) -> Path:
    return _published_finding(pending)[1]


def _published_run(directory: Path) -> Path:
    pending = directory / "findings" / "pending"
    finding, _, index = _published_finding(pending)
    bundle.build_run(
        directory,
        environment=finding.environment or pytest.fail("scan v2 environment missing"),
        input_kind="directory",
        files=(("nested/input.parquet", len(b"PAR1controlled")), ("overflow.parquet", 4)),
        skipped_symlinks=2,
        visited_entries=6,
        engines=finding.engines,
        timeout_seconds=30,
        max_saved=1,
        findings=(index,),
        overflow=("overflow.parquet",),
    )
    return directory


def test_scan_child_is_canonical_standalone_and_binds_complete_evidence(tmp_path: Path) -> None:
    child = _publish_finding(tmp_path / "finding")
    validated = bundle.validate_finding(child)
    payload = (child / "finding.json").read_bytes()
    document = cast(dict[str, object], json.loads(payload))
    assert payload == _canonical(document)
    assert document["format"] == "parquity.scan-finding.v2"
    assert validated.record.environment == _environment(validated.record.engines)
    assert validated.record.source_path == "nested/input.parquet"
    assert validated.record.input_sha256 == hashlib.sha256(b"PAR1controlled").hexdigest()
    artifacts = cast(list[dict[str, object]], document["artifacts"])
    assert tuple(item["path"] for item in artifacts) == SCAN_ARTIFACTS
    for artifact in artifacts:
        artifact_payload = (child / cast(str, artifact["path"])).read_bytes()
        observed = (len(artifact_payload), hashlib.sha256(artifact_payload).hexdigest())
        assert (artifact["bytes"], artifact["sha256"]) == observed
    assert "sys.executable" in (child / "reproduce.py").read_text(encoding="utf-8")
    assert "parquity" not in (child / "upstream_repro.py").read_text(encoding="utf-8").lower()
    assert str(tmp_path) not in payload.decode()


def test_scan_finding_id_projection_is_fixed_and_manifest_tampering_is_rejected(
    tmp_path: Path,
) -> None:
    signature = "0" * 64
    assert records.finding_id(signature) == (
        "4d08fea03912179b753571473ded707eafb120461a7f9d1880382cfde8f7ddba"
    )
    child = _publish_finding(tmp_path / "finding-id")
    manifest = child / "finding.json"
    document = cast(dict[str, object], json.loads(manifest.read_bytes()))
    document["finding_id"] = records.finding_id("1" * 64)
    with pytest.raises(records.ScanRecordError):
        records.ScanFindingRecord.from_json(records.canonical_bytes(document))


def test_scan_run_binds_children_and_standalone_copy(tmp_path: Path) -> None:
    run_directory = _published_run(tmp_path / "run")
    validated = bundle.validate_run(run_directory)
    payload = (run_directory / "scan.json").read_bytes()
    document = cast(dict[str, object], json.loads(payload))
    identity = {**document, "scan_id": ""}
    assert payload == _canonical(document)
    assert document["scan_id"] == hashlib.sha256(_canonical(identity)).hexdigest()
    assert document["format"] == "parquity.scan-run.v2"
    assert (document["status"], len(validated.children)) == (
        "SAVED_EVIDENCE_LIMIT_REACHED",
        1,
    )
    assert document["max_saved"] == 1 and "max_findings" not in document
    assert validated.record.environment == validated.children[0].record.environment
    discovery = cast(dict[str, object], document["discovery"])
    assert (discovery["skipped_symlinks"], discovery["visited_entries"]) == (2, 6)
    assert cast(dict[str, object], document["limits"])["max_visited_entries"] == 4096
    child_copy = tmp_path / "standalone"
    shutil.copytree(validated.children[0].directory, child_copy)
    assert bundle.validate_finding(child_copy).record == validated.children[0].record


@pytest.mark.parametrize("tamper", _CHILD_TAMPERS)
def test_scan_child_tampering_is_rejected(tmp_path: Path, tamper: str) -> None:
    if tamper == "symlink" and not symlinks_available(tmp_path):
        pytest.skip("creating a symlink requires a privilege this environment lacks")
    child = _publish_finding(tmp_path / tamper)
    if tamper == "input":
        target = child / "input.parquet"
        target.write_bytes(target.read_bytes() + b"tamper")
    elif tamper in ("manifest", "path"):
        path = child / "finding.json"
        document = cast(dict[str, object], json.loads(path.read_bytes()))
        if tamper == "manifest":
            path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        else:
            cast(list[dict[str, object]], document["artifacts"])[0]["path"] = "../REPORT.md"
            path.write_bytes(_canonical(document))
    elif tamper == "symlink":
        report = child / "REPORT.md"
        report.unlink()
        report.symlink_to(child / "input.parquet")
    else:
        (child / "unexpected").write_text("extra", encoding="utf-8")
    with pytest.raises(bundle.ScanBundleError):
        bundle.validate_finding(child)


def test_scan_run_tampering_is_rejected(tmp_path: Path) -> None:
    for name in (*_RUN_TAMPERS, "environment"):
        run = _published_run(tmp_path / name)
        if name == "child":
            finding = next((run / "findings").iterdir()) / "finding.json"
            finding.write_bytes(finding.read_bytes() + b"tamper")
        elif name == "extra":
            (run / "findings" / "extra").mkdir()
        elif name == "total-bool":
            path = run / "scan.json"
            document = cast(dict[str, object], json.loads(path.read_bytes()))
            discovery = cast(dict[str, object], document["discovery"])
            discovery["total_bytes"] = True
            document["scan_id"] = ""
            document["scan_id"] = records.scan_id(document)
            path.write_bytes(records.canonical_bytes(document))
        else:
            path = run / "scan.json"
            document = cast(dict[str, object], json.loads(path.read_bytes()))
            environment = cast(dict[str, object], document["environment"])
            environment["platform"] = "different-platform"
            document["scan_id"] = ""
            document["scan_id"] = records.scan_id(document)
            path.write_bytes(records.canonical_bytes(document))
        with pytest.raises(bundle.ScanBundleError):
            bundle.validate_run(run)


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
    with pytest.raises(bundle.ScanBundleError):
        bundle.validate_finding(child)


@pytest.mark.parametrize("mutation", ("detail", "missing"))
def test_scan_manifest_rejects_incomplete_group_comparisons(tmp_path: Path, mutation: str) -> None:
    child = _publish_finding(tmp_path / mutation)
    manifest = child / "finding.json"
    document = cast(dict[str, object], json.loads(manifest.read_bytes()))
    if mutation == "detail":
        cast(list[dict[str, object]], document["comparisons"])[0]["detail"] = "x" * 501
    else:
        document["comparisons"] = []
    manifest.write_bytes(_canonical(document))
    with pytest.raises(bundle.ScanBundleError):
        bundle.validate_finding(child)


def test_scan_run_rejects_resealed_child_discovery_size_mismatch(tmp_path: Path) -> None:
    destination = _published_run(tmp_path / "run-size")
    path = destination / "scan.json"
    document = cast(dict[str, object], json.loads(path.read_bytes()))
    discovery = cast(dict[str, object], document["discovery"])
    file = cast(list[dict[str, object]], discovery["files"])[0]
    file["bytes"] = cast(int, file["bytes"]) + 1
    discovery["total_bytes"] = cast(int, discovery["total_bytes"]) + 1
    document["scan_id"] = ""
    document["scan_id"] = records.scan_id(document)
    path.write_bytes(records.canonical_bytes(document))

    with pytest.raises(bundle.ScanBundleError):
        bundle.validate_run(destination)
