from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import cast

import pytest

import parquity.cli as cli
from parquity.cli.output import emit
from parquity.findings import evidence
from parquity.generation.reduce import ReductionCounts
from parquity.generation.search import SearchFinding
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs.bundle import RunSource, publish_run
from parquity.runs.bundle import validate_run as validate_generated
from parquity.scans import records
from parquity.scans.bundle import build_finding, build_run, digest_data
from parquity.scans.records import ReaderOutcomeRecord
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict

Capture = pytest.CaptureFixture[str]
Dependency = evidence.DependencyVersion
Drift = list[dict[str, object]]


def _generated_run(root: Path, *, name: str = "generated-run", bound: int = 10) -> Path:
    writers = (EngineVersion("pyarrow", "1"),)
    readers = (EngineVersion("duckdb", "2"), EngineVersion("fastparquet", "3"))
    first = Case((Field("alpha", TypeSpec(Kind.INT32)),), ((1,),))
    second = Case((Field("beta", TypeSpec(Kind.INT32)),), ((1,), (2,)))
    failure = ("pyarrow", "1", "duckdb", "2", "compare", Verdict.VALUE_MISMATCH)
    passing = CellResult("pyarrow", "1", "fastparquet", "3", "compare", Verdict.PASS, "$", "")
    results = {
        first.case_id: (CellResult(*failure, "$rows[0].alpha", "stable mismatch"), passing),
        second.case_id: (CellResult(*failure, "$rows[1].beta", "stable mismatch"), passing),
    }

    def evaluate(case: Case, directory: Path) -> MatrixRun:
        directory.mkdir(parents=True)
        output = directory / "pyarrow.parquet"
        output.write_bytes(f"PAR1{case.case_id}PAR1".encode())
        return MatrixRun(
            case.case_id, results[case.case_id], (("pyarrow", output),), writers, readers
        )

    findings: list[SearchFinding] = []
    for case in (first, second):
        result = results[case.case_id][0]
        key = result.fingerprint or pytest.fail("failure fingerprint missing")
        matrix = MatrixRun(case.case_id, results[case.case_id], (), writers, readers)
        findings.append(
            SearchFinding(case, case, key, result, matrix, bound, False, ReductionCounts())
        )
    dependencies = (Dependency("pyarrow", "1"), Dependency("pandas", "3"))
    source = RunSource(
        "fuzz",
        tuple(findings),
        (),
        writers,
        readers,
        evidence.DiscoveryEvidence(bound, 0, 8, evidence.EXAMPLE_BOUND_REACHED),
        evidence.EnvironmentEvidence(
            "0.1.0", "6.165.1", "3.12", "controlled", (*writers, *readers), dependencies
        ),
    )
    destination = root / name
    assert publish_run(source, destination, evaluate) is not None
    return destination


def _scan_run(root: Path) -> Path:
    destination = root / "scan-run"
    engines = (EngineVersion("reader", "1"), EngineVersion("other", "2"))
    hostile = "kind`\n## injected\n[link](https://invalid)|<tag>\n```"
    outcomes = (
        ReaderOutcomeRecord("reader", "1", "PROVIDER_ERROR", hostile, hostile, "", False),
        ReaderOutcomeRecord(
            "other", "2", "PROCESS_CRASH", "PROCESS_CRASH", "crashed", "crashed", False
        ),
    )
    name, payload = "a.parquet", b"PAR1a"
    pending = destination / "findings" / "pending"
    finding = build_finding(
        pending,
        parquity_version="0.1.0",
        source_path=name,
        input_payload=payload,
        engines=engines,
        timeout_seconds=30,
        outcomes=outcomes,
        groups=(),
        comparisons=(),
    )
    child = pending.with_name(finding.finding_id)
    pending.rename(child)
    manifest = digest_data(
        f"findings/{finding.finding_id}/finding.json", (child / "finding.json").read_bytes()
    )
    index = {"finding_id": finding.finding_id, "source_path": name, "manifest": manifest}
    build_run(
        destination,
        parquity_version="0.1.0",
        input_kind="directory",
        files=((name, len(payload)),),
        skipped_symlinks=0,
        engines=engines,
        timeout_seconds=30,
        max_findings=4,
        findings=(index,),
        overflow=(),
    )
    return destination


def _payload(captured: Capture) -> tuple[dict[str, object], str]:
    streams = captured.readouterr()
    return cast(dict[str, object], json.loads(streams.out)), streams.err


def _inventory(directory: Path) -> dict[str, bytes]:
    files = (path for path in sorted(directory.rglob("*")) if path.is_file())
    return {str(path.relative_to(directory)): path.read_bytes() for path in files}


def _replay(run_id: str, ids: tuple[str, ...], pd: str | None, drift: Drift) -> dict[str, object]:
    version_evidence: list[dict[str, object]] = [
        {"role": role, "engine": engine, "original": version, "current": version, "available": True}
        for role, engine, version in (("writer", "pyarrow", "1"), ("reader", "duckdb", "2"))
    ]
    dependency_evidence: list[dict[str, object]] = [
        {
            "package": package,
            "original": original,
            "current": current,
            "available": current is not None,
        }
        for package, original, current in (("pyarrow", "1", "1"), ("pandas", "3", pd))
    ]
    findings: list[dict[str, object]] = [
        {
            "finding_id": finding_id,
            "classification": classification,
            "version_evidence": version_evidence,
            "version_drift": [],
            "dependency_evidence": dependency_evidence,
            "dependency_drift": drift,
        }
        for finding_id, classification in zip(ids, ("NOT_REPRODUCED", "REPRODUCED"), strict=True)
    ]
    return {
        "format": "parquity.cli.v1",
        "command": "replay",
        "status": "REPRODUCED",
        "run_id": run_id,
        "exact": 1,
        "related": 0,
        "absent": 1,
        "findings": findings,
    }


def _reject_stale_report(directory: Path, manifest_name: str, kind: str, cap: Capture) -> None:
    historical = b"Historical aggregate report without a family section.\n"
    report, manifest_path = directory / "REPORT.md", directory / manifest_name
    report.write_bytes(historical)
    manifest = cast(dict[str, object], json.loads(manifest_path.read_bytes()))
    manifest["report"] = digest_data("REPORT.md", historical)
    if "scan_id" in manifest:
        manifest["scan_id"] = records.scan_id({**manifest, "scan_id": ""})
    manifest_path.write_bytes(records.canonical_bytes(manifest))
    assert cli.main(["triage", str(directory)]) == 2
    rejected, _ = _payload(cap)
    assert cast(dict[str, object], rejected["error"])["kind"] == kind
    assert report.read_bytes() == historical


def test_triage_is_deterministic_read_only_and_focus_only_filters_display(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    generated, scan = _generated_run(tmp_path), _scan_run(tmp_path)
    before = {"generated": _inventory(generated), "scan": _inventory(scan)}
    counters = {"provider": 0, "process": 0, "write": 0}
    main_module = import_module("parquity.cli.main")
    reader_resolver = main_module.resolve_reader_selection

    def forbidden(kind: str) -> Callable[..., None]:
        def fail(*args: object, **kwargs: object) -> None:
            del args, kwargs
            counters[kind] += 1
            raise AssertionError(f"triage attempted forbidden {kind}")

        return fail

    provider = forbidden("provider")
    for name in ("resolve_engine_selection", "resolve_reader_selection", "resolve_engines"):
        monkeypatch.setattr(main_module, name, provider)
    monkeypatch.setattr(subprocess, "Popen", forbidden("process"))
    for name in ("write_bytes", "write_text", "mkdir"):
        monkeypatch.setattr(Path, name, forbidden("write"))
    assert cli.main(["triage", str(generated)]) == 0
    all_generated, stderr = _payload(capsys)
    assert cli.main(["triage", str(generated)]) == 0
    repeated, _ = _payload(capsys)
    assert all_generated == repeated and stderr == ""
    assert all_generated["status"] == "TRIAGED" and all_generated["occurrence_count"] == 2
    assert all_generated["finding_bundle_count"] == 2
    assert all_generated["symptom_family_count"] == 1
    assert all_generated["displayed_symptom_family_count"] == 1
    family = cast(list[dict[str, object]], all_generated["symptom_families"])[0]
    versions = cast(dict[str, object], family["observed_versions"])
    packages = cast(list[dict[str, object]], versions["packages"])
    assert [item["package"] for item in packages] == ["hypothesis", "pandas", "parquity", "pyarrow"]
    assert cli.main(["triage", str(generated), "--focus", "execution"]) == 0
    execution, _ = _payload(capsys)
    assert execution["occurrence_count"] == 2 and execution["symptom_family_count"] == 1
    assert execution["displayed_symptom_family_count"] == 0
    assert execution["symptom_families"] == []
    assert cli.main(["triage", str(generated), "--focus", "data"]) == 0
    data, _ = _payload(capsys)
    assert data["symptom_families"] == all_generated["symptom_families"]
    assert cli.main(["triage", str(scan)]) == 0
    scan_payload, _ = _payload(capsys)
    assert scan_payload["occurrence_count"] == 2 and scan_payload["symptom_family_count"] == 2
    assert scan_payload["finding_bundle_count"] == 1
    families = cast(list[dict[str, object]], scan_payload["symptom_families"])
    provider = next(item for item in families if item["signal"] == "PROVIDER_ERROR")
    diagnostic = cast(dict[str, object], provider["projection"])["diagnostic_kind"]
    assert diagnostic == "kind`\n## injected\n[link](https://invalid)|<tag>\n```"
    child_report = next((scan / "findings").iterdir()).joinpath("REPORT.md").read_text()
    child_summary = child_report.split("## Evidence", 1)[0]
    assert "\n## injected" not in child_summary and "\n```" not in child_summary
    assert "[link](https://invalid)" not in child_summary and "<tag>" not in child_summary
    monkeypatch.setattr(main_module, "resolve_reader_selection", reader_resolver)
    assert cli.main(["replay", str(scan)]) == 2
    unavailable, _ = _payload(capsys)
    assert cast(dict[str, object], unavailable["error"])["kind"] == "UNKNOWN_ENGINE"
    assert counters == {"provider": 0, "process": 0, "write": 0}
    assert before == {"generated": _inventory(generated), "scan": _inventory(scan)}


def test_triage_rejects_non_aggregates_usage_and_maps_internal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    generated = _generated_run(tmp_path)
    child = validate_generated(generated).children[0].directory
    assert cli.main(["triage", str(child)]) == 2
    invalid, stderr = _payload(capsys)
    assert cast(dict[str, object], invalid["error"])["kind"] == "INVALID_RUN"
    assert stderr.startswith("parquity:")
    assert cli.main(["triage", str(generated), "--focus", "unknown"]) == 2
    usage, _ = _payload(capsys)
    assert cast(dict[str, object], usage["error"])["kind"] == "USAGE_ERROR"
    generated = _generated_run(tmp_path, name="stale")
    _reject_stale_report(generated, "run.json", "INVALID_BUNDLE", capsys)
    _reject_stale_report(_scan_run(tmp_path), "scan.json", "INVALID_RUN", capsys)
    triage_module = import_module("parquity.triage")

    def fail(*args: object) -> None:
        del args
        raise RuntimeError("controlled")

    monkeypatch.setattr(triage_module, "triage_run", fail)
    assert cli.main(["triage", str(generated)]) == 3
    internal, internal_stderr = _payload(capsys)
    assert internal["status"] == "INTERNAL_ERROR"
    assert cast(dict[str, object], internal["error"])["kind"] == "RuntimeError"
    assert internal_stderr == "parquity: RuntimeError\n"


def test_generated_replay_evidence_is_complete_bound_and_selects_representative(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _generated_run(tmp_path)
    identifiers = tuple(
        child.finding.finding_id for child in validate_generated(directory).children
    )
    other = validate_generated(_generated_run(tmp_path, name="other-run", bound=11))
    assert tuple(child.finding.finding_id for child in other.children) == identifiers
    run_id = validate_generated(directory).run.run_id
    states: tuple[tuple[str | None, list[dict[str, object]]], ...] = (
        ("9", [{"package": "pandas", "original": "3", "current": "9"}]),
        (None, []),
        ("3", []),
    )
    replay_path = tmp_path / "generated-replay.json"
    for current, current_drift in states:
        replay = _replay(run_id, identifiers, current, current_drift)
        emit(replay)
        replay_path.write_bytes(capsys.readouterr().out.encode("utf-8"))
        assert cli.main(["triage", str(directory), "--replay-evidence", str(replay_path)]) == 0
        payload, _ = _payload(capsys)
        family = cast(list[dict[str, object]], payload["symptom_families"])[0]
        state_counts = cast(dict[str, int], family["reproduction_state_counts"])
        assert family["representative_reproduction_state"] == "REPRODUCED"
        assert state_counts["REPRODUCED"] == 1 and payload["replay_evidence"] == "VALIDATED"
        assert cast(dict[str, object], family["representative"])["finding_id"] == identifiers[1]
    replay = _replay(run_id, identifiers, "3", [])
    replay_findings = cast(list[dict[str, object]], replay["findings"])
    version_evidence = cast(list[dict[str, object]], replay_findings[0]["version_evidence"])
    dependency_evidence = cast(list[dict[str, object]], replay_findings[0]["dependency_evidence"])
    missing_dependency = {
        key: value for key, value in replay_findings[0].items() if key != "dependency_evidence"
    }
    contradictory = {
        **replay_findings[0],
        "version_evidence": [{**version_evidence[0], "available": False}, version_evidence[1]],
    }
    drift = {"role": "writer", "engine": "pyarrow", "original": "1", "current": "9"}
    unavailable_dependency = [{**dependency_evidence[0], "available": False}]
    dependency_drift = [{"package": "pyarrow", "original": "1", "current": "9"}]

    def changed_findings(first: object, second: object = replay_findings[1]) -> dict[str, object]:
        return {**replay, "findings": [first, second]}

    invalid_documents = (
        {**replay, "run_id": other.run.run_id},
        {**replay, "extra": True},
        {**replay, "findings": replay_findings[:1]},
        {**replay, "findings": list(reversed(replay_findings))},
        {**replay, "findings": [replay_findings[0], replay_findings[0]]},
        changed_findings({**replay_findings[0], "extra": True}),
        changed_findings(missing_dependency),
        changed_findings(contradictory),
        changed_findings({**replay_findings[0], "dependency_evidence": unavailable_dependency}),
        changed_findings({**replay_findings[0], "dependency_drift": dependency_drift}),
        changed_findings({**replay_findings[0], "version_drift": [drift]}),
        changed_findings(
            replay_findings[0], {**replay_findings[1], "classification": "NOT_CHECKED"}
        ),
        {**replay, "exact": 0},
    )
    invalid_payloads = (
        b"{",
        *(records.canonical_bytes(item) + b"\n" for item in invalid_documents),
        json.dumps(replay, indent=2).encode() + b"\n",
    )
    for index, invalid_payload in enumerate(invalid_payloads):
        path = tmp_path / f"invalid-{index}.json"
        path.write_bytes(invalid_payload)
        assert cli.main(["triage", str(directory), "--replay-evidence", str(path)]) == 2
        rejected, _ = _payload(capsys)
        assert cast(dict[str, object], rejected["error"])["kind"] == "INVALID_REPLAY_EVIDENCE"
