import hashlib
import json
import shutil
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from parquity import cli
from parquity import writer_profiles as wp
from parquity.findings import evidence
from parquity.findings.bundle import validate_bundle
from parquity.findings.model import finding_id_for
from parquity.generation.reduce import ReductionCounts
from parquity.generation.search import OverflowObservation, SearchFinding
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs import bundle, model, replay
from parquity.triage.model import canonical_bytes
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict

_CASE = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))
_ENGINES = tuple(map(EngineVersion, ("pyarrow", "duckdb", "polars"), ("1", "2", "3")))
_CHECK = evidence.DiscoveryEvidence(None, None, None, evidence.CHECK_COMPLETE)
_CAPPED = evidence.DiscoveryEvidence(10, 0, 3, evidence.FINDING_CAP_REACHED, 1, 7)
Profile = wp.WriterProfileIdentity
Capability = wp.WriterProfileCapability
Source = bundle.RunSource
Published = tuple[model.RunRecord, Path]
Found = tuple[SearchFinding, ...]
Observed = tuple[OverflowObservation, ...]
Capture = pytest.CaptureFixture[str]
Status, Cell, WRITE = wp.CapabilityStatus, CellResult, Verdict.WRITE_ERROR
Dependency, OverflowEvidence = evidence.DependencyVersion, model.OverflowEvidence
_HOSTILE = "kind`\n# injected\n[link](https://invalid)|<tag>\n```"
_FAILURES = (
    Cell("pyarrow", "1", "duckdb", "2", "compare", Verdict.VALUE_MISMATCH, "$", _HOSTILE, _HOSTILE),
    CellResult("duckdb", "2", "pyarrow", "1", "compare", Verdict.SCHEMA_MISMATCH, "$", "schema"),
    CellResult("polars", "3", "*", "*", "write", WRITE, "$", "failure", "ComputeError"),
)


def _pass(w: EngineVersion, r: EngineVersion, profile: Profile | None = None) -> CellResult:
    engines = (w.name, w.version, r.name, r.version)
    return CellResult(*engines, "compare", Verdict.PASS, "$", "", writer_profile=profile)


def _results(failures: tuple[CellResult, ...]) -> tuple[CellResult, ...]:
    cells = {(item.writer, item.reader): item for item in failures if item.operation != "write"}
    write_errors = {item.writer: item for item in failures if item.operation == "write"}
    results: list[CellResult] = []
    for writer in _ENGINES:
        if writer.name in write_errors:
            results.append(write_errors[writer.name])
            continue
        results.extend(
            cells.get((writer.name, reader.name), _pass(writer, reader)) for reader in _ENGINES
        )
    return tuple(results)


def _finding(result: CellResult, run: MatrixRun) -> SearchFinding:
    fingerprint = result.fingerprint or pytest.fail("failure fingerprint missing")
    return SearchFinding(_CASE, _CASE, fingerprint, result, run, 0, False, ReductionCounts())


def _evaluate(case: Case, directory: Path) -> MatrixRun:
    directory.mkdir(parents=True)
    files = [(writer, directory / f"{writer}.parquet") for writer in ("pyarrow", "duckdb")]
    for writer, path in files:
        path.write_bytes(f"PAR1{writer}PAR1".encode())
    return MatrixRun(case.case_id, _results(_FAILURES), tuple(files), _ENGINES, _ENGINES)


def _search_findings() -> tuple[SearchFinding, ...]:
    run = MatrixRun(_CASE.case_id, _results(_FAILURES), (), _ENGINES, _ENGINES)
    return tuple(_finding(result, run) for result in _FAILURES)


def _source(command: str = "check", stops: Observed = (), items: Found | None = None) -> Source:
    discovery = _CHECK if command == "check" else _CAPPED
    selected = _search_findings() if items is None else items
    env = evidence.EnvironmentEvidence("p", "h", "3", "x", _ENGINES, (Dependency("pyarrow", "1"),))
    return bundle.RunSource(command, selected, stops, _ENGINES, _ENGINES, discovery, env)


def _published(root: Path, name: str = "run", source: Source | None = None) -> Published:
    destination = root / name
    record = bundle.publish_run(_source() if source is None else source, destination, _evaluate)
    return record or pytest.fail("run publication returned no record"), destination


def test_run_publishes_three_children_with_complete_hash_chain(tmp_path: Path) -> None:
    record, destination = _published(tmp_path)
    assert record.environment.providers == record.writers == record.readers
    assert {path.name for path in destination.iterdir()} == {"run.json", "REPORT.md", "findings"}
    fingerprints = [item.fingerprint for item in record.findings]
    assert fingerprints == sorted(fingerprints, key=lambda item: item.canonical_bytes())
    assert len(record.findings) == 3
    for item in record.findings:
        manifest = destination / item.manifest_path
        payload = manifest.read_bytes()
        assert item.byte_count == len(payload)
        assert item.sha256 == hashlib.sha256(payload).hexdigest()
        child = validate_bundle(manifest.parent)
        assert child.finding.finding_id == item.finding_id
        assert (len(child.matrix.results), len(child.matrix.selection_order)) == (7, 3)
    payload = (destination / "run.json").read_bytes()
    assert payload == canonical_bytes(json.loads(payload))
    child, extracted = next((destination / "findings").iterdir()), tmp_path / "extracted-child"
    shutil.copytree(child, extracted)
    shutil.rmtree(destination)
    validated = validate_bundle(extracted)
    assert (validated.finding.finding_id, validated.case) == (child.name, _CASE)
    overflow_result = CellResult("pyarrow", "1", "*", "*", "write", WRITE, "$", "x", "ArrowInvalid")
    fingerprint = overflow_result.fingerprint or pytest.fail("overflow fingerprint missing")
    overflow = (OverflowObservation(_CASE.case_id, fingerprint, _CASE, overflow_result),)
    record, destination = _published(tmp_path, "capped", _source(command="fuzz", stops=overflow))
    assert record.status == _CAPPED.stop_reason and record.overflow[0].fingerprint == fingerprint
    report = (destination / "REPORT.md").read_text()
    assert all(x in report for x in ("## Run scope", "## Inputs", "| Discovery |", "### C1"))
    hostile = ("\n# injected", "[link](https://invalid)", "<tag>", "\\n```", " [default]")
    assert not any(value in report for value in hostile)
    destination = tmp_path / "none"
    assert bundle.publish_run(_source(items=()), destination, _evaluate) is None
    assert not destination.exists()
    destination.mkdir()
    (destination / "owned.txt").write_text("preserve")
    with pytest.raises(bundle.RunPublicationError):
        bundle.publish_run(_source(), destination, _evaluate)
    assert (destination / "owned.txt").read_text() == "preserve"
    unplanned = tmp_path / "unplanned"
    with pytest.raises(bundle.RunPublicationError, match="unindexed fingerprint"):
        bundle.publish_run(_source(items=(_search_findings()[0],)), unplanned, _evaluate)
    assert not unplanned.exists()


def test_run_replay_aggregates_in_fingerprint_order(tmp_path: Path, capsys: Capture) -> None:
    _, destination = _published(tmp_path)
    related = replace(_FAILURES[1], detail="changed normalized detail")

    def replay_evaluator(case: Case, directory: Path) -> MatrixRun:
        del directory
        return MatrixRun(case.case_id, _results((_FAILURES[0], related)), (), _ENGINES, _ENGINES)

    outcome = replay.replay_run(destination, replay_evaluator)
    assert (outcome.exact_count, outcome.related_count, outcome.absent_count) == (1, 1, 1)
    fingerprints = [item.finding.fingerprint for item in outcome.outcomes]
    assert fingerprints == sorted(fingerprints, key=lambda item: item.canonical_bytes())
    last_child = sorted((destination / "findings").iterdir())[-1]
    (last_child / "REPORT.md").write_text("tampered")
    calls = 0

    def forbidden(case: Case, directory: Path) -> MatrixRun:
        nonlocal calls
        calls += 1
        raise AssertionError((case, directory))

    with pytest.raises(bundle.RunBundleValidationError):
        replay.replay_run(destination, forbidden)
    assert calls == 0

    def capability(item: EngineVersion, value: dict[str, int] | None) -> Capability:
        if value is None:
            return Capability(item, "row-group-2", Status.UNSUPPORTED, None, "OPTION_UNAVAILABLE")
        return Capability(item, "row-group-2", Status.SUPPORTED, Profile("row-group-2", value))

    changes = {
        "addition": ({"row_group_size": 2}, {"historical_group_size": 2}, {"row_group_size": 2}),
        "removal": (None, {"historical_group_size": 2}, {"row_group_size": 2}),
        "options": ({"historical_group_size": 3}, None, {"row_group_size": 2}),
    }
    for change, options in changes.items():
        capabilities = tuple(capability(*pair) for pair in zip(_ENGINES, options, strict=True))
        plan = wp.WriterProfilePlan(("row-group-2",), capabilities)
        polars_profile = capabilities[2].profile_identity or pytest.fail("profile missing")
        profiled_failure = replace(_FAILURES[2], writer_profile=polars_profile)
        results = tuple(
            (_FAILURES[2] if execution.writer_profile is None else profiled_failure)
            if execution.writer == _ENGINES[2]
            else _pass(execution.writer, _ENGINES[0], execution.writer_profile)
            for execution in plan.executions(_ENGINES)
        )
        matrix = MatrixRun(_CASE.case_id, results, (), _ENGINES, (_ENGINES[0],), plan)
        observed = tuple(_finding(result, matrix) for result in (_FAILURES[2], profiled_failure))
        source = replace(_source(items=observed), readers=(_ENGINES[0],), writer_profiles=plan)
        target = tmp_path / change
        assert bundle.publish_run(source, target, lambda _case, _path, run=matrix: run) is not None
        value = bundle.validate_run(target)
        assert value.run.writer_profiles == value.children[0].finding.writer_profiles == plan
        children = value.children
        child_reports = "".join((child.directory / "REPORT.md").read_text() for child in children)
        for report in ((target / "REPORT.md").read_text(), child_reports):
            assert "polars [default]" in report and "polars [row-group-2]" in report
        assert cli.main(["replay", str(target)]) == 2
        payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
        assert cast(dict[str, object], payload["error"])["kind"] == ("WRITER_PROFILE_NOT_EVALUABLE")


@pytest.mark.parametrize("shape", ("file", "extra", "link", "run", "findings", "digest", "report"))
def test_run_root_inventory_rejects_wrong_types(tmp_path: Path, shape: str) -> None:
    destination = tmp_path / "run"
    if shape == "file":
        destination.write_text("not a directory")
    else:
        bundle.publish_run(_source(), destination, _evaluate)
        if shape == "extra":
            (destination / "extra").write_text("unexpected")
        elif shape == "link":
            target = tmp_path / "report"
            (destination / "REPORT.md").rename(target)
            (destination / "REPORT.md").symlink_to(target)
        elif shape == "run":
            (destination / "run.json").unlink()
            (destination / "run.json").mkdir()
        elif shape == "findings":
            shutil.rmtree(destination / "findings")
            (destination / "findings").write_text("not a directory")
        elif shape == "digest":
            path = destination / "run.json"
            data = cast(dict[str, object], json.loads(path.read_bytes()))
            cast(list[dict[str, object]], data["findings"])[0]["sha256"] = "0" * 64
            path.write_bytes(canonical_bytes(data))
        else:
            payload = b"# arbitrary but resealed\n"
            (destination / "REPORT.md").write_bytes(payload)
            manifest = destination / "run.json"
            run = model.RunRecord.from_json(manifest.read_bytes())
            digest = model.RunDigest("REPORT.md", hashlib.sha256(payload).hexdigest(), len(payload))
            manifest.write_bytes(replace(run, report=digest).canonical_bytes())
    with pytest.raises(bundle.RunBundleValidationError):
        bundle.validate_run(destination)


@pytest.mark.parametrize("shape", ("extra", "symlink", "digest", "conflict", "noncanonical"))
def test_run_rejects_bad_child_inventory(tmp_path: Path, shape: str) -> None:
    record, destination = _published(tmp_path, shape)
    child = next((destination / "findings").iterdir())
    if shape == "extra":
        (child.parent / "extra").mkdir()
    elif shape == "symlink":
        target = tmp_path / "child"
        child.rename(target)
        child.symlink_to(target, target_is_directory=True)
    elif shape == "digest":
        manifest = child / "finding.json"
        manifest.write_bytes(bytes(((payload := manifest.read_bytes())[0] ^ 1,)) + payload[1:])
    elif shape == "conflict":
        manifest = child / "finding.json"
        data = cast(dict[str, object], json.loads(manifest.read_bytes()))
        cast(dict[str, object], data["environment"])["platform"] = "conflicted"
        payload = canonical_bytes(data)
        manifest.write_bytes(payload)
        position = [item.finding_id for item in record.findings].index(child.name)
        indexed = replace(
            record.findings[position],
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_count=len(payload),
        )
        indexes = (*record.findings[:position], indexed, *record.findings[position + 1 :])
        identity = (record.command, record.status, record.writers, record.readers)
        evidence = (record.discovery, record.environment, indexes, record.overflow)
        changed = replace(
            record, findings=indexes, run_id=model.calculate_run_id(*identity, *evidence)
        )
        (destination / "run.json").write_bytes(changed.canonical_bytes())
    else:
        manifest = destination / "run.json"
        manifest.write_text(json.dumps(json.loads(manifest.read_bytes()), indent=2))
    with pytest.raises(bundle.RunBundleValidationError):
        bundle.validate_run(destination)


def test_run_model_rejects_conflicting_identity_order_status_and_digests(tmp_path: Path) -> None:
    record, _ = _published(tmp_path)
    rejected = partial(pytest.raises, model.RunValidationError)
    indexed = record.findings[0]
    duplicate = replace(
        indexed,
        finding_id=(duplicate_id := finding_id_for(other_case := "1" * 64, indexed.fingerprint)),
        case_id=other_case,
        manifest_path=f"findings/{duplicate_id}/finding.json",
    )
    overlap = OverflowEvidence(_CASE, _FAILURES[0], _CAPPED.stop_reason)
    changes = ({"command": "bad"}, {"findings": ()}, {"status": evidence.FINDING_CAP_REACHED})
    changes += ({"overflow": (overlap,)}, {"overflow": (overlap, overlap)}, {"run_id": "0" * 64})
    changes += ({"findings": tuple(reversed(record.findings))},)
    changes += ({"findings": (indexed, indexed)}, {"findings": (indexed, duplicate)})
    for change in changes:
        rejected(replace, record, **change)
    digest_changes = ((record.report, "path", "unknown"), (record.report, "sha256", "bad"))
    digest_changes += ((record.report, "byte_count", -1), (indexed, "finding_id", "0" * 64))
    digest_changes += ((indexed, "manifest_path", "finding.json"), (indexed, "sha256", "bad"))
    digest_changes += ((indexed, "byte_count", -1),)
    for target, name, value in digest_changes:
        rejected(replace, target, **{name: value})
    rejected(replace, overlap, stop_reason="bad")
    with pytest.raises(ValueError):
        type(record).from_data({**record.to_data(), "extra": True})
    rejected(type(record).from_json, b"{")
    providers = record.environment.providers
    variants = (
        (record.readers, providers[:-1]),
        (record.readers, (*providers, EngineVersion("extra", "1"))),
        (record.readers, (providers[0], replace(providers[1], version="9"), *providers[2:])),
        ((replace(record.readers[0], name="other"), *record.readers[1:]), providers),
    )
    for readers, inventory in variants:
        environment = replace(record.environment, providers=inventory)
        rejected(replace, record, readers=readers, environment=environment)
        data = record.to_data()
        data["readers"] = [engine.to_data() for engine in readers]
        data["environment"] = environment.to_data()
        rejected(type(record).from_json, json.dumps(data))

    def identified(**changes: object) -> dict[str, object]:
        data = {**record.to_data(), **changes}
        identity = {
            key: value for key, value in data.items() if key not in ("format", "run_id", "report")
        }
        data["run_id"] = hashlib.sha256(canonical_bytes(identity)).hexdigest()
        return data

    writers = [engine.to_data() for engine in record.writers]
    readers = [engine.to_data() for engine in record.readers]
    example = evidence.DiscoveryEvidence(10, 0, 3, evidence.EXAMPLE_BOUND_REACHED)
    invalid: list[dict[str, object]] = []
    for role, engines in (("writers", writers), ("readers", readers)):
        invalid.extend((identified(**{role: list[object]()}), identified(**{role: engines[1:]})))
        invalid.append(identified(**{role: [*engines, engines[0]]}))
    invalid.extend((identified(discovery=example.to_data()), identified(command="fuzz")))
    for data in invalid:
        rejected(type(record).from_json, json.dumps(data))
    rejected(replace, record, writers=(), run_id=cast(str, invalid[0]["run_id"]))
    cap = evidence.DiscoveryEvidence(10, 0, 3, evidence.FINDING_CAP_REACHED)
    outside = replace(_FAILURES[0], writer="outside", writer_version="9")
    target = next(item for item in _FAILURES if item.reader != "*")
    wildcard = replace(target, reader="*", reader_version="*")
    for result in (outside, wildcard):
        overflow = (OverflowEvidence(_CASE, result, _CAPPED.stop_reason),)
        replay_changes: dict[str, object] = {
            "command": "fuzz",
            "status": evidence.FINDING_CAP_REACHED,
            "discovery": cap.to_data(),
            "overflow": [item.to_data() for item in overflow],
        }
        data = identified(**replay_changes)
        replay_changes.update(discovery=cap, overflow=overflow, run_id=cast(str, data["run_id"]))
        rejected(replace, record, **replay_changes)
