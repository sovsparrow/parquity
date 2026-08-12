import hashlib
import json
import shutil
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from parquity import cli
from parquity import profiles as wp
from parquity.evidence import EngineVersion
from parquity.evidence.json_codec import canonical_bytes
from parquity.findings import bundle as finding_bundle
from parquity.findings import model as fm
from parquity.generation import evidence
from parquity.generation.search.identity import finding_key
from parquity.generation.search.records import OverflowObservation
from parquity.model import Case
from parquity.runs import bundle, replay
from parquity.runs.formats import v1 as model
from parquity.verdicts import CellResult, MatrixRun, Verdict
from tests.support import generated_run as fixtures

_CASE, _ENGINES = fixtures.CASE, fixtures.ENGINES
_CAPPED, _FAILURES = fixtures.CAPPED, fixtures.FAILURES
_evaluate, _finding = fixtures.evaluate, fixtures.finding
_pass, _results, _source = fixtures.pass_result, fixtures.results, fixtures.source
published_run = fixtures.published_run
Profile = wp.WriterProfileIdentity
Capability = wp.WriterProfileCapability
Status, Cell, WRITE = wp.CapabilityStatus, CellResult, Verdict.WRITE_ERROR
Phase = bundle.RunPublicationPhase


def test_run_publishes_three_children_with_complete_hash_chain(tmp_path: Path) -> None:
    events: list[bundle.RunPublicationProgress] = []

    def progress(value: bundle.RunPublicationProgress) -> None:
        events.append(value)

    current = bundle.publish_run(_source(), tmp_path / "run", _evaluate, progress)
    assert current is not None
    record, destination = current.run, current.directory
    assert [item.phase for item in events] == [Phase.WRITING] * 4 + [Phase.FINALIZING]
    assert [item.completed_findings for item in events] == [0, 1, 2, 3, 3]
    assert {item.total_findings for item in events} == {3}
    assert record.environment.providers == record.writers == record.readers
    assert {path.name for path in destination.iterdir()} == {"run.json", "REPORT.md", "findings"}
    current = bundle.validate_run(destination)
    raw = (destination / "REPORT.md").read_bytes()
    assert (len(raw), hashlib.sha256(raw).hexdigest()) == (
        record.report.byte_count,
        record.report.sha256,
    )
    fingerprints = [item.fingerprint for item in record.findings]
    assert fingerprints == sorted(fingerprints, key=lambda item: item.canonical_bytes())
    assert len(record.findings) == 3
    for item in record.findings:
        manifest = destination / item.manifest_path
        payload = manifest.read_bytes()
        assert (item.byte_count, item.sha256) == (len(payload), hashlib.sha256(payload).hexdigest())
        child = finding_bundle.validate_bundle(manifest.parent)
        assert (child.finding.finding_id, len(child.matrix.results)) == (item.finding_id, 7)
        assert len(child.matrix.selection_order) == 3
    payload = (destination / "run.json").read_bytes()
    assert payload == canonical_bytes(json.loads(payload))
    child, extracted = next((destination / "findings").iterdir()), tmp_path / "extracted-child"
    shutil.copytree(child, extracted)
    shutil.rmtree(destination)
    validated = finding_bundle.validate_bundle(extracted)
    assert (validated.finding.finding_id, validated.case) == (child.name, _CASE)


def test_run_overflow_evidence_and_publication_failures(tmp_path: Path) -> None:
    overflow_result = Cell("pyarrow", "1", "*", "*", "write", WRITE, "$", "x", "ArrowInvalid")
    fingerprint = overflow_result.fingerprint or pytest.fail("overflow fingerprint missing")
    overflow = (OverflowObservation(_CASE, overflow_result, evidence.DISCOVERY_OVERFLOW),)
    record, _ = published_run(tmp_path, "capped", _source(command="fuzz", stops=overflow))
    assert record.status == _CAPPED.stop_reason and record.overflow[0].fingerprint == fingerprint
    assert record.status == evidence.SAVED_EVIDENCE_LIMIT_REACHED
    assert record.to_data()["status"] == "FINDING_CAP_REACHED"
    assert record.overflow[0].to_data()["stop_reason"] == "FINDING_CAP_REACHED"
    assert model.RunRecord.from_data(record.to_data()) == record
    planned = replace(_FAILURES[1], schema_path="$schema.field_1")
    exact_sibling = replace(planned, schema_path="$schema.field_2")
    planned_fingerprint = planned.fingerprint or pytest.fail("planned fingerprint missing")
    sibling_fingerprint = exact_sibling.fingerprint or pytest.fail("sibling fingerprint missing")
    assert planned_fingerprint != sibling_fingerprint
    assert finding_key(planned_fingerprint) == finding_key(sibling_fingerprint)
    planned_overflow = (OverflowObservation(_CASE, planned, evidence.DISCOVERY_OVERFLOW),)
    selected = (_source().findings[0],)
    planned_source = _source(command="fuzz", stops=planned_overflow, items=selected)

    def sibling_evaluator(case: Case, directory: Path) -> MatrixRun:
        run = _evaluate(case, directory)
        return replace(run, results=_results((_FAILURES[0], exact_sibling)))

    accepted = bundle.publish_run(planned_source, tmp_path / "planned-sibling", sibling_evaluator)
    assert accepted is not None
    novel = replace(exact_sibling, detail="novel exact diagnostic")

    def novel_evaluator(case: Case, directory: Path) -> MatrixRun:
        run = _evaluate(case, directory)
        return replace(run, results=_results((_FAILURES[0], novel)))

    with pytest.raises(bundle.RunPublicationError, match="unplanned finding"):
        bundle.publish_run(planned_source, tmp_path / "unplanned", novel_evaluator)
    assert not (tmp_path / "unplanned").exists()


def test_run_replay_and_profile_drift(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, destination = published_run(tmp_path, "current", _source(version="0.1.1"))
    related = replace(_FAILURES[1], detail="changed normalized detail")
    evaluated = _results((_FAILURES[0], related))

    def evaluator(case: Case, _: Path) -> MatrixRun:
        return MatrixRun(case.case_id, evaluated, (), _ENGINES, _ENGINES)

    outcome = replay.replay_run(destination, evaluator)
    assert (outcome.exact_count, outcome.related_count, outcome.absent_count) == (1, 1, 1)
    validated = bundle.validate_run(destination)
    assert tuple(item.finding.finding_id for item in outcome.outcomes) == tuple(
        item.finding_id for item in validated.run.findings
    )
    expected = {
        _FAILURES[0].fingerprint: "REPRODUCED",
        _FAILURES[1].fingerprint: "RELATED_FAILURE",
        _FAILURES[2].fingerprint: "NOT_REPRODUCED",
    }
    assert tuple(item.classification.value for item in outcome.outcomes) == tuple(
        expected[item.fingerprint] for item in validated.run.findings
    )
    (sorted((destination / "findings").iterdir())[-1] / "REPORT.md").write_text("tampered")
    calls = 0

    def forbidden(case: Case, directory: Path) -> MatrixRun:
        nonlocal calls
        calls += 1
        return _evaluate(case, directory)

    with pytest.raises(bundle.RunBundleValidationError):
        replay.replay_run(destination, forbidden)
    assert calls == 0

    def capability(item: EngineVersion, value: dict[str, int] | None) -> Capability:
        if value is None:
            return Capability(item, "row-group-2", Status.UNSUPPORTED, None, "OPTION_UNAVAILABLE")
        return Capability(item, "row-group-2", Status.SUPPORTED, Profile("row-group-2", value))

    options = ({"historical_group_size": 3}, None, {"row_group_size": 2})
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
    target = tmp_path / "profile-drift"
    assert bundle.publish_run(source, target, lambda _case, _path: matrix) is not None
    value = bundle.validate_run(target)
    assert value.run.writer_profiles == value.children[0].finding.writer_profiles == plan
    assert cli.main(["replay", str(target)]) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert cast(dict[str, object], payload["error"])["kind"] == "WRITER_PROFILE_NOT_EVALUABLE"


@pytest.mark.parametrize(
    "shape",
    (
        "file",
        "extra",
        "link",
        "run",
        "findings",
        "digest",
        "noncanonical",
        "child-extra",
        "child-link",
    ),
)
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
        elif shape == "noncanonical":
            path = destination / "run.json"
            path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2))
        elif shape == "child-extra":
            (destination / "findings" / "unexpected").mkdir()
        else:
            child = next((destination / "findings").iterdir())
            external = tmp_path / "external-child"
            child.rename(external)
            child.symlink_to(external, target_is_directory=True)
    with pytest.raises(bundle.RunBundleValidationError) as raised:
        bundle.validate_run(destination)
    assert raised.value.kind == "INVALID_BUNDLE"


def test_run_model_rejects_conflicting_identity_order_status_and_digests(tmp_path: Path) -> None:
    record, _ = published_run(tmp_path)
    rejected = partial(pytest.raises, model.RunValidationError)
    indexed = record.findings[0]
    duplicate = replace(
        indexed,
        finding_id=(duplicate_id := fm.finding_id_for(other_case := "1" * 64, indexed.fingerprint)),
        case_id=other_case,
        manifest_path=f"findings/{duplicate_id}/finding.json",
    )
    overlap = model.OverflowEvidence(_CASE, _FAILURES[0], _CAPPED.stop_reason)
    changes = (
        {"command": "bad"},
        {"findings": ()},
        {"status": evidence.SAVED_EVIDENCE_LIMIT_REACHED},
    )
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
        omitted = ("format", "run_id", "report")
        identity = {key: value for key, value in data.items() if key not in omitted}
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
    cap = evidence.DiscoveryEvidence(10, 0, 3, evidence.SAVED_EVIDENCE_LIMIT_REACHED)
    outside = replace(_FAILURES[0], writer="outside", writer_version="9")
    overflow = (model.OverflowEvidence(_CASE, outside, _CAPPED.stop_reason),)
    replay_changes: dict[str, object] = {"command": "fuzz", "status": cap.stop_reason}
    overflow_data = [item.to_data() for item in overflow]
    replay_changes.update(discovery=cap.to_data(), overflow=overflow_data)
    data = identified(**replay_changes)
    replay_changes.update(discovery=cap, overflow=overflow, run_id=cast(str, data["run_id"]))
    rejected(replace, record, **replay_changes)
