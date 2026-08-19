from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from functools import partial
from importlib import metadata
from pathlib import Path
from typing import cast

import pytest

from parquity import cli
from parquity import profiles as wp
from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.findings.bundle import (
    BundlePublicationError,
    BundleValidationError,
    FindingSource,
    build_bundle,
    validate_bundle,
)
from parquity.findings.model import ReductionEvidence, ReplaySignature
from parquity.findings.replay import ReplayClassification
from parquity.findings.replay import replay_validated_bundle as replay
from parquity.generation.evidence import CHECK_COMPLETE, DiscoveryEvidence
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, MatrixRun, Verdict
from tests.support import symlinks_available

Capability = wp.WriterProfileCapability


def _case(*, extra_field: bool = False) -> Case:
    field = Field("value", TypeSpec(Kind.INT32), nullable=False)
    if extra_field:
        extra = Field("extra", TypeSpec(Kind.STRING), nullable=False)
        return Case((field, extra), ((1, "remove"),))
    return Case((field,), ((1,),))


def _result(
    *,
    writer_version: str = "1",
    reader_version: str = "2",
    detail: str = "controlled mismatch",
    diagnostic_kind: str = "VALUE_MISMATCH",
) -> CellResult:
    engines = ("pyarrow", writer_version, "duckdb", reader_version)
    values = (*engines, "compare", Verdict.VALUE_MISMATCH, "$rows[0].value", detail)
    return CellResult(*values, diagnostic_kind)


def _versions() -> tuple[tuple[EngineVersion, ...], tuple[EngineVersion, ...]]:
    return (EngineVersion("pyarrow", "1"),), (EngineVersion("duckdb", "2"),)


def _capability(writer: EngineVersion, options: dict[str, int] | None) -> Capability:
    if options is None:
        status = wp.CapabilityStatus.UNSUPPORTED
        return Capability(writer, "row-group-2", status, None, wp.OPTION_UNAVAILABLE)
    profile = wp.WriterProfileIdentity("row-group-2", options)
    return Capability(writer, "row-group-2", wp.CapabilityStatus.SUPPORTED, profile)


def _historical_plan(change: str, writers: tuple[EngineVersion, ...]) -> wp.WriterProfilePlan:
    options = {
        "addition": ({"row_group_size": 2}, {"historical_group_size": 2}),
        "removal": (None, {"historical_group_size": 2}),
        "options": ({"historical_group_size": 3}, None),
    }[change]
    pairs = zip(writers, options, strict=True)
    capabilities = tuple(_capability(writer, option) for writer, option in pairs)
    return wp.WriterProfilePlan(("row-group-2",), capabilities)


def _passing(writer: EngineVersion, profile: wp.WriterProfileIdentity | None) -> CellResult:
    engines = (writer.name, writer.version, "duckdb", "2")
    return CellResult(*engines, "compare", Verdict.PASS, "$", "match", writer_profile=profile)


def _historical_evaluate(
    case: Case, directory: Path, plan: wp.WriterProfilePlan, writers: tuple[EngineVersion, ...]
) -> MatrixRun:
    directory.mkdir(parents=True)
    artifact = directory / "pyarrow.parquet"
    artifact.write_bytes(b"PAR1controlled-inputPAR1")
    executions = plan.executions(writers)
    results = (_result(), *(_passing(item.writer, item.writer_profile) for item in executions[1:]))
    readers = (EngineVersion("duckdb", "2"),)
    return MatrixRun(case.case_id, results, (("pyarrow", artifact),), writers, readers, plan)


def _source(*, discovered: Case | None = None) -> FindingSource:
    case = _case()
    discovered_case = case if discovered is None else discovered
    result = _result()
    fingerprint = result.fingerprint
    assert fingerprint is not None
    writers, readers = _versions()
    discovery = DiscoveryEvidence(None, None, None, CHECK_COMPLETE)
    dependencies = (DependencyVersion("pyarrow", "1"),)
    environment = EnvironmentEvidence("p", "h", "3", "x", (*writers, *readers), dependencies)
    changed = int(discovered_case.case_id != case.case_id)
    reduction = ReductionEvidence(discovered_case.case_id, case.case_id, False, changed, 0, 0, 0, 0)
    identity = (case, discovered_case, fingerprint, "check", writers, readers)
    return FindingSource(*identity, discovery, environment, reduction)


def _evaluate(case: Case, directory: Path) -> MatrixRun:
    directory.mkdir(parents=True)
    parquet = directory / "pyarrow.parquet"
    parquet.write_bytes(b"PAR1controlled-inputPAR1")
    result = _result(detail=f"controlled   mismatch\ninside {directory}")
    writers, readers = _versions()
    return MatrixRun(case.case_id, (result,), (("pyarrow", parquet),), writers, readers)


def _build(destination: Path, *, discovered: Case | None = None) -> None:
    def evaluator(case: Case, directory: Path) -> MatrixRun:
        run = _evaluate(case, directory)
        target = run.failures[0]
        return replace(run, results=(replace(target, detail="controlled mismatch"),))

    build_bundle(_source(discovered=discovered), destination, evaluator)


def _replace_artifact(directory: Path, name: str, payload: bytes) -> None:
    (directory / name).write_bytes(payload)
    path = directory / "finding.json"
    manifest = cast(dict[str, object], json.loads(path.read_bytes()))
    artifacts = cast(list[dict[str, object]], manifest["artifacts"])
    artifact = next(item for item in artifacts if item["name"] == name)
    artifact.update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    manifest_text = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_bytes(manifest_text.encode())


def test_child_inventory_hash_chain_and_matrix_are_verified(tmp_path: Path) -> None:
    destination = tmp_path / "finding"
    _build(destination)
    expected = {"finding.json", "REPORT.md", "case.json", "matrix.json"}
    expected |= {"reproduce.py", "upstream_repro.py", "input.parquet"}
    assert {path.name for path in destination.iterdir()} == expected
    manifest_payload = (destination / "finding.json").read_bytes()
    decoded = cast(dict[str, object], json.loads(manifest_payload))
    canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert manifest_payload == canonical.encode()
    artifacts = cast(list[dict[str, object]], decoded["artifacts"])
    assert "finding.json" not in {item["name"] for item in artifacts}
    for artifact in artifacts:
        payload = (destination / cast(str, artifact["name"])).read_bytes()
        assert artifact["bytes"] == len(payload)
        assert artifact["sha256"] == hashlib.sha256(payload).hexdigest()
    matrix = cast(dict[str, object], json.loads((destination / "matrix.json").read_bytes()))
    assert matrix["format"] == "parquity.matrix.v1"
    lengths = tuple(len(cast(list[object], matrix[key])) for key in ("results", "selection_order"))
    assert lengths == (1, 1)


def test_child_bytes_and_discovered_case(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _build(first)
    _build(second)

    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }
    reduced = tmp_path / "reduced"
    _build(reduced, discovered=_case(extra_field=True))
    expected = _case(extra_field=True).canonical_bytes()
    assert (reduced / "discovered_case.json").read_bytes() == expected


def test_publication_refuses_existing_targets_before_evaluation(tmp_path: Path) -> None:
    existing_file = tmp_path / "existing-file"
    existing_file.write_bytes(b"owned")
    existing_directory = tmp_path / "existing-directory"
    existing_directory.mkdir()

    def forbidden(case: Case, directory: Path) -> MatrixRun:
        raise AssertionError((case, directory))

    for destination in (existing_file, existing_directory):
        with pytest.raises(BundlePublicationError):
            build_bundle(_source(), destination, forbidden)
    assert existing_file.read_bytes() == b"owned"
    writers, readers = _versions()
    run = MatrixRun(_case().case_id, (_result(),), (), writers, readers)
    with pytest.raises(RuntimeError):
        build_bundle(_source(), tmp_path / "invalid", lambda case, path: run)
    escaped = tmp_path / "escaped"

    def escape(case: Case, directory: Path) -> MatrixRun:
        directory.mkdir(parents=True)
        (directory.parent / "outside.parquet").write_bytes(b"PAR1outsidePAR1")
        writers, readers = _versions()
        path = directory / ".." / "outside.parquet"
        return MatrixRun(case.case_id, (_result(),), (("pyarrow", path),), writers, readers)

    with pytest.raises(RuntimeError, match="outside the evaluation directory"):
        build_bundle(_source(), escaped, escape)
    profile = _capability(writers[0], {"row_group_size": 2})
    plan = wp.WriterProfilePlan(("row-group-2",), (profile,))
    with pytest.raises(RuntimeError, match="conflicting writer profile plan"):
        build_bundle(replace(_source(), writer_profiles=plan), tmp_path / "profile", _evaluate)


def test_invalid_payload_shapes_fail_validation(tmp_path: Path) -> None:
    mutations = ("missing", "missing-manifest", "extra")
    mutations += ("report", "noncanonical", "nested")
    if symlinks_available(tmp_path):
        # Windows refuses to create one without Developer Mode or elevation, and the mutation is
        # about what validation rejects rather than about what the filesystem will let a test build.
        mutations += ("symlink",)
    for mutation in mutations:
        destination = tmp_path / mutation
        _build(destination)
        if mutation == "missing":
            (destination / "REPORT.md").unlink()
        elif mutation == "missing-manifest":
            (destination / "finding.json").unlink()
        elif mutation == "extra":
            (destination / "extra.txt").write_text("extra", encoding="utf-8")
        elif mutation == "report":
            (destination / "REPORT.md").write_bytes(b"# unsealed tamper\n")
        elif mutation == "noncanonical":
            path = destination / "finding.json"
            path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2), encoding="utf-8")
        elif mutation == "nested":
            (destination / "nested").mkdir()
        else:
            external = tmp_path / "external.md"
            external.write_text("external", encoding="utf-8")
            (destination / "REPORT.md").unlink()
            (destination / "REPORT.md").symlink_to(external)
        with pytest.raises(BundleValidationError) as caught:
            validate_bundle(destination)
        if mutation == "report":
            assert (caught.value.kind, caught.value.detail) == (
                "INVALID_BUNDLE",
                "artifact evidence does not match",
            )


def test_canonical_payloads_with_conflicting_identity_are_rejected(tmp_path: Path) -> None:
    for mutation in ("matrix-noncanonical", "case", "discovered", "matrix"):
        destination = tmp_path / mutation
        _build(
            destination, discovered=_case(extra_field=True) if mutation == "discovered" else None
        )
        if mutation == "matrix-noncanonical":
            data = json.loads((destination / "matrix.json").read_bytes())
            _replace_artifact(destination, "matrix.json", json.dumps(data, indent=2).encode())
        elif mutation == "case":
            _replace_artifact(destination, "case.json", _case(extra_field=True).canonical_bytes())
        elif mutation == "discovered":
            _replace_artifact(destination, "discovered_case.json", _case().canonical_bytes())
        else:
            data = cast(dict[str, object], json.loads((destination / "matrix.json").read_bytes()))
            data["case_id"] = "0" * 64
            payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            _replace_artifact(destination, "matrix.json", payload)
        with pytest.raises(BundleValidationError):
            validate_bundle(destination)
    signature = ReplaySignature.from_result(_result())
    data = signature.to_data()
    assert ReplaySignature.from_data(data) == signature
    profile = wp.WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    profiled = replace(signature, writer_profile=profile)
    assert ReplaySignature.from_data(profiled.to_data(), allow_profile=True) == profiled
    invalid = [{**data, key: "forbidden"} for key in ("writer_version", "reader_version", "extra")]
    invalid.extend(
        ({key: value for key, value in data.items() if key != "reader"}, profiled.to_data())
    )
    for document in invalid:
        with pytest.raises(ValueError):
            ReplaySignature.from_data(document)


def test_replay_classifies_version_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "finding"
    _build(destination)
    dependency_versions: dict[str, str | None] = {"pyarrow": "1"}

    def dependency_version(package: str) -> str:
        current = dependency_versions[package]
        if current is None:
            raise metadata.PackageNotFoundError(package)
        return current

    monkeypatch.setattr("parquity.findings.replay.metadata.version", dependency_version)

    def evaluator(result: CellResult):
        def evaluate(case: Case, directory: Path) -> MatrixRun:
            del directory
            writers = (EngineVersion("pyarrow", result.writer_version),)
            readers = (EngineVersion("duckdb", result.reader_version),)
            return MatrixRun(case.case_id, (result,), (), writers, readers)

        return evaluate

    validated = validate_bundle(destination)
    exact = replay(validated, evaluator(_result(writer_version="9", reader_version="8")))
    dependency_versions["pyarrow"] = "9"
    related = replay(validated, evaluator(_result(detail="controlled mismatch 7")))
    dependency_versions["pyarrow"] = None
    absent = replay(validated, evaluator(_result(diagnostic_kind="DifferentError")))
    assert exact.classification is ReplayClassification.REPRODUCED
    drift = [(item.original, item.current) for item in exact.version_drift]
    assert drift == [("1", "9"), ("2", "8")]
    assert related.classification is ReplayClassification.RELATED_FAILURE
    assert absent.classification is ReplayClassification.NOT_REPRODUCED
    dependency = exact.dependency_evidence[0]
    assert (dependency.original, dependency.current, dependency.available) == ("1", "1", True)
    assert [(x.original, x.current) for x in related.dependency_drift] == [("1", "9")]
    assert [(x.current, x.available) for x in absent.dependency_evidence] == [(None, False)]


def test_historical_profile_plans_validate_before_replay_admission(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for change in ("addition", "removal", "options"):
        writers = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
        plan = _historical_plan(change, writers)
        source = replace(_source(), writers=writers, writer_profiles=plan)
        historical = tmp_path / change
        historical_evaluator = partial(_historical_evaluate, plan=plan, writers=writers)
        build_bundle(source, historical, historical_evaluator)
        assert validate_bundle(historical).finding.writer_profiles == plan
        assert cli.main(["replay", str(historical)]) == 2
        payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
        assert cast(dict[str, object], payload["error"])["kind"] == ("WRITER_PROFILE_NOT_EVALUABLE")
