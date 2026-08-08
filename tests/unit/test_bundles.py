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
from parquity.findings.bundle import (
    BundlePublicationError,
    BundleValidationError,
    FindingSource,
    publish_bundle,
    validate_bundle,
)
from parquity.findings.evidence import (
    CHECK_COMPLETE,
    DependencyVersion,
    DiscoveryEvidence,
    EnvironmentEvidence,
    ReductionEvidence,
)
from parquity.findings.identity import ReplaySignature
from parquity.findings.replay import ReplayClassification, replay_bundle
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict
from parquity.writer_profiles import (
    OPTION_UNAVAILABLE,
    CapabilityStatus,
    WriterProfileCapability,
    WriterProfileIdentity,
    WriterProfilePlan,
)


def _case(*, extra_field: bool = False) -> Case:
    fields = [Field("value", TypeSpec(Kind.INT32), nullable=False)]
    if extra_field:
        fields.append(Field("extra", TypeSpec(Kind.STRING), nullable=False))
        return Case(tuple(fields), ((1, "remove"),))
    return Case(tuple(fields), ((1,),))


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


def _capability(writer: EngineVersion, options: dict[str, int] | None) -> WriterProfileCapability:
    if options is None:
        status = CapabilityStatus.UNSUPPORTED
        return WriterProfileCapability(writer, "row-group-2", status, None, OPTION_UNAVAILABLE)
    profile = WriterProfileIdentity("row-group-2", options)
    return WriterProfileCapability(writer, "row-group-2", CapabilityStatus.SUPPORTED, profile)


def _historical_plan(change: str, writers: tuple[EngineVersion, ...]) -> WriterProfilePlan:
    options = {
        "addition": ({"row_group_size": 2}, {"historical_group_size": 2}),
        "removal": (None, {"historical_group_size": 2}),
        "options": ({"historical_group_size": 3}, None),
    }[change]
    capabilities = tuple(
        _capability(writer, option) for writer, option in zip(writers, options, strict=True)
    )
    return WriterProfilePlan(("row-group-2",), capabilities)


def _passing(writer: EngineVersion, profile: WriterProfileIdentity | None) -> CellResult:
    engines = (writer.name, writer.version, "duckdb", "2")
    return CellResult(*engines, "compare", Verdict.PASS, "$", "match", writer_profile=profile)


def _historical_evaluate(
    case: Case, directory: Path, plan: WriterProfilePlan, writers: tuple[EngineVersion, ...]
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


def _publish(destination: Path, *, discovered: Case | None = None) -> None:
    source = _source(discovered=discovered)

    def evaluator(case: Case, directory: Path) -> MatrixRun:
        run = _evaluate(case, directory)
        target = run.failures[0]
        return replace(run, results=(replace(target, detail="controlled mismatch"),))

    publish_bundle(source, destination, evaluator)


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
    _publish(destination)
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
    _publish(first)
    _publish(second)

    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }
    assert not (first / "discovered_case.json").exists()
    reduced = tmp_path / "reduced"
    _publish(reduced, discovered=_case(extra_field=True))
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
            publish_bundle(_source(), destination, forbidden)
    assert existing_file.read_bytes() == b"owned"
    writers, readers = _versions()
    passing = CellResult("pyarrow", "1", "duckdb", "2", "compare", Verdict.PASS, "$", "match")
    invalid_runs = (
        MatrixRun("wrong", (passing,), (), writers, readers),
        MatrixRun(_case().case_id, (passing,), (), writers, readers),
        MatrixRun(_case().case_id, (_result(),), (), writers, readers),
    )
    for index, run in enumerate(invalid_runs):
        with pytest.raises(RuntimeError):
            publish_bundle(
                _source(), tmp_path / f"invalid-{index}", lambda case, path, value=run: value
            )
    escaped = tmp_path / "escaped"

    def escape(case: Case, directory: Path) -> MatrixRun:
        directory.mkdir(parents=True)
        (directory.parent / "outside.parquet").write_bytes(b"PAR1outsidePAR1")
        writers, readers = _versions()
        path = directory / ".." / "outside.parquet"
        return MatrixRun(case.case_id, (_result(),), (("pyarrow", path),), writers, readers)

    with pytest.raises(RuntimeError, match="outside the evaluation directory"):
        publish_bundle(_source(), escaped, escape)
    assert not escaped.exists()


def test_invalid_payload_shapes_fail_validation(tmp_path: Path) -> None:
    mutations = ("missing", "missing-manifest", "extra", "tampered")
    mutations += ("resealed-report", "noncanonical", "nested", "symlink")
    for mutation in mutations:
        destination = tmp_path / mutation
        _publish(destination)
        if mutation == "missing":
            (destination / "REPORT.md").unlink()
        elif mutation == "missing-manifest":
            (destination / "finding.json").unlink()
        elif mutation == "extra":
            (destination / "extra.txt").write_text("extra")
        elif mutation == "tampered":
            (destination / "matrix.json").write_bytes(b"{}")
        elif mutation == "resealed-report":
            _replace_artifact(destination, "REPORT.md", b"# arbitrary but resealed\n")
        elif mutation == "noncanonical":
            path = destination / "finding.json"
            path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2))
        elif mutation == "nested":
            (destination / "nested").mkdir()
        else:
            external = tmp_path / "external.md"
            external.write_text("external")
            (destination / "REPORT.md").unlink()
            (destination / "REPORT.md").symlink_to(external)
        with pytest.raises(BundleValidationError):
            validate_bundle(destination)


def test_canonical_payloads_with_conflicting_identity_are_rejected(tmp_path: Path) -> None:
    def forbidden(case: Case, directory: Path) -> MatrixRun:
        raise AssertionError((case, directory))

    for mutation in ("matrix-noncanonical", "case", "discovered", "matrix"):
        destination = tmp_path / mutation
        _publish(
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
        if mutation == "case":
            with pytest.raises(BundleValidationError):
                replay_bundle(destination, forbidden)
    signature = ReplaySignature.from_result(_result())
    data = signature.to_data()
    assert ReplaySignature.from_data(data) == signature
    profile = WriterProfileIdentity("row-group-2", {"row_group_size": 2})
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
    _publish(destination)
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

    exact = replay_bundle(destination, evaluator(_result(writer_version="9", reader_version="8")))
    dependency_versions["pyarrow"] = "9"
    related = replay_bundle(destination, evaluator(_result(detail="controlled mismatch 7")))
    dependency_versions["pyarrow"] = None
    absent = replay_bundle(destination, evaluator(_result(diagnostic_kind="DifferentError")))
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
        publish_bundle(source, historical, historical_evaluator)
        assert validate_bundle(historical).finding.writer_profiles == plan
        assert cli.main(["replay", str(historical)]) == 2
        payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
        assert cast(dict[str, object], payload["error"])["kind"] == ("WRITER_PROFILE_NOT_EVALUABLE")
