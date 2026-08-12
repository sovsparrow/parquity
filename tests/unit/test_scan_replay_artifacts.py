import hashlib
import platform
from collections.abc import Callable, Mapping
from dataclasses import replace
from importlib import metadata
from pathlib import Path
from typing import Any, cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity.engines import ReaderSelection, resolve_reader_selection
from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.evidence.storage import DestinationExistsError, StagingError
from parquity.scans import bundle, replay, workflow
from parquity.scans.control import WorkerProtocolError
from parquity.scans.discovery import ScanConfigurationError, discover_input, snapshot_file
from parquity.scans.observations import GroupedObservations, ObservationMetadata
from parquity.scans.records import ReaderOutcomeKind, ReaderOutcomeRecord
from parquity.scans.supervision import WorkerLimitError, WorkerOutcome
from parquity.scans.workflow import evaluate_snapshot


def _inventory(root: Path) -> tuple[tuple[Path, bytes], ...]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    return tuple((path.relative_to(root), path.read_bytes()) for path in files)


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
    outcome = replace(outcome, version=version)
    engines = (EngineVersion("pyarrow", version),)
    environment = EnvironmentEvidence(
        "0.0.0" if recorded_version else metadata.version("parquity"),
        metadata.version("hypothesis"),
        platform.python_version(),
        platform.platform(),
        engines,
        (DependencyVersion("pyarrow", version),),
    )
    target = directory / "bundle"
    bundle.build_finding(
        target,
        environment=environment,
        source_path="source.parquet",
        input_payload=input_payload,
        engines=engines,
        timeout_seconds=30,
        outcomes=(outcome,),
        groups=(evaluation.grouped.groups if outcome.kind is ReaderOutcomeKind.SUCCESS else ()),
        comparisons=(
            evaluation.grouped.differences if outcome.kind is ReaderOutcomeKind.SUCCESS else ()
        ),
    )
    return target, selection


def test_scan_replay_exact_related_absent_and_version_drift(tmp_path: Path) -> None:
    exact_path, selection = _provider_finding(tmp_path / "exact", b"not parquet")
    exact = replay.replay_finding(bundle.validate_finding(exact_path), selection)
    assert exact.classification == "REPRODUCED"
    related_path, related_selection = _provider_finding(
        tmp_path / "related",
        b"not parquet",
        lambda item: replace(item, detail="changed\n## injected\n```"),
    )
    before = _inventory(related_path)
    related = replay.replay_finding(bundle.validate_finding(related_path), related_selection)
    assert _inventory(related_path) == before and related.classification == "RELATED_FAILURE"
    occurrence = related.occurrence_results[0]
    observation = cast(Mapping[str, object], occurrence["current_observation"])
    change = cast(list[Mapping[str, object]], observation["detail_changes"])[0]
    assert observation["signal"] == "PROVIDER_ERROR" and observation["target_reader"] == "pyarrow"
    assert observation["reader_roster"] == ["pyarrow"]
    assert change["original_detail"] == "changed ## injected ```"
    expected_sha256 = hashlib.sha256(b"changed ## injected ```").hexdigest()
    assert change["original_detail_sha256"] == expected_sha256
    assert change["current_detail_sha256"] != change["original_detail_sha256"]
    table_path = tmp_path / "valid.parquet"
    cast(Any, pq).write_table(pa.table({"value": [1]}), table_path)
    absent_path, absent_selection = _provider_finding(
        tmp_path / "absent",
        table_path.read_bytes(),
        lambda item: ReaderOutcomeRecord(
            item.engine,
            item.version,
            ReaderOutcomeKind.PROCESS_ERROR,
            "PROCESS_CRASH",
            "",
            "",
            False,
        ),
    )
    absent = replay.replay_finding(bundle.validate_finding(absent_path), absent_selection)
    assert absent.classification == "NOT_REPRODUCED"
    drift_path, drift_selection = _provider_finding(
        tmp_path / "drift", b"not parquet", recorded_version="recorded-version"
    )
    drift = replay.replay_finding(bundle.validate_finding(drift_path), drift_selection)
    assert drift.classification == "REPRODUCED"
    assert drift.version_evidence[0]["drift"] is True
    assert drift.package_version["drift"] is True


@pytest.mark.parametrize(
    ("failure", "kind", "detail"),
    (
        ("destination_race", "OUTPUT_EXISTS", "output path already exists"),
        ("rename_error", "OUTPUT_ERROR", "scan output could not be published"),
        ("staging_error", "OUTPUT_ERROR", "output path could not be prepared"),
    ),
)
def test_scan_publication_failures_leave_no_output(
    failure: str,
    kind: str,
    detail: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.parquet"
    source.write_bytes(b"controlled finding")
    destination = tmp_path / "run"
    selection = resolve_reader_selection(("pyarrow",))
    finding = ReaderOutcomeRecord(
        "pyarrow",
        selection.reader_versions[0][1],
        ReaderOutcomeKind.PROVIDER_ERROR,
        "CONTROLLED_ERROR",
        "controlled detail",
        "",
        False,
    )

    def controlled_evaluation(*_: object) -> workflow.FileEvaluation:
        return workflow.FileEvaluation((finding,), GroupedObservations((), ()))

    def destination_race(*_: object) -> None:
        raise DestinationExistsError(destination)

    def rename_error(*_: object) -> None:
        raise OSError("controlled unrelated rename failure")

    def staging_error(*_: object, **__: object) -> object:
        raise StagingError("controlled staging failure")

    fault = {"destination_race": destination_race, "rename_error": rename_error}.get(
        failure, staging_error
    )
    target = "staging_directory" if failure == "staging_error" else "atomic_publish_directory"
    monkeypatch.setattr(workflow, "evaluate_snapshot", controlled_evaluation)
    monkeypatch.setattr(workflow, target, fault)
    with pytest.raises(ScanConfigurationError) as raised:
        workflow.execute_scan(source, destination, selection, timeout_seconds=30, max_saved=1)
    assert (raised.value.kind, raised.value.detail) == (kind, detail)
    assert not destination.exists()
    assert not tuple(tmp_path.glob(f".{destination.name}.parquity-scan-*"))


@pytest.mark.parametrize("mutation", ("deleted", "changed"))
def test_scan_replay_rejects_post_validation_input_drift_before_evaluation(
    mutation: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    finding_path, selection = _provider_finding(tmp_path / "finding", b"recorded input")
    validated = bundle.validate_finding(finding_path)
    input_path = finding_path / "input.parquet"
    if mutation == "deleted":
        input_path.unlink()
    else:
        input_path.write_bytes(b"changed input")

    def unexpected_evaluation(*_: object) -> object:
        raise AssertionError("input drift reached provider evaluation")

    monkeypatch.setattr(workflow, "evaluate_snapshot", unexpected_evaluation)
    with pytest.raises(ScanConfigurationError) as raised:
        replay.replay_finding(validated, selection)
    assert raised.value.kind == "INPUT_DRIFT"
    assert raised.value.detail == "validated scan input changed before replay"


def test_scan_replay_rejects_reader_roster_drift_before_evaluation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    finding_path, selection = _provider_finding(tmp_path / "finding", b"recorded input")
    validated = bundle.validate_finding(finding_path)
    changed_selection = ReaderSelection(("different-reader",), selection.readers)

    def unexpected_evaluation(*_: object) -> object:
        raise AssertionError("reader roster drift reached provider evaluation")

    monkeypatch.setattr(workflow, "evaluate_snapshot", unexpected_evaluation)
    with pytest.raises(
        WorkerProtocolError, match=r"^scan replay requires the exact recorded reader roster$"
    ):
        replay.replay_finding(validated, changed_selection)


def test_scan_evaluation_maps_worker_configuration_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worker_error = WorkerLimitError("controlled worker limit")
    source = tmp_path / "input.parquet"
    source.write_bytes(b"input")
    snapshot = snapshot_file(discover_input(source).files[0], tmp_path / "snapshot")
    selection = resolve_reader_selection(("pyarrow",))

    def controlled_failure(*_: object, **__: object) -> WorkerOutcome:
        raise worker_error

    monkeypatch.setattr(workflow, "run_worker_process", controlled_failure)
    with pytest.raises(ScanConfigurationError) as raised:
        evaluate_snapshot(snapshot, selection, 30, tmp_path / "private")
    assert raised.value.kind == "SCAN_LIMIT_EXCEEDED"
    assert raised.value.detail == str(worker_error)


def test_scan_evaluation_rejects_invalid_success_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "input.parquet"
    source.write_bytes(b"input")
    snapshot = snapshot_file(discover_input(source).files[0], tmp_path / "snapshot")
    selection = resolve_reader_selection(("pyarrow",))
    identity = selection.readers[0].identity
    metadata_value = ObservationMetadata(1, "0" * 64, 0, 0, "0" * 64)
    malformed = WorkerOutcome(
        ReaderOutcomeKind.SUCCESS,
        identity.name,
        identity.version,
        "SUCCESS",
        "",
        "",
        False,
        b"x",
        metadata_value,
    )

    def malformed_success(*_: object, **__: object) -> WorkerOutcome:
        return malformed

    monkeypatch.setattr(workflow, "run_worker_process", malformed_success)
    with pytest.raises(WorkerProtocolError, match=r"^worker observation artifact is invalid$"):
        evaluate_snapshot(snapshot, selection, 30, tmp_path / "private")
