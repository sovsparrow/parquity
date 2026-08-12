from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from parquity.engines import ReaderSelection
from parquity.engines.base import EngineReader
from parquity.runs import bundle as run_bundle
from parquity.runs import replay as run_replay
from parquity.scans import bundle as scan_bundle
from parquity.scans import replay as scan_replay
from parquity.scans import workflow as scan_workflow
from parquity.scans.observations import GroupedObservations
from parquity.verdicts import MatrixRun

_ROOT = Path(__file__).parents[1] / "fixtures" / "v0_1_0"
_GENERATED_RUN_ID = "dacc978fd02146092a69dacd6385f113e32a43bc0d4e2bc1a5d384242d51ee6f"
_GENERATED_FINDING_ID = "4301899bdcf5dde01d90c0e2c01c9d634167cd0c0413b8505cbd82d01f1facbe"
_SCAN_RUN_ID = "20f19229efec91c5e3fc8a0f6f7e80eb079cd5a4d4717a28eae04eed0ce84890"
_SCAN_FINDING_ID = "15b1baa9209f13415b4f2b2d74ce3147aa9da6caa90f75617218a73d7fec9d33"

_GENERATED_INVENTORY = {
    "REPORT.md": (2966, "1065f48199994b63c5d5f3b2588b29acf55d7a3ebacaa69f86b8af8365c69400"),
    f"findings/{_GENERATED_FINDING_ID}/REPORT.md": (
        3351,
        "9e61afa87a9c83c5a308ffc128a5d8da289f85a3cd61e7b31b03b90f8971168b",
    ),
    f"findings/{_GENERATED_FINDING_ID}/case.json": (
        111,
        "fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3",
    ),
    f"findings/{_GENERATED_FINDING_ID}/finding.json": (
        2521,
        "b1b61546a79345bc1efac70248e1a12e331f735963506a139fe5b69fd95d94e0",
    ),
    f"findings/{_GENERATED_FINDING_ID}/input.parquet": (
        24,
        "a233caef4261b42d7d0bf9acf8e002e047798ef30ee1ee0d34df37618bd91ce3",
    ),
    f"findings/{_GENERATED_FINDING_ID}/matrix.json": (
        1079,
        "0001265a82e40d58ffdf827f9d34a429c90e8fe5641c393aa9f2b0b3667e3bbc",
    ),
    f"findings/{_GENERATED_FINDING_ID}/reproduce.py": (
        238,
        "2b19b985b93270de908ec9eb816b0e0a25ef6e69142218ddf0b7446b10fdd39b",
    ),
    f"findings/{_GENERATED_FINDING_ID}/upstream_repro.py": (
        2447,
        "2cba747c8d9001205e7c552f392be65431b057a5717a9c676f2fde2c29ab2cdb",
    ),
    "run.json": (1428, "59b2d499420bd78d4c09baff4443f2662546a5ca101954308c6ac0943272a785"),
}
_SCAN_INVENTORY = {
    "REPORT.md": (2203, "a1ee8e8927f2531007de67ffafa71fe326a9273b5eab6bb214117c540b1e300b"),
    f"findings/{_SCAN_FINDING_ID}/REPORT.md": (
        2447,
        "26d897e064a5a54f441ba43b1eab2c46ed620c7918c0ca639d232ea4e50b1b7a",
    ),
    f"findings/{_SCAN_FINDING_ID}/finding.json": (
        1605,
        "45c110c4869744004957b1a057921cee49aee26cf03b4c27291a42804bafe5cd",
    ),
    f"findings/{_SCAN_FINDING_ID}/input.parquet": (
        21,
        "1d59e28d35ef1ee9591ad9df0d3ae9bb5f3b3404f7f98f4c41550a76663e7228",
    ),
    f"findings/{_SCAN_FINDING_ID}/reproduce.py": (
        279,
        "0d0f1f9143a69c40c4dec1a43b98860cf94d4627c0f12160e77ff43454ab9b8a",
    ),
    f"findings/{_SCAN_FINDING_ID}/upstream_repro.py": (
        1844,
        "12cd3c984261d5aebd1c30a1161da9abe41e5d5d0a1a86476e4544761bb8e94a",
    ),
    "scan.json": (1167, "1d7db2ae7c938ecb5fa32e51fede16f2702e5878015edbd9597bf34fc6a8a581"),
}


def _inventory(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.relative_to(root).as_posix(): (
            len(payload := path.read_bytes()),
            hashlib.sha256(payload).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _document(path: Path) -> Mapping[str, object]:
    value = cast(object, json.loads(path.read_bytes()))
    assert isinstance(value, dict)
    return cast(Mapping[str, object], value)


def test_released_generated_run_has_literal_inventory_shape_and_identity() -> None:
    root = _ROOT / "generated"
    assert _inventory(root) == _GENERATED_INVENTORY
    run = _document(root / "run.json")
    child = _document(root / "findings" / _GENERATED_FINDING_ID / "finding.json")
    assert (run["format"], run["run_id"]) == ("parquity.run.v1", _GENERATED_RUN_ID)
    assert (child["format"], child["finding_id"]) == (
        "parquity.finding.v1",
        _GENERATED_FINDING_ID,
    )

    validated = run_bundle.validate_run(root)
    assert validated.run.run_id == _GENERATED_RUN_ID
    assert tuple(item.finding.finding_id for item in validated.children) == (_GENERATED_FINDING_ID,)


def test_released_generated_run_replays_with_a_deterministic_fake() -> None:
    root = _ROOT / "generated"
    validated = run_bundle.validate_run(root)
    child = validated.children[0]

    def evaluate(case: object, directory: Path) -> MatrixRun:
        del directory
        assert case == child.case
        return MatrixRun(
            child.case.case_id,
            (child.finding.result,),
            (),
            validated.run.writers,
            validated.run.readers,
        )

    outcome = run_replay.replay_run(root, evaluate)
    assert (outcome.exact_count, outcome.related_count, outcome.absent_count) == (1, 0, 0)
    assert outcome.outcomes[0].finding.finding_id == _GENERATED_FINDING_ID


def test_released_scan_run_has_literal_inventory_shape_and_identity() -> None:
    root = _ROOT / "scan"
    assert _inventory(root) == _SCAN_INVENTORY
    run = _document(root / "scan.json")
    child = _document(root / "findings" / _SCAN_FINDING_ID / "finding.json")
    assert (run["format"], run["scan_id"]) == ("parquity.scan-run.v1", _SCAN_RUN_ID)
    assert (child["format"], child["finding_id"]) == (
        "parquity.scan-finding.v1",
        _SCAN_FINDING_ID,
    )
    validated = scan_bundle.validate_run(root)
    assert validated.record.data["scan_id"] == _SCAN_RUN_ID
    assert tuple(item.record.finding_id for item in validated.children) == (_SCAN_FINDING_ID,)


def test_released_scan_run_replays_with_a_deterministic_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = scan_bundle.validate_run(_ROOT / "scan")
    child = validated.children[0]
    readers = cast(
        tuple[EngineReader, ...],
        tuple(SimpleNamespace(identity=item) for item in child.record.engines),
    )
    selection = ReaderSelection(tuple(item.name for item in child.record.engines), readers)

    def evaluate(*_: object) -> scan_workflow.FileEvaluation:
        return scan_workflow.FileEvaluation(
            child.record.outcomes,
            GroupedObservations((), ()),
        )

    monkeypatch.setattr(scan_workflow, "evaluate_snapshot", evaluate)
    outcome = scan_replay.replay_finding(child, selection)
    occurrences = outcome.occurrence_results
    assert outcome.classification == "REPRODUCED"
    assert len(occurrences) == 2
    assert {item["classification"] for item in occurrences} == {"REPRODUCED"}


@pytest.mark.parametrize("name", ("generated", "scan"))
def test_released_fixture_rejects_unsealed_report_tampering(tmp_path: Path, name: str) -> None:
    copied = tmp_path / name
    shutil.copytree(_ROOT / name, copied)
    report = copied / "REPORT.md"
    report.write_bytes(report.read_bytes() + b"tamper\n")
    validator = run_bundle.validate_run if name == "generated" else scan_bundle.validate_run
    with pytest.raises((run_bundle.RunBundleValidationError, scan_bundle.ScanBundleError)):
        validator(copied)
