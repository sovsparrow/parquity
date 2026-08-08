from __future__ import annotations

import json
from dataclasses import replace
from importlib import import_module
from pathlib import Path
from typing import cast

import pyarrow as pa
import pytest

from parquity import cli
from parquity.engines import EngineSelection
from parquity.engines.base import EngineIdentity
from parquity.engines.fastparquet import FastparquetEngine
from parquity.engines.pyarrow import PyArrowEngine
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs.bundle import RunBundleValidationError, ValidatedRun, validate_run
from parquity.triage.adapters import generated_occurrences
from parquity.triage.model import Occurrence, group_occurrences
from parquity.writer_profiles import WriterProfileIdentity


class _InvalidArtifactEngine(PyArrowEngine):
    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        assert profile == self.writer_profile(profile.name)
        if table.num_rows == 4 and table.column_names == ["value", "label"]:
            super().write_profiled(table, path, profile)
        else:
            super().write(table, path)

    def read(self, path: Path) -> pa.Table:
        raise AssertionError(f"unexpected reader execution for {path}")


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert not captured.err
    return cast(dict[str, object], json.loads(captured.out))


def _case(path: Path, case: Case) -> None:
    path.write_bytes(case.canonical_bytes())


def _triage_occurrences(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    name: str,
    profiles: str | None,
) -> tuple[ValidatedRun, tuple[Occurrence, ...]]:
    source, destination = tmp_path / f"{name}.json", tmp_path / name
    _case(
        source,
        Case(
            (Field("tick", TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC"), False),),
            ((-(2**63),),),
        ),
    )
    arguments = ["check", str(source), "--out", str(destination)]
    arguments += ["--writers", "pyarrow,fastparquet", "--readers", "pyarrow"]
    if profiles is not None:
        arguments.extend(("--writer-profiles", profiles))
    assert cli.main(arguments) == 1
    _payload(capsys)
    validated = validate_run(destination)
    return validated, generated_occurrences(validated)


def _family_id(occurrence: Occurrence) -> str:
    return group_occurrences((occurrence,))[0].family_id


def test_profiled_check_emits_complete_mixed_capability_evidence_without_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, destination = tmp_path / "case.json", tmp_path / "run"
    _case(source, Case((Field("value", TypeSpec(Kind.INT32), False),), ((1,), (2,), (3,))))
    code = cli.main(
        [
            "check",
            str(source),
            "--out",
            str(destination),
            "--writers",
            "pyarrow,duckdb",
            "--readers",
            "pyarrow",
            "--writer-profiles",
            "row-group-2,compression-brotli",
        ]
    )
    payload = _payload(capsys)
    assert (code, payload["status"]) == (0, "NO_FINDING")
    plan = cast(dict[str, object], payload["writer_profiles"])
    assert plan["requested"] == ["compression-brotli", "row-group-2"]
    assert len(cast(list[object], plan["capabilities"])) == 4
    assert not destination.exists()


@pytest.mark.parametrize(
    "profiles,kind",
    (
        ("default", "INVALID_WRITER_PROFILE_SET"),
        ("row-group-2,", "INVALID_WRITER_PROFILE_SET"),
        ("row-group-2,row-group-2", "INVALID_WRITER_PROFILE_SET"),
        ("unknown", "UNKNOWN_WRITER_PROFILE"),
    ),
)
def test_invalid_profile_sets_exit_two_before_output(
    profiles: str,
    kind: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, destination = tmp_path / "case.json", tmp_path / "run"
    _case(source, Case((Field("value", TypeSpec(Kind.INT32), False),), ((1,),)))
    assert (
        cli.main(["check", str(source), "--out", str(destination), "--writer-profiles", profiles])
        == 2
    )
    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    assert cast(dict[str, object], payload["error"])["kind"] == kind
    assert not destination.exists()


def test_profiled_fuzz_uses_existing_bounded_lifecycle(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "fuzz"
    code = cli.main(
        [
            "fuzz",
            "--examples",
            "2",
            "--seed",
            "17",
            "--out",
            str(destination),
            "--writers",
            "pyarrow",
            "--readers",
            "pyarrow",
            "--writer-profiles",
            "row-group-2",
        ]
    )
    payload = _payload(capsys)
    assert code == 0
    assert payload["status"] == "NO_FINDING"
    assert "writer_profiles" in payload
    assert not destination.exists()


def test_profiled_run_replay_triage_reproduction_and_atomic_precondition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "case.json"
    destination = tmp_path / "run"
    _case(
        source,
        Case(
            (Field("tick", TypeSpec(Kind.TIMESTAMP, unit="ns", timezone="UTC"), False),),
            ((-(2**63),),),
        ),
    )
    arguments = [
        "check",
        str(source),
        "--out",
        str(destination),
        "--writers",
        "fastparquet",
        "--readers",
        "pyarrow",
        "--writer-profiles",
        "row-group-2",
    ]
    assert cli.main(arguments) == 1
    published = _payload(capsys)
    assert published["finding_count"] == 2
    validated = validate_run(destination)
    assert validated.run.writer_profiles is not None
    profiled = next(
        child
        for child in validated.children
        if child.finding.fingerprint.writer_profile is not None
    )
    script = (profiled.directory / "upstream_repro.py").read_text()
    assert "options = {'row_group_offsets': 2}" in script
    assert "write_index=False, **options" in script
    assert "row_group_offsets=2" not in script
    compile(script, str(profiled.directory / "upstream_repro.py"), "exec")

    run_path = destination / "run.json"
    run_bytes = run_path.read_bytes()
    run_data = cast(dict[str, object], json.loads(run_bytes))
    run_data.pop("writer_profiles")
    run_path.write_text(json.dumps(run_data, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunBundleValidationError):
        validate_run(destination)
    run_path.write_bytes(run_bytes)
    finding_path = profiled.directory / "finding.json"
    finding_bytes = finding_path.read_bytes()
    finding_data = cast(dict[str, object], json.loads(finding_bytes))
    finding_data.pop("writer_profiles")
    finding_path.write_text(json.dumps(finding_data, sort_keys=True, separators=(",", ":")))
    with pytest.raises(RunBundleValidationError):
        validate_run(destination)
    finding_path.write_bytes(finding_bytes)
    assert cli.main(["replay", str(destination)]) == 1
    replay_text = capsys.readouterr().out
    replay = cast(dict[str, object], json.loads(replay_text))
    assert replay["status"] == "REPRODUCED"
    assert replay["exact"] == 2
    evidence = tmp_path / "replay.json"
    evidence.write_text(replay_text)
    assert cli.main(["triage", str(destination), "--replay-evidence", str(evidence)]) == 0
    triage = _payload(capsys)
    assert triage["symptom_family_count"] == 2
    families = cast(list[dict[str, object]], triage["symptom_families"])
    target = next(family for family in families if "writer_profile" in family)
    assert cast(dict[str, object], target["writer_profile"])["name"] == "row-group-2"
    assert target["representative_reproduction_state"] == "REPRODUCED"

    calls = 0

    def unavailable(self: FastparquetEngine, name: str) -> None:
        del self, name

    def forbidden(*args: object, **kwargs: object) -> None:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise AssertionError("profile precondition started provider work")

    monkeypatch.setattr(FastparquetEngine, "writer_profile", unavailable)
    monkeypatch.setattr(FastparquetEngine, "write", forbidden)
    monkeypatch.setattr(FastparquetEngine, "write_profiled", forbidden)
    assert cli.main(["replay", str(destination)]) == 2
    failed = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(failed.out))
    assert cast(dict[str, object], payload["error"])["kind"] == "WRITER_PROFILE_NOT_EVALUABLE"
    assert calls == 0


def test_generated_family_identity_depends_only_on_the_target_execution(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plain_run, plain = _triage_occurrences(tmp_path, capsys, "plain", None)
    planned_run, planned = _triage_occurrences(tmp_path, capsys, "planned", "row-group-2")
    expanded_run, expanded = _triage_occurrences(
        tmp_path, capsys, "expanded", "row-group-2,compression-gzip"
    )

    plain_default = next(item for item in plain if item.writer_profile is None)
    planned_default = next(item for item in planned if item.writer_profile is None)
    expanded_default = next(item for item in expanded if item.writer_profile is None)
    planned_profile = next(item for item in planned if item.writer_profile is not None)
    expanded_profile = next(
        item
        for item in expanded
        if item.writer_profile is not None and item.writer_profile.name == "row-group-2"
    )

    assert "writer_profiles" not in plain_default.projection
    assert "writer_profile" not in plain_default.projection
    assert planned_default.projection == plain_default.projection == expanded_default.projection
    assert _family_id(planned_default) == _family_id(plain_default) == _family_id(expanded_default)
    assert "writer_profiles" not in planned_profile.projection
    assert planned_profile.writer_profile is not None
    assert planned_profile.projection["writer_profile"] == planned_profile.writer_profile.to_data()
    assert planned_profile.projection == expanded_profile.projection
    assert _family_id(planned_profile) == _family_id(expanded_profile)

    assert planned_default.writer_profiles == planned_run.run.writer_profiles
    assert expanded_profile.writer_profiles == expanded_run.run.writer_profiles
    assert all(
        child.finding.writer_profiles == expanded_run.run.writer_profiles
        for child in expanded_run.children
    )
    assert plain_run.run.writer_profiles is None

    family_id = _family_id(planned_profile)
    changed_profiles = (
        WriterProfileIdentity("row-group-2", {"row_group_size": 3}),
        WriterProfileIdentity("compression-gzip", {"compression": "gzip"}),
    )
    for profile in changed_profiles:
        changed = replace(
            planned_profile,
            projection={**planned_profile.projection, "writer_profile": profile.to_data()},
            writer_profile=profile,
        )
        assert _family_id(changed) != family_id


def test_cli_reports_artifact_contract_violation_without_publishing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "case.json"
    destination = tmp_path / "output"
    _case(source, Case((Field("value", TypeSpec(Kind.INT32), False),), ((1,), (2,))))
    engine = _InvalidArtifactEngine(EngineIdentity("pyarrow", "controlled"))
    selection = EngineSelection(("pyarrow",), ("pyarrow",), (engine,), (engine,))

    def resolve(*_arguments: object) -> EngineSelection:
        return selection

    main_module = import_module("parquity.cli.main")
    monkeypatch.setattr(main_module, "resolve_engine_selection", resolve)
    arguments = [
        "check",
        str(source),
        "--out",
        str(destination),
        "--writer-profiles",
        "compression-gzip",
    ]
    assert cli.main(arguments) == 3
    captured = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(captured.out))
    assert payload["status"] == "INTERNAL_ERROR"
    error = cast(dict[str, object], payload["error"])
    assert error["kind"] == "WRITER_PROFILE_CONTRACT_VIOLATION"
    assert "finding_count" not in payload and not destination.exists()
