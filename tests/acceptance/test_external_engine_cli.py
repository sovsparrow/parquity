from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from parquity import cli
from parquity.engines import default_engine_names
from parquity.model import Case, Field, Kind, TypeSpec
from tests.support import external_engine as bridge
from tests.support.cli_output import captured_payload

CASE = Case(
    (
        Field("value", TypeSpec(Kind.INT32), nullable=False),
        Field("label", TypeSpec(Kind.STRING), nullable=True),
    ),
    ((1, "a"), (2, None)),
)


def _case(root: Path) -> Path:
    path = root / "case.json"
    path.write_bytes(CASE.canonical_bytes())
    return path


def _engines(capsys: pytest.CaptureFixture[str]) -> list[dict[str, object]]:
    assert cli.main(["engines", "--json"]) == 0
    payload, _ = captured_payload(capsys)
    return cast(list[dict[str, object]], payload["engines"])


def test_a_configured_bridge_is_listed_with_the_version_it_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge.configure(monkeypatch, tmp_path)
    listed = next(item for item in _engines(capsys) if item["name"] == bridge.NAME)

    assert listed["tier"] == "external"
    assert listed["available"] is True
    assert listed["version"] == "9.9.9"
    assert (listed["reader"], listed["writer"]) == (True, True)


def test_an_external_engine_never_joins_the_default_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Configuring a bridge must not silently widen anyone's default run; it is selected by name.
    bridge.configure(monkeypatch, tmp_path)
    assert bridge.NAME not in default_engine_names("writer")
    assert bridge.NAME not in default_engine_names("reader")


@pytest.mark.parametrize("injected", ("info-exit", "info-garbage", "info-protocol", "info-engine"))
def test_a_bridge_that_fails_its_probe_is_unavailable_rather_than_silently_dropped(
    injected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bridge.configure(monkeypatch, tmp_path)
    bridge.fault(monkeypatch, injected)

    listed = next(item for item in _engines(capsys) if item["name"] == bridge.NAME)
    assert listed["available"] is False
    assert listed["version"] is None
    assert listed["installation_hint"]

    # Selecting it is a configuration error before any matrix work, not a smaller matrix.
    selection = ["--writers", bridge.NAME, "--out", str(tmp_path / "out"), "--json"]
    assert cli.main(["check", str(_case(tmp_path)), *selection]) == 2
    payload, stderr = captured_payload(capsys)
    assert payload["status"] == "CONFIGURATION_ERROR"
    unavailable = cast(list[dict[str, object]], payload["engines"])
    assert [item["name"] for item in unavailable] == [bridge.NAME]
    assert unavailable[0]["available"] is False
    assert bridge.NAME in stderr
    assert not (tmp_path / "out").exists()


def test_selecting_a_direction_the_bridge_does_not_declare_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge.directions(monkeypatch, "read")
    bridge.configure(monkeypatch, tmp_path)

    selection = ["--writers", bridge.NAME, "--out", str(tmp_path / "out"), "--json"]
    assert cli.main(["check", str(_case(tmp_path)), *selection]) == 2
    payload, _ = captured_payload(capsys)
    error = cast(dict[str, object], payload["error"])
    assert error["kind"] == "ENGINE_CAPABILITY_ERROR"


def test_a_malformed_declaration_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge.configure(monkeypatch, tmp_path, "[engines.controlled]\n")

    assert cli.main(["engines", "--json"]) == 2
    payload, _ = captured_payload(capsys)
    error = cast(dict[str, object], payload["error"])
    assert error["kind"] == "EXTERNAL_ENGINE_CONFIGURATION_ERROR"
    assert "requires a command" in cast(str, error["detail"])


def test_a_check_runs_end_to_end_through_the_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The controlled bridge round-trips what it is given, so a matrix that both writes and reads
    # through it must agree with the Case. This exercises selection, both directions, and the
    # comparison path against a real subprocess.
    bridge.configure(monkeypatch, tmp_path)
    destination = tmp_path / "out"
    arguments = [
        "check",
        str(_case(tmp_path)),
        "--writers",
        bridge.NAME,
        "--readers",
        bridge.NAME,
        "--out",
        str(destination),
        "--json",
    ]

    assert cli.main(arguments) == 0
    payload, stderr = captured_payload(capsys)
    assert payload["status"] == "NO_FINDING"
    assert payload["writers"] == [bridge.NAME] and payload["readers"] == [bridge.NAME]
    assert not stderr and not destination.exists()


def test_a_broken_contract_during_a_run_stops_it_instead_of_recording_a_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bridge.configure(monkeypatch, tmp_path)
    bridge.fault(monkeypatch, "reject")
    destination = tmp_path / "out"
    arguments = ["check", str(_case(tmp_path)), "--writers", bridge.NAME, "--out", str(destination)]

    assert cli.main([*arguments, "--json"]) == 3
    payload, _ = captured_payload(capsys)
    error = cast(dict[str, object], payload["error"])
    assert error["kind"] == "EXTERNAL_ENGINE_PROTOCOL_ERROR"
    assert "rejected the write request" in cast(str, error["detail"])
    assert not destination.exists()


def test_a_finding_records_the_probed_version_and_a_portable_reproducer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A failure the bridge reports about itself is evidence, so the run saves a reproducer naming
    # the external writer and the version its probe returned.
    bridge.configure(monkeypatch, tmp_path)
    bridge.fault(monkeypatch, "provider")
    destination = tmp_path / "out"
    arguments = [
        "check",
        str(_case(tmp_path)),
        "--writers",
        bridge.NAME,
        "--readers",
        bridge.NAME,
        "--out",
        str(destination),
        "--json",
    ]

    assert cli.main(arguments) == 1
    payload, _ = captured_payload(capsys)
    findings = cast(list[dict[str, object]], payload["findings"])
    assert findings and findings[0]["writer"] == bridge.NAME
    assert findings[0]["writer_version"] == "9.9.9"
    assert findings[0]["verdict"] == "WRITE_ERROR"
    assert findings[0]["diagnostic_kind"] == "ControlledProviderError"

    run = json.loads((destination / "run.json").read_text(encoding="utf-8"))
    assert {item["name"]: item["version"] for item in run["writers"]}[bridge.NAME] == "9.9.9"

    reproducer = next((destination / "findings").iterdir()) / "upstream_repro.py"
    source = reproducer.read_text(encoding="utf-8")
    compile(source, str(reproducer), "exec")
    assert f"BRIDGES = ['{bridge.NAME}']" in source
    assert "PARQUITY_ENGINE_" in source and "def bridge(" in source
    # The configured command is a local path, and evidence is meant to be shareable, so the
    # reproducer resolves it from the environment instead of embedding it.
    assert str(bridge.BRIDGE) not in source
    assert str(bridge.BRIDGE.parent) not in source


def test_a_timeout_is_reported_where_the_remedy_is_and_saves_no_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A bridge that never answers says nothing about the implementation, so the run must not record
    # a finding against it -- otherwise a slow machine invents defects. It is reported against the
    # setting that fixes it instead.
    bridge.configure(monkeypatch, tmp_path, bridge.declaration(timeout_seconds=1))
    bridge.fault(monkeypatch, "slow")
    destination = tmp_path / "out"
    arguments = [
        "check",
        str(_case(tmp_path)),
        "--writers",
        bridge.NAME,
        "--readers",
        bridge.NAME,
        "--out",
        str(destination),
        "--json",
    ]

    assert cli.main(arguments) == 2
    payload, _ = captured_payload(capsys)
    assert payload["status"] == "CONFIGURATION_ERROR"
    error = cast(dict[str, object], payload["error"])
    assert error["kind"] == "EXTERNAL_ENGINE_TIMEOUT"
    assert "did not answer" in cast(str, error["detail"])
    assert "finding_count" not in payload and not destination.exists()
