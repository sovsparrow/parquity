from __future__ import annotations

import io
import json
import re
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

import parquity.cli as cli
from parquity.cli.output import configuration, emit, progress

_CONTROL = re.compile(r"\x1b(?:\[[0-9;]*m|\]8;;.*?\x1b\\)")


class _Output(io.TextIOBase):
    def __init__(self, *, tty: bool) -> None:
        self._tty = tty
        self._bytes = io.BytesIO()

    @property
    def buffer(self) -> io.BytesIO:
        return self._bytes

    def isatty(self) -> bool:
        return self._tty

    def write(self, value: str) -> int:
        self._bytes.write(value.encode("utf-8"))
        return len(value)

    def flush(self) -> None:
        return None

    def bytes(self) -> bytes:
        return self._bytes.getvalue()

    def text(self) -> str:
        return self.bytes().decode("utf-8")


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    arguments: Sequence[str],
    *,
    tty: bool,
) -> tuple[int, bytes]:
    output = _Output(tty=tty)
    monkeypatch.setattr(sys, "stdout", output)
    return cli.main(arguments), output.bytes()


def _plain(value: bytes) -> str:
    return _CONTROL.sub("", value.decode("utf-8"))


def test_terminal_engine_table_is_derived_from_the_canonical_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, machine = _invoke(monkeypatch, ["engines"], tty=False)
    document = cast(dict[str, object], json.loads(machine))
    engines = cast(list[dict[str, object]], document["engines"])
    exit_code, human = _invoke(monkeypatch, ["engines"], tty=True)
    lines = _plain(human).splitlines()
    assert exit_code == 0 and not human.lstrip().startswith(b"{")
    for engine in engines:
        name = cast(str, engine["name"])
        rows = [line.split() for line in lines if line.split()[:1] == [name]]
        assert len(rows) == 1
        row = rows[0]
        assert cast(str, engine["tier"]) in row
        assert ("yes" if engine["available"] else "no") in row
        assert ("yes" if engine["reader"] else "—") in row
        assert ("yes" if engine["writer"] else "—") in row
        assert cast(str, engine["version"]) in row


def test_terminal_smoke_matrix_preserves_every_canonical_cell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, machine = _invoke(monkeypatch, ["smoke"], tty=False)
    document = cast(dict[str, object], json.loads(machine))
    results = cast(list[dict[str, object]], document["results"])
    readers = tuple(dict.fromkeys(cast(str, item["reader"]) for item in results))
    writers = tuple(dict.fromkeys(cast(str, item["writer"]) for item in results))
    exit_code, human = _invoke(monkeypatch, ["smoke"], tty=True)
    lines = [line.split() for line in _plain(human).splitlines()]
    assert exit_code == 0 and not human.lstrip().startswith(b"{")
    assert any(all(reader in line for reader in readers) for line in lines)
    for writer in writers:
        expected = [cast(str, item["verdict"]) for item in results if item["writer"] == writer]
        assert [writer, *expected] in lines


def test_terminal_tables_preserve_unavailable_and_non_passing_cells(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engines: dict[str, object] = {
        "command": "engines",
        "status": "OK",
        "engines": [
            {
                "name": "engine-a",
                "tier": "extended",
                "available": False,
                "reader": True,
                "writer": True,
                "version": None,
            }
        ],
        "python_support": {"engine-a": ["3.12"], "engine-b": ["3.13"]},
    }
    smoke: dict[str, object] = {
        "command": "smoke",
        "status": "FAIL",
        "results": [
            {"writer": "writer-a", "reader": "reader-a", "verdict": "FAIL"},
            {"writer": "writer-a", "reader": "reader-b", "verdict": "READ_ERROR"},
        ],
    }
    for payload, values in (
        (engines, ("engine-a", "extended", "no", "yes", "—")),
        (smoke, ("writer-a", "reader-a", "reader-b", "FAIL", "READ_ERROR")),
    ):
        output = _Output(tty=True)
        monkeypatch.setattr(sys, "stdout", output)
        emit(payload)
        assert all(value in _plain(output.bytes()) for value in values)


@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        (
            {
                "command": "check",
                "status": "NO_FINDING",
                "case_id": "case-identity",
                "writers": [{"name": "writer-a"}],
                "readers": [{"name": "reader-b"}],
            },
            ("case-identity", "writer-a", "reader-b"),
        ),
        (
            {
                "command": "fuzz",
                "status": "NO_FINDING",
                "discovery_bound": 37,
                "seed": 913,
            },
            ("37", "913"),
        ),
        (
            {"command": "scan", "status": "AGREEMENT", "readers": ["reader-a", "reader-b"]},
            ("reader-a", "reader-b"),
        ),
        (
            {
                "command": "replay",
                "status": "REPRODUCED",
                "finding_id": "finding-identity",
                "version_drift": [{"name": "engine"}],
            },
            ("finding-identity", "1"),
        ),
        (
            {
                "command": "triage",
                "status": "TRIAGED",
                "finding_bundle_count": 5,
                "occurrence_count": 8,
                "symptom_family_count": 3,
                "displayed_symptom_family_count": 2,
                "symptom_families": [
                    {
                        "signal": "VALUE_DIFFERENCE",
                        "occurrence_count": 4,
                        "representative_reproduction_state": "REPRODUCED",
                        "family_id": "0123456789abcdef",
                    }
                ],
            },
            ("5", "8", "3", "2", "VALUE_DIFFERENCE", "4", "REPRODUCED", "0123456789ab"),
        ),
    ),
)
def test_terminal_summaries_retain_command_data(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    expected: tuple[str, ...],
) -> None:
    output = _Output(tty=True)
    monkeypatch.setattr(sys, "stdout", output)
    emit(payload)
    plain = _plain(output.bytes())
    assert not output.bytes().lstrip().startswith(b"{")
    assert all(value in plain for value in expected)


@pytest.mark.parametrize("command", ("check", "fuzz", "scan"))
def test_published_report_path_is_clickable_only_with_terminal_controls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    destination = tmp_path / f"{command} run"
    report = destination / "REPORT.md"
    payload: dict[str, object] = {
        "command": command,
        "status": "RUN_PUBLISHED",
        "finding_count": 2,
        "overflow_count": 0,
        "output": str(destination),
    }
    output = _Output(tty=True)
    monkeypatch.setattr(sys, "stdout", output)
    emit(payload)
    assert str(report) in _plain(output.bytes())
    assert report.resolve().as_uri().encode() in output.bytes()
    assert b"\x1b]8;;" in output.bytes()

    for environment in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        plain_output = _Output(tty=True)
        monkeypatch.setattr(sys, "stdout", plain_output)
        emit(payload)
        assert str(report) in plain_output.text()
        assert b"\x1b" not in plain_output.bytes()


@pytest.mark.parametrize("arguments", (("--version",), ("engines",), ("smoke",)))
def test_json_flag_on_a_terminal_matches_non_terminal_bytes(
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
) -> None:
    _, expected = _invoke(monkeypatch, arguments, tty=False)
    exit_code, forced = _invoke(monkeypatch, (*arguments, "--json"), tty=True)
    assert exit_code in (0, 1)
    assert forced == expected
    assert forced.endswith(b"\n") and not forced.endswith(b"\n\n")
    assert b"\x1b" not in forced
    assert cast(dict[str, object], json.loads(forced))["format"] == "parquity.cli.v1"


def test_terminal_version_is_human_and_help_declares_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, machine = _invoke(monkeypatch, ["--version"], tty=False)
    version = cast(dict[str, object], json.loads(machine))["version"]
    exit_code, human = _invoke(monkeypatch, ["--version"], tty=True)
    assert exit_code == 0
    assert _plain(human).strip().split() == ["parquity", version]
    _, help_output = _invoke(monkeypatch, ["--help"], tty=True)
    assert "--json" in _plain(help_output)


def test_help_controls_follow_terminal_policy_and_fit_eighty_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    _, terminal = _invoke(monkeypatch, ["-h"], tty=True)
    _, piped = _invoke(monkeypatch, ["-h"], tty=False)
    assert b"\x1b" in terminal
    assert b"\x1b" not in piped
    assert _plain(terminal) == piped.decode("utf-8")
    assert max(map(len, _plain(terminal).splitlines())) <= 80

    monkeypatch.setenv("NO_COLOR", "1")
    _, no_color = _invoke(monkeypatch, ["-h"], tty=True)
    assert no_color == piped


def test_error_detail_is_styled_only_on_a_capable_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detail = "$.rows[0] requires an integer"
    for tty, environment, expects_controls in (
        (True, {"TERM": "xterm-256color"}, True),
        (True, {"TERM": "xterm-256color", "NO_COLOR": "1"}, False),
        (True, {"TERM": "dumb"}, False),
        (False, {"TERM": "xterm-256color"}, False),
    ):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        stdout = _Output(tty=tty)
        stderr = _Output(tty=tty)
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(sys, "stderr", stderr)
        assert configuration("check", "INVALID_CASE", detail) == 2
        assert detail in _plain(stderr.bytes())
        assert (b"\x1b" in stderr.bytes()) is expects_controls
        if tty:
            assert stdout.bytes() == b""
        else:
            error = cast(dict[str, object], json.loads(stdout.bytes()))["error"]
            assert cast(dict[str, object], error)["detail"] == detail


def test_progress_is_transient_on_a_terminal_and_silent_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stdout = _Output(tty=True)
    stderr = _Output(tty=True)
    written = threading.Event()
    write = stderr.write
    moments = iter((0.0, 61.0))
    monkeypatch.setattr("parquity.cli.progress.time.monotonic", lambda: next(moments, 61.0))

    def signal_write(value: str) -> int:
        result = write(value)
        written.set()
        return result

    monkeypatch.setattr(stderr, "write", signal_write)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    with progress("Checking evidence"):
        assert written.wait(1)
        emit({"command": "probe", "status": "OK"})
    assert "Checking evidence · 1m 01s" in stderr.text() and stderr.text().endswith("\r")
    written.clear()
    with progress("Completing evidence"):
        assert written.wait(1)

    monkeypatch.setenv("CI", "1")
    silent = _Output(tty=True)
    monkeypatch.setattr(sys, "stderr", silent)
    with progress("Must stay silent"):
        pass
    assert silent.bytes() == b""
