from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import os
import sys
from collections.abc import Sequence
from multiprocessing.connection import Connection
from pathlib import Path
from typing import cast

import pytest

import parquity.cli as cli
from parquity.cli.output import configuration
from parquity.cli.parser import UsageError, parse
from parquity.cli.spec import COMMAND_SPECS
from tests.support.cli_import_contract import loaded_capability_modules
from tests.support.cli_output import Output, plain

_SPEC_OPTIONS = {spec.command.value: spec.option_names for spec in COMMAND_SPECS}


def _invoke(
    monkeypatch: pytest.MonkeyPatch, arguments: Sequence[str], *, tty: bool
) -> tuple[int, bytes]:
    output = Output(tty=tty)
    monkeypatch.setattr(sys, "stdout", output)
    return cli.main(arguments), output.bytes()


_TARGETS = (
    (
        None,
        "Usage: parquity COMMAND [OPTIONS]",
        ("engines", "smoke", "check", "fuzz", "scan", "replay", "--version"),
    ),
    ("engines", "Usage: parquity engines", ("--help", "-h", "installed Parquet engines")),
    ("smoke", "Usage: parquity smoke", ("--help", "-h", "built-in compatibility case")),
    (
        "check",
        "Usage: parquity check CASE_FILE --out OUTPUT_DIR",
        (
            "CASE_FILE",
            "OUTPUT_DIR",
            *_SPEC_OPTIONS["check"],
            "default: pyarrow,duckdb,polars",
            "default: none",
            "parquity check ./case.json --out ./check-run",
        ),
    ),
    (
        "fuzz",
        "Usage: parquity fuzz --examples N --seed N --out OUTPUT_DIR",
        (
            *_SPEC_OPTIONS["fuzz"],
            "CASE_FILE",
            "OUTPUT_DIR",
            "default: 8",
            "[0, 18446744073709551615]",
            "1 to 64",
            "default: pyarrow,duckdb,polars",
            "default: none",
            "Case grammar with `rows: []`",
            "omit to generate both schema and rows",
            "Save 1 to 64 reproducers",
            "Equivalent generated failures share one reproducer",
            "distinct failure beyond the --max-saved limit",
            "Each reproducer includes the exact table",
        ),
    ),
    (
        "scan",
        "Usage: parquity scan FILE_OR_DIR --out OUTPUT_DIR",
        (
            "FILE_OR_DIR",
            "OUTPUT_DIR",
            *_SPEC_OPTIONS["scan"],
            "default: pyarrow,duckdb,polars",
            "default: 30",
            "[1, 300]",
            "default: 32",
            "1 to 64",
        ),
    ),
    (
        "replay",
        "Usage: parquity replay RUN_DIR",
        ("RUN_DIR", "saved reproducer", "recorded failure", "--help", "-h"),
    ),
)


@pytest.mark.parametrize(("target", "usage", "required"), _TARGETS)
def test_help_is_human_readable_and_complete(
    target: str | None,
    usage: str,
    required: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = ["--help"] if target is None else [target, "--help"]
    assert cli.main(arguments) == 0
    streams = capsys.readouterr()
    assert streams.err == ""
    assert usage in streams.out
    assert not streams.out.lstrip().startswith("{")
    normalized = " ".join(streams.out.split())
    assert all(item in normalized for item in required)
    if target == "fuzz":
        assert "overflow" not in streams.out.lower()
    if target is not None:
        assert all(f"  {code}  " in streams.out for code in range(4))
    else:
        commands = streams.out.split("Commands:\n", 1)[1].split("\n\nOptions:", 1)[0]
        assert tuple(line.split()[0] for line in commands.splitlines()) == (
            "engines",
            "smoke",
            "check",
            "fuzz",
            "scan",
            "replay",
        )


def _fresh_process_help_probe(directory: str, connection: Connection) -> None:
    os.chdir(directory)
    targets = (None, "engines", "smoke", "check", "fuzz", "scan", "replay")
    before = sorted(path.name for path in Path.cwd().iterdir())
    records: list[tuple[int, bool, str]] = []
    for target in (*targets, None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        flag = "-h" if target is None and len(records) == len(targets) else "--help"
        arguments = [flag] if target is None else [target, flag]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(arguments)
        records.append((exit_code, bool(stdout.getvalue()), stderr.getvalue()))
    after = sorted(path.name for path in Path.cwd().iterdir())
    loaded = loaded_capability_modules(sys.modules)
    connection.send({"records": records, "loaded": loaded, "unchanged": before == after})
    connection.close()


def test_all_help_targets_are_import_and_work_free_in_a_fresh_process(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_fresh_process_help_probe, args=(str(tmp_path), sender))
    process.start()
    sender.close()
    result = receiver.recv()
    receiver.close()
    process.join()
    assert process.exitcode == 0
    assert result["unchanged"] is True
    assert result["loaded"] == ()
    assert all(record == (0, True, "") for record in result["records"])


def test_arbitrary_unknown_command_is_rejected_by_the_parser(
    capsys: pytest.CaptureFixture[str],
) -> None:
    unknown = "not-a-parquity-command"
    with pytest.raises(UsageError):
        parse((unknown,))
    assert cli.main([unknown]) == 2
    rejected = capsys.readouterr()
    payload = cast(dict[str, object], json.loads(rejected.out))
    assert cast(dict[str, object], payload["error"])["kind"] == "USAGE_ERROR"


def test_json_flag_on_a_terminal_matches_non_terminal_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = ("engines",)
    _, expected = _invoke(monkeypatch, arguments, tty=False)
    exit_code, forced = _invoke(monkeypatch, (*arguments, "--json"), tty=True)
    assert exit_code in (0, 1) and forced == expected
    assert forced.endswith(b"\n") and not forced.endswith(b"\n\n") and b"\x1b" not in forced
    assert cast(dict[str, object], json.loads(forced))["format"] == "parquity.cli.v1"


def test_terminal_version_is_human_and_help_declares_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _, machine = _invoke(monkeypatch, ["--version"], tty=False)
    version = cast(dict[str, object], json.loads(machine))["version"]
    exit_code, human = _invoke(monkeypatch, ["--version"], tty=True)
    assert exit_code == 0 and plain(human).strip().split() == ["parquity", version]
    _, help_output = _invoke(monkeypatch, ["--help"], tty=True)
    assert "--json" in plain(help_output)


def test_help_fits_eighty_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, piped = _invoke(monkeypatch, ["-h"], tty=False)
    assert max(map(len, piped.decode().splitlines())) <= 80


def test_error_detail_is_styled_only_on_a_capable_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    detail = "$.rows[0] requires an integer"
    settings = (
        (True, {"TERM": "xterm-256color"}, True),
        (True, {"TERM": "xterm-256color", "NO_COLOR": "1"}, False),
        (True, {"TERM": "dumb"}, False),
        (False, {"TERM": "xterm-256color"}, False),
    )
    for tty, environment, expects_controls in settings:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TERM", raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        stdout, stderr = Output(tty=tty), Output(tty=tty)
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(sys, "stderr", stderr)
        assert configuration("check", "INVALID_CASE", detail) == 2
        assert detail in plain(stderr.bytes()) and (b"\x1b" in stderr.bytes()) is expects_controls
        if tty:
            assert stdout.bytes() == b""
        else:
            error = cast(dict[str, object], json.loads(stdout.bytes()))["error"]
            assert cast(dict[str, object], error)["detail"] == detail
