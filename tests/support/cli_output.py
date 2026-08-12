import io
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

_CONTROL = re.compile(r"\x1b(?:\[[0-9;]*m|\]8;;.*?\x1b\\)")


class Output(io.TextIOBase):
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


def plain(value: bytes) -> str:
    return _CONTROL.sub("", value.decode("utf-8"))


def captured_payload(captured: pytest.CaptureFixture[str]) -> tuple[dict[str, object], str]:
    streams = captured.readouterr()
    payload = cast(dict[str, object], json.loads(streams.out))
    assert payload["format"] == "parquity.cli.v1"
    return payload, streams.err


def run_python_script(
    script: Path,
    cwd: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - executes a generated script with the test interpreter.
        [sys.executable, str(script), *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def run_json_script(
    script: Path,
    cwd: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
    returncode: int,
) -> dict[str, object]:
    completed = run_python_script(script, cwd, *arguments, environment=environment)
    assert completed.returncode == returncode
    return cast(dict[str, object], json.loads(completed.stdout))


__all__ = ["Output", "captured_payload", "plain", "run_json_script", "run_python_script"]
