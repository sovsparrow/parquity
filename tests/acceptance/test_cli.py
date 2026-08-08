from __future__ import annotations

import io
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from importlib import import_module, metadata
from pathlib import Path
from typing import Protocol, cast

import pytest

import parquity
import parquity.cli as cli
from parquity.cli.output import emit
from parquity.cli.parser import Command
from parquity.engines import EngineResolution
from parquity.engines.base import EngineReader, EngineWriter
from parquity.runs.bundle import RunPublicationError
from parquity.verdicts import CellResult, EngineAvailability, EngineVersion, MatrixRun, Verdict


class _MainModule(Protocol):
    resolve_engines: Callable[[Sequence[str]], tuple[EngineResolution, ...]]


class _SmokeModule(Protocol):
    execute_smoke: Callable[[Path, Sequence[EngineWriter], Sequence[EngineReader]], MatrixRun]


def _payload(captured: pytest.CaptureFixture[str]) -> tuple[dict[str, object], str]:
    streams = captured.readouterr()
    decoded = cast(object, json.loads(streams.out))
    assert isinstance(decoded, dict)
    payload = cast(dict[str, object], decoded)
    assert payload["format"] == "parquity.cli.v1"
    return payload, streams.err


def _availability(*, available: bool) -> EngineAvailability:
    return EngineAvailability(
        "duckdb",
        "duckdb",
        "core",
        True,
        True,
        available,
        "1" if available else None,
        None if available else "Install DuckDB",
        "controlled availability",
    )


def test_lazy_package_version(monkeypatch: pytest.MonkeyPatch) -> None:
    def package_version(distribution: str) -> str:
        assert distribution == "parquity"
        return "9.8.7"

    monkeypatch.setattr(metadata, "version", package_version)
    assert parquity.__version__ == "9.8.7"
    missing_attribute = "unrelated_attribute"
    with pytest.raises(AttributeError):
        getattr(parquity, missing_attribute)


def test_help_version_and_engines_remain_provider_and_workflow_import_free() -> None:
    probe = """
import contextlib
import io
import json
import sys
from parquity import cli

forbidden = (
    "pyarrow", "duckdb", "polars", "datafusion", "fastparquet", "hypothesis",
    "parquity.model", "parquity.generation", "parquity.findings", "parquity.runs",
    "parquity.arrow_bridge", "parquity.compare", "parquity.matrix",
    "parquity.engines.pyarrow", "parquity.engines.duckdb", "parquity.engines.polars",
    "parquity.engines.datafusion", "parquity.engines.fastparquet", "parquity.cli.smoke",
)
records = []
for arguments in (["--help"], ["--version"], ["engines"]):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = cli.main(arguments)
    records.append({
        "exit_code": exit_code,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
    })
loaded = sorted(
    name for name in sys.modules
    if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
)
print(json.dumps({"records": records, "loaded": loaded}, sort_keys=True))
"""
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and literal probe.
        [sys.executable, "-c", probe],
        check=False,
        capture_output=True,
        text=True,
    )
    assert (completed.returncode, completed.stderr) == (0, "")
    result = cast(dict[str, object], json.loads(completed.stdout))
    records = cast(list[dict[str, object]], result["records"])
    assert [record["exit_code"] for record in records] == [0, 0, 0]
    assert all(record["stderr"] == "" for record in records)
    assert "Usage: parquity COMMAND [OPTIONS]" in cast(str, records[0]["stdout"])
    payloads = [
        cast(dict[str, object], json.loads(cast(str, record["stdout"]))) for record in records[1:]
    ]
    assert payloads[0]["version"] == metadata.version("parquity")
    names = [item["name"] for item in cast(list[dict[str, object]], payloads[1]["engines"])]
    assert names == ["pyarrow", "duckdb", "polars", "datafusion", "fastparquet"]
    versions = ["3.11", "3.12", "3.13", "3.14"]
    assert payloads[1]["python_support"] == dict.fromkeys(names, versions)
    assert result["loaded"] == []


def test_simple_documents_in_process(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    streams = capsys.readouterr()
    assert "Usage: parquity COMMAND [OPTIONS]" in streams.out
    assert streams.err == ""
    for arguments, command in (
        (["--version"], "version"),
        (["engines"], "engines"),
    ):
        assert cli.main(arguments) == 0
        payload, stderr = _payload(capsys)
        assert (payload["command"], payload["status"], stderr) == (command, "OK", "")


def test_real_scalar_smoke(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["smoke"])
    payload, stderr = _payload(capsys)
    results = cast(list[dict[str, object]], payload["results"])
    assert (exit_code, stderr, payload["status"]) == (0, "", "PASS")
    assert len(results) == 9
    assert {result["verdict"] for result in results} == {"PASS"}
    assert {result["diagnostic_kind"] for result in results} == {"PASS"}


def test_cli_output_is_canonical_utf8_with_literal_lf(monkeypatch: pytest.MonkeyPatch) -> None:
    translated = io.TextIOWrapper(raw := io.BytesIO(), encoding="utf-8", newline="\r\n")
    monkeypatch.setattr(sys, "stdout", translated)
    emit({"command": "probe", "value": "İstanbul"})
    expected = '{"command":"probe","format":"parquity.cli.v1","value":"İstanbul"}\n'.encode()
    assert raw.getvalue() == expected
    raw.seek(0)
    raw.truncate()
    assert cli.main(["smoke"]) == 0
    smoke = raw.getvalue()
    assert smoke.endswith(b"\n") and b"\r\n" not in smoke
    assert cast(dict[str, object], json.loads(smoke))["status"] == "PASS"
    monkeypatch.setattr(sys, "stdout", fallback := io.StringIO())
    emit({"command": "probe", "value": "İstanbul"})
    assert fallback.getvalue().encode() == expected


def test_typed_smoke_finding_maps_to_exit_one(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    smoke = cast(_SmokeModule, import_module("parquity.cli.smoke"))

    def finding(
        directory: Path,
        writers: Sequence[EngineWriter],
        readers: Sequence[EngineReader],
    ) -> MatrixRun:
        del directory, writers, readers
        result = CellResult(
            "pyarrow",
            "controlled",
            "*",
            "*",
            "write",
            Verdict.WRITE_ERROR,
            "$",
            "controlled failure",
            "ArrowInvalid",
        )
        selection = (EngineVersion("pyarrow", "controlled"),)
        return MatrixRun("controlled", (result,), (), selection, selection)

    monkeypatch.setattr(smoke, "execute_smoke", finding)
    assert cli.main(["smoke"]) == 1
    payload, stderr = _payload(capsys)
    assert stderr == "" and payload["status"] == "FAIL"


def test_unavailable_and_incomplete_core_resolution_keep_exit_two_and_three(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_module = cast(_MainModule, import_module("parquity.cli.main"))

    def unavailable(names: Sequence[str]) -> tuple[EngineResolution, ...]:
        del names
        return (EngineResolution(_availability(available=False), None, None),)

    monkeypatch.setattr(main_module, "resolve_engines", unavailable)
    assert cli.main(["smoke"]) == 2
    payload, stderr = _payload(capsys)
    assert cast(list[dict[str, object]], payload["engines"])[0]["available"] is False
    assert stderr != ""

    def incomplete(names: Sequence[str]) -> tuple[EngineResolution, ...]:
        del names
        return (EngineResolution(_availability(available=True), None, None),)

    monkeypatch.setattr(main_module, "resolve_engines", incomplete)
    assert cli.main(["smoke"]) == 3
    payload, stderr = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "TypeError"
    assert stderr.startswith("parquity: TypeError")


@pytest.mark.parametrize(
    "arguments",
    (
        [],
        ["check"],
        ["fuzz"],
        ["fuzz", "--examples"],
        ["fuzz", "--examples", "1", "--examples", "2", "--out", "unused"],
        ["fuzz", "--examples", "bad", "--seed", "2", "--out", "unused"],
        ["check", "case.json", "--unknown", "value", "--out", "unused"],
    ),
)
def test_usage_errors_are_diagnostic(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(arguments) == 2
    payload, stderr = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "USAGE_ERROR"
    assert stderr.startswith("parquity:")


@pytest.mark.parametrize(
    ("examples", "seed", "max_findings"),
    ((0, 0, 8), (1, -1, 8), (1, 2**64, 8), (1, 0, 0), (1, 0, 65)),
)
def test_fuzz_argument_bounds_exit_two(
    examples: int,
    seed: int,
    max_findings: int,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = [
        "fuzz",
        "--examples",
        str(examples),
        "--seed",
        str(seed),
        "--max-findings",
        str(max_findings),
        "--out",
        "unused",
    ]
    assert cli.main(arguments) == 2
    payload, stderr = _payload(capsys)
    assert payload["status"] == "CONFIGURATION_ERROR" and stderr.startswith("parquity:")


def test_missing_version_metadata_is_caught_after_safe_package_import() -> None:
    probe = """
from importlib import metadata
def fail(distribution):
    raise metadata.PackageNotFoundError(distribution)
metadata.version = fail
import parquity
from parquity import cli
raise SystemExit(cli.main(["--version"]))
"""
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and literal probe.
        [sys.executable, "-c", probe],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = cast(dict[str, object], json.loads(completed.stdout))
    assert completed.returncode == 3 and payload["status"] == "INTERNAL_ERROR"
    assert cast(dict[str, object], payload["error"])["kind"] == "PackageNotFoundError"


def test_module_entry_uses_public_cli_externally(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "parquity", "--version"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert (completed.returncode, completed.stderr) == (0, "")
    payload = cast(dict[str, object], json.loads(completed.stdout))
    assert payload["version"] == metadata.version("parquity")


def test_typed_evidence_rejects_incomplete_versions_and_supplies_default_kinds() -> None:
    with pytest.raises(ValueError):
        replace(_availability(available=True), version=None)
    unavailable = _availability(available=False)
    with pytest.raises(ValueError):
        replace(unavailable, installation_hint=None)
    with pytest.raises(ValueError):
        EngineVersion("", "1")
    result = CellResult("p", "1", "*", "*", "write", Verdict.WRITE_ERROR, "$", "failure")
    assert result.diagnostic_kind == "WRITE_ERROR"


def test_cli_maps_defensive_dispatch_selection_and_publication_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    main_module = import_module("parquity.cli.main")

    def inconsistent(arguments: tuple[str, ...]) -> tuple[Command, None]:
        del arguments
        return Command.CHECK, None

    monkeypatch.setattr(main_module, "parse", inconsistent)
    assert cli.main(["ignored"]) == 3
    _payload(capsys)
    monkeypatch.undo()
    arguments = ["fuzz", "--examples", "1", "--seed", "0", "--out", str(tmp_path / "out")]
    assert cli.main([*arguments, "--writers", "unknown"]) == 2
    _payload(capsys)
    workflow = import_module("parquity.generation.workflow")

    def fail(*args: object, **kwargs: object) -> None:
        raise RunPublicationError("OUTPUT_ERROR", "controlled publication failure")

    monkeypatch.setattr(workflow, "execute_fuzz", fail)
    assert cli.main(arguments) == 2
    payload, _ = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "OUTPUT_ERROR"
