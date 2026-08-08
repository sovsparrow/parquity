from __future__ import annotations

import contextlib
import io
import multiprocessing
import os
import sys
from multiprocessing.connection import Connection
from pathlib import Path

import pytest

import parquity.cli as cli

_TARGETS = (
    (
        None,
        "Usage: parquity COMMAND [OPTIONS]",
        ("engines", "smoke", "check", "fuzz", "scan", "replay", "triage", "--version"),
    ),
    ("engines", "Usage: parquity engines", ("--help", "-h", "installed Parquet engines")),
    ("smoke", "Usage: parquity smoke", ("--help", "-h", "built-in compatibility case")),
    (
        "check",
        "Usage: parquity check CASE_FILE --out OUTPUT_DIR",
        (
            "CASE_FILE",
            "OUTPUT_DIR",
            "--out",
            "--writers",
            "--readers",
            "--writer-profiles",
            "default: pyarrow,duckdb,polars",
            "default: none",
            "parquity check ./case.json --out ./check-run",
        ),
    ),
    (
        "fuzz",
        "Usage: parquity fuzz --examples N --seed N --out OUTPUT_DIR",
        (
            "--examples",
            "--seed",
            "--out",
            "--schema",
            "CASE_FILE",
            "OUTPUT_DIR",
            "--max-findings",
            "default: 8",
            "[0, 18446744073709551615]",
            "1 to 64",
            "--writers",
            "--readers",
            "--writer-profiles",
            "default: pyarrow,duckdb,polars",
            "default: none",
            "omit to generate both schema and rows",
        ),
    ),
    (
        "scan",
        "Usage: parquity scan FILE_OR_DIR --out OUTPUT_DIR",
        (
            "FILE_OR_DIR",
            "OUTPUT_DIR",
            "--out",
            "--engines",
            "default: pyarrow,duckdb,polars",
            "--timeout",
            "default: 30",
            "[1, 300]",
            "--max-findings",
            "default: 32",
            "1 to 64",
        ),
    ),
    ("replay", "Usage: parquity replay RUN_DIR", ("RUN_DIR", "recorded target", "--help", "-h")),
    (
        "triage",
        "Usage: parquity triage RUN_DIR",
        (
            "RUN_DIR",
            "--focus",
            "all|execution|data|schema",
            "default: all",
            "--replay-evidence",
            "NOT_CHECKED",
        ),
    ),
)


@pytest.mark.parametrize(("target", "usage", "required"), _TARGETS)
@pytest.mark.parametrize("flag", ("--help", "-h"))
def test_help_is_human_readable_and_complete(
    target: str | None,
    usage: str,
    required: tuple[str, ...],
    flag: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    before = tuple(tmp_path.iterdir())
    arguments = [flag] if target is None else [target, flag]
    assert cli.main(arguments) == 0
    streams = capsys.readouterr()
    assert streams.err == ""
    assert usage in streams.out
    assert not streams.out.lstrip().startswith("{")
    assert all(item in streams.out for item in required)
    if target is not None:
        assert all(f"  {code}  " in streams.out for code in range(4))
    assert tuple(tmp_path.iterdir()) == before


def _fresh_process_help_probe(directory: str, connection: Connection) -> None:
    os.chdir(directory)
    forbidden = (
        "pyarrow",
        "duckdb",
        "polars",
        "datafusion",
        "fastparquet",
        "hypothesis",
        "parquity.model",
        "parquity.generation",
        "parquity.findings",
        "parquity.runs",
        "parquity.scans",
        "parquity.triage",
        "parquity.arrow_bridge",
        "parquity.compare",
        "parquity.matrix",
        "parquity.engines.pyarrow",
        "parquity.engines.duckdb",
        "parquity.engines.polars",
        "parquity.engines.datafusion",
        "parquity.engines.fastparquet",
        "parquity.cli.smoke",
        "parquity.cli.generated",
    )
    targets = (None, "engines", "smoke", "check", "fuzz", "scan", "replay", "triage")
    before = sorted(path.name for path in Path.cwd().iterdir())
    records: list[tuple[int, bool, str]] = []
    for target in targets:
        for flag in ("--help", "-h"):
            stdout = io.StringIO()
            stderr = io.StringIO()
            arguments = [flag] if target is None else [target, flag]
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = cli.main(arguments)
            records.append((exit_code, bool(stdout.getvalue()), stderr.getvalue()))
    after = sorted(path.name for path in Path.cwd().iterdir())
    loaded = sorted(
        name
        for name in sys.modules
        if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
    )
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
    assert result["loaded"] == []
    assert all(record == (0, True, "") for record in result["records"])
