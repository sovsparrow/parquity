from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import IO, cast

import pyarrow as pa
import pytest

import parquity.process as process_module
import parquity.scans.workflow as workflow_module
import parquity.worker as worker_module
from parquity.engines import resolve_engine, resolve_reader_selection
from parquity.process import (
    WorkerInternalError,
    WorkerOutcome,
    WorkerProtocolError,
    run_worker_process,
)
from parquity.scans.discovery import DiscoveredFile, ScanConfigurationError, Snapshot
from parquity.scans.workflow import execute_scan as scan

CHILD = Path(__file__).parents[1] / "support" / "scan_child_program.py"


def _run(mode: str, root: Path, *extra: Path) -> WorkerOutcome:
    private = root / "worker"
    argv = [sys.executable, str(CHILD), mode, str(private), *(str(path) for path in extra)]
    return run_worker_process(
        argv,
        private,
        expected_engine="reader",
        expected_version="1.0",
        timeout_seconds=1,
        owned_root=root,
    )


def test_success_validates_and_returns_parent_owned_artifact_then_cleans(tmp_path: Path) -> None:
    outcome = _run("success", tmp_path)
    assert outcome.kind == "SUCCESS"
    assert outcome.artifact == b"controlled artifact"
    assert outcome.metadata is not None
    assert outcome.metadata.row_count == 2
    assert not (tmp_path / "worker").exists()


def test_provider_error_is_typed_and_private_inventory_is_removed(tmp_path: Path) -> None:
    outcome = _run("provider", tmp_path)
    assert outcome.kind == "PROVIDER_ERROR"
    assert outcome.diagnostic_kind == "ControlledError"
    assert outcome.artifact is None
    assert not (tmp_path / "worker").exists()


def test_timeout_terminates_reaps_drains_and_removes_resources(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    outcome = _run("block", tmp_path, ready)
    assert ready.read_text(encoding="utf-8") == "ready"
    assert outcome.kind == "TIMEOUT"
    assert outcome.terminated
    assert not (tmp_path / "worker").exists()


def test_timeout_kills_a_child_that_does_not_exit_during_grace(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    outcome = _run("resist", tmp_path, ready)
    assert ready.read_text(encoding="utf-8") == "ready"
    assert outcome.kind == "TIMEOUT"
    assert outcome.terminated
    assert outcome.killed
    assert not (tmp_path / "worker").exists()


def test_timeout_kills_a_resistant_descendant_and_reaps_the_direct_child(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "ready"
    outcome = _run("descendant", tmp_path, ready)
    direct, descendant = (int(value) for value in ready.read_text(encoding="utf-8").split())
    assert outcome.kind == "TIMEOUT"
    assert outcome.terminated and outcome.killed
    _require_process_absent(direct)
    _require_process_absent(descendant)
    assert not (tmp_path / "worker").exists()


def _require_process_absent(pid: int) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} still exists")


def test_scan_spawns_one_real_child_per_engine_file_and_none_after_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = process_module.subprocess.Popen
    launched: list[process_module.subprocess.Popen[bytes]] = []

    def recording_popen(
        arguments: Sequence[str],
        *,
        stdin: int,
        stdout: int,
        stderr: int,
        shell: bool,
        start_new_session: bool,
    ) -> process_module.subprocess.Popen[bytes]:
        child = original(
            list(arguments),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=shell,
            start_new_session=start_new_session,
        )
        launched.append(child)
        return child

    monkeypatch.setattr(process_module.subprocess, "Popen", recording_popen)
    source = tmp_path / "source"
    source.mkdir()
    for name in ("a.parquet", "b.parquet"):
        (source / name).write_bytes(b"not parquet")
    selection = resolve_reader_selection("duckdb,pyarrow")
    result = scan(source, tmp_path / "result", selection, timeout_seconds=30, max_findings=4)
    assert selection.reader_names == ("pyarrow", "duckdb") and result.evaluated_files == 2
    assert len(launched) == 4
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(ScanConfigurationError):
        scan(source, occupied, selection, timeout_seconds=30, max_findings=4)
    with pytest.raises(ScanConfigurationError):
        scan(
            tmp_path / "missing", tmp_path / "unused", selection, timeout_seconds=30, max_findings=4
        )
    assert len(launched) == 4
    moving = tmp_path / "moving-source"
    moving.write_bytes(b"not parquet")
    original_snapshot = workflow_module.discovery.snapshot_file

    def replace_before_snapshot(item: DiscoveredFile, directory: Path) -> Snapshot:
        moving.unlink()
        moving.mkdir()
        return original_snapshot(item, directory)

    monkeypatch.setattr(workflow_module.discovery, "snapshot_file", replace_before_snapshot)
    with pytest.raises(ScanConfigurationError) as drift:
        scan(moving, tmp_path / "moved-run", selection, timeout_seconds=30, max_findings=4)
    assert drift.value.kind == "INPUT_DRIFT" and len(launched) == 4 and moving.is_dir()


def test_abnormal_exit_is_a_neutral_process_crash(tmp_path: Path) -> None:
    outcome = _run("crash", tmp_path)
    assert outcome.kind == "PROCESS_CRASH"
    assert outcome.diagnostic_kind == "PROCESS_CRASH"
    assert not (tmp_path / "worker").exists()


def test_nonzero_exit_without_control_is_a_process_crash(tmp_path: Path) -> None:
    outcome = _run("exit", tmp_path)
    assert outcome.kind == outcome.diagnostic_kind == "PROCESS_CRASH"
    assert outcome.detail == outcome.stderr == "" and not (tmp_path / "worker").exists()


@pytest.mark.parametrize(
    "mode",
    (
        "malformed",
        "empty",
        "extra",
        "oversized",
        "bad-digest",
        "noncanonical",
        "wrong-engine",
        "incomplete",
        "bad-control-digest",
        "extra-artifact",
        "artifact-directory",
    ),
)
def test_protocol_and_artifact_failures_fail_closed_and_clean(mode: str, tmp_path: Path) -> None:
    with pytest.raises(WorkerProtocolError):
        _run(mode, tmp_path)
    assert not (tmp_path / "worker").exists()


def test_symlink_artifact_is_rejected_and_external_target_is_preserved(tmp_path: Path) -> None:
    target = tmp_path / "external"
    with pytest.raises(WorkerProtocolError):
        _run("artifact-symlink", tmp_path, target)
    assert target.read_bytes() == b"controlled artifact"
    assert not (tmp_path / "worker").exists()


def test_runner_rejects_invalid_deadline_creation_and_spawn(tmp_path: Path) -> None:
    private = tmp_path / "invalid"
    with pytest.raises(ValueError):
        run_worker_process(
            [], private, expected_engine="x", expected_version="1", timeout_seconds=0
        )
    private.mkdir()
    with pytest.raises(WorkerInternalError):
        run_worker_process(
            [], private, expected_engine="x", expected_version="1", timeout_seconds=1
        )
    spawn = tmp_path / "spawn"
    with pytest.raises(WorkerInternalError):
        run_worker_process(
            [str(tmp_path / "missing-program")],
            spawn,
            expected_engine="x",
            expected_version="1",
            timeout_seconds=1,
        )
    assert not spawn.exists()


def test_controlled_unexpected_worker_exception_is_internal(tmp_path: Path) -> None:
    with pytest.raises(WorkerInternalError):
        _run("internal", tmp_path)
    assert not (tmp_path / "worker").exists()


def test_stderr_is_drained_bounded_and_owned_paths_are_normalized(tmp_path: Path) -> None:
    outcome = _run("stderr", tmp_path)
    assert (outcome.kind, outcome.stderr_truncated) == ("PROVIDER_ERROR", True)
    assert len(outcome.stderr.encode()) <= 64 * 1024
    assert "<PARQUITY_TEMP>" in outcome.stderr and str(tmp_path) not in outcome.stderr
    invalid = _run("invalid-stderr", tmp_path)
    assert (invalid.kind, invalid.stderr_truncated) == ("PROCESS_CRASH", True)
    assert 0 < len(invalid.stderr.encode("utf-8")) <= 64 * 1024
    assert not (tmp_path / "worker").exists()


def test_real_handle_is_reaped_once_and_both_streams_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = process_module.subprocess.Popen
    handles: list[_RecordingProcess] = []

    def recording_popen(
        arguments: Sequence[str],
        *,
        stdin: int,
        stdout: int,
        stderr: int,
        shell: bool,
        start_new_session: bool,
    ) -> _RecordingProcess:
        handle = _RecordingProcess(
            original(
                list(arguments),
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                shell=shell,
                start_new_session=start_new_session,
            )
        )
        handles.append(handle)
        return handle

    monkeypatch.setattr(process_module.subprocess, "Popen", recording_popen)

    assert _run("success", tmp_path).kind == "SUCCESS"
    assert handles[0].successful_waits == 1
    assert cast(IO[bytes], handles[0].stdout).closed
    assert cast(IO[bytes], handles[0].stderr).closed


class _RecordingProcess:
    def __init__(self, process: process_module.subprocess.Popen[bytes]) -> None:
        self.process = process
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.successful_waits = 0

    @property
    def pid(self) -> int:
        return self.process.pid

    def wait(self, timeout: float | None = None) -> int:
        result = self.process.wait(timeout=timeout)
        self.successful_waits += 1
        return result


def _call_worker(
    source: Path,
    directory: Path,
    version: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> dict[str, object]:
    directory.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "parquity.worker",
            "--engine",
            "pyarrow",
            "--version",
            version,
            "--input",
            str(source),
            "--out",
            str(directory),
        ],
    )
    assert worker_module.main() == 0
    streams = capsys.readouterr()
    assert streams.err == ""
    return cast(dict[str, object], json.loads(streams.out))


def test_worker_emits_success_provider_error_and_internal_controls(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    resolution = resolve_engine("pyarrow")
    assert resolution.writer is not None
    version = resolution.writer.identity.version
    valid = tmp_path / "valid.parquet"
    resolution.writer.write(pa.table({"value": [1]}), valid)

    success = _call_worker(valid, tmp_path / "success", version, monkeypatch, capsys)
    assert success["outcome"] == "SUCCESS"
    assert (tmp_path / "success" / "observation.arrow").is_file()
    invalid = tmp_path / "invalid.parquet"
    invalid.write_bytes(b"not parquet")
    provider = _call_worker(invalid, tmp_path / "provider", version, monkeypatch, capsys)
    assert provider["outcome"] == "PROVIDER_ERROR"
    internal = _call_worker(valid, tmp_path / "internal", "changed", monkeypatch, capsys)
    assert internal["outcome"] == "INTERNAL_ERROR"
    monkeypatch.setattr(sys, "argv", ["parquity.worker"])
    with pytest.raises(ValueError):
        worker_module.main()
