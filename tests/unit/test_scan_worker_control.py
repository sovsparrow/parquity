from __future__ import annotations

import sys
from pathlib import Path

import pyarrow as pa
import pytest

import parquity.scans.worker as worker_module
from parquity.engines import resolve_engine
from parquity.scans.control import CONTROL_NAME, WorkerControl


def _call_worker(
    source: Path,
    directory: Path,
    version: str,
    monkeypatch: pytest.MonkeyPatch,
) -> WorkerControl:
    directory.mkdir()
    arguments = ["parquity.scans.worker", "--engine", "pyarrow", "--version", version]
    arguments += ["--input", str(source), "--out", str(directory)]
    monkeypatch.setattr(sys, "argv", arguments)
    assert worker_module.main() == 0
    return WorkerControl.from_json((directory / CONTROL_NAME).read_bytes())


def test_worker_emits_success_provider_error_and_internal_controls(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    resolution = resolve_engine("pyarrow")
    assert resolution.writer is not None
    version = resolution.writer.identity.version
    valid = tmp_path / "valid.parquet"
    resolution.writer.write(pa.table({"value": [1]}), valid)

    success = _call_worker(valid, tmp_path / "success", version, monkeypatch)
    assert (success.outcome, success.engine, success.engine_version) == (
        "SUCCESS",
        "pyarrow",
        version,
    )
    assert success.metadata is not None
    assert (success.metadata.row_count, success.metadata.column_count) == (1, 1)
    assert (tmp_path / "success" / "observation.arrow").is_file()
    invalid = tmp_path / "invalid.parquet"
    invalid.write_bytes(b"not parquet")
    provider = _call_worker(invalid, tmp_path / "provider", version, monkeypatch)
    assert (provider.outcome, provider.engine, provider.engine_version) == (
        "PROVIDER_ERROR",
        "pyarrow",
        version,
    )
    assert provider.metadata is None and provider.diagnostic_kind
    assert len(provider.detail) <= 500
    internal = _call_worker(valid, tmp_path / "internal", "changed", monkeypatch)
    assert (internal.outcome, internal.diagnostic_kind) == ("INTERNAL_ERROR", "RuntimeError")
    assert internal.detail == "recorded reader is unavailable or changed"
