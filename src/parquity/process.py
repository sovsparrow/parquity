from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NamedTuple, cast

from .findings import json_codec as codec
from .scans.observations import MAX_OBSERVATION_BYTES, ObservationMetadata
from .scans.records import canonical_bytes

MAX_STDOUT_BYTES, MAX_STDERR_BYTES = 16 * 1024, 64 * 1024
TERMINATION_GRACE_SECONDS = 1.0
WORKER_CONTROL_FORMAT = "parquity.worker-control.v1"
ARTIFACT_NAME = "observation.arrow"
_CONTROL_KEYS = "format outcome engine engine_version artifact artifact_bytes artifact_sha256 row_count column_count schema_sha256 diagnostic_kind detail"


class WorkerInternalError(RuntimeError): ...


class WorkerLimitError(ValueError): ...


class WorkerProtocolError(RuntimeError): ...


class WorkerUnavailableError(RuntimeError): ...


class WorkerControl(NamedTuple):
    outcome: str
    engine: str
    engine_version: str
    metadata: ObservationMetadata | None
    diagnostic_kind: str
    detail: str

    def to_data(self) -> dict[str, object]:
        metadata = self.metadata
        return {
            "format": WORKER_CONTROL_FORMAT,
            "outcome": self.outcome,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "artifact": ARTIFACT_NAME if metadata is not None else None,
            "artifact_bytes": None if metadata is None else metadata.byte_count,
            "artifact_sha256": None if metadata is None else metadata.sha256,
            "row_count": None if metadata is None else metadata.row_count,
            "column_count": None if metadata is None else metadata.column_count,
            "schema_sha256": None if metadata is None else metadata.schema_sha256,
            "diagnostic_kind": self.diagnostic_kind,
            "detail": self.detail,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_data())

    @classmethod
    def from_json(cls, payload: bytes) -> WorkerControl:
        try:
            decoded = codec.decode(payload)
            data = codec.mapping(decoded, "worker control")
            if set(data) != set(_CONTROL_KEYS.split()) or data["format"] != WORKER_CONTROL_FORMAT:
                raise WorkerProtocolError("worker control fields are malformed")
            metadata = _control_metadata(data)
            if data["artifact"] != (ARTIFACT_NAME if metadata is not None else None):
                raise WorkerProtocolError("worker artifact evidence is malformed")
            control = cls(
                codec.string(data["outcome"], "outcome"),
                codec.string(data["engine"], "engine"),
                codec.string(data["engine_version"], "engine version"),
                metadata,
                codec.string(data["diagnostic_kind"], "diagnostic kind"),
                codec.string(data["detail"], "detail"),
            )
            allowed = ("SUCCESS", "PROVIDER_ERROR", "LIMIT_ERROR", "INTERNAL_ERROR")
            if (
                control.outcome not in allowed
                or not all((control.engine, control.engine_version, control.diagnostic_kind))
                or (control.outcome == "SUCCESS") != (metadata is not None)
            ):
                raise WorkerProtocolError("worker control identity is malformed")
        except WorkerProtocolError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise WorkerProtocolError("worker control is malformed") from error
        if control.canonical_bytes() != payload:
            raise WorkerProtocolError("worker control is not canonical")
        return control


class WorkerOutcome(NamedTuple):
    kind: str
    engine: str
    engine_version: str
    diagnostic_kind: str
    detail: str
    stderr: str
    stderr_truncated: bool
    artifact: bytes | None = None
    metadata: ObservationMetadata | None = None
    terminated: bool = False
    killed: bool = False


@dataclass(slots=True)
class _Capture:
    limit: int
    payload: bytearray
    truncated: bool = False
    error: OSError | None = None

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(8192):
                available = max(0, self.limit - len(self.payload))
                self.payload.extend(chunk[:available])
                self.truncated = self.truncated or len(chunk) > available
        except OSError as error:
            self.error = error
        finally:
            stream.close()


def run_worker_process(
    argv: Sequence[str],
    private_directory: Path,
    *,
    expected_engine: str,
    expected_version: str,
    timeout_seconds: int,
    owned_root: Path | None = None,
) -> WorkerOutcome:
    if not 1 <= timeout_seconds <= 300:
        raise ValueError("worker timeout must be in [1, 300]")
    if os.name != "posix" or not hasattr(os, "killpg"):
        raise WorkerUnavailableError("worker process-group isolation is unavailable")
    try:
        private_directory.mkdir()
    except OSError as error:
        raise WorkerInternalError("private worker directory could not be created") from error
    try:
        root = private_directory.parent if owned_root is None else owned_root
        return _execute(
            argv, private_directory, expected_engine, expected_version, timeout_seconds, root
        )
    finally:
        try:
            shutil.rmtree(private_directory)
        except OSError as error:
            raise WorkerInternalError("private worker resources could not be removed") from error


def _execute(
    argv: Sequence[str],
    private_directory: Path,
    engine: str,
    version: str,
    timeout: int,
    owned_root: Path,
) -> WorkerOutcome:
    process = _spawn(argv)
    stdout = _Capture(MAX_STDOUT_BYTES, bytearray())
    stderr = _Capture(MAX_STDERR_BYTES, bytearray())
    streams = (cast(BinaryIO, process.stdout), cast(BinaryIO, process.stderr))
    threads = tuple(
        threading.Thread(target=capture.drain, args=(stream,), daemon=True)
        for capture, stream in zip((stdout, stderr), streams, strict=True)
    )
    for thread in threads:
        thread.start()
    try:
        state = _wait_for_process(process, timeout)
    finally:
        for thread in threads:
            thread.join(TERMINATION_GRACE_SECONDS)
    drain_failed = any(thread.is_alive() for thread in threads) or stdout.error or stderr.error
    if drain_failed:
        try:
            _shutdown_group(process, reap=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise WorkerInternalError("worker streams could not be drained") from error
        for thread in threads:
            thread.join(TERMINATION_GRACE_SECONDS)
        raise WorkerInternalError("worker streams could not be drained")
    return_code, timed_out, terminated, killed = state
    normalized_stderr = _normalize(bytes(stderr.payload), owned_root)
    encoded_stderr = normalized_stderr.encode("utf-8")
    retained_stderr = encoded_stderr[:MAX_STDERR_BYTES].decode("utf-8", errors="ignore")
    stderr_truncated = stderr.truncated or len(encoded_stderr) > MAX_STDERR_BYTES
    if timed_out or return_code:
        if not timed_out and stdout.payload:
            _read_control(stdout, engine, version)
            raise WorkerProtocolError("worker control record conflicts with its exit status")
        kind = "TIMEOUT" if timed_out else "PROCESS_CRASH"
        values = (kind, engine, version, kind, retained_stderr, retained_stderr, stderr_truncated)
        return WorkerOutcome(*values, terminated=terminated, killed=killed)
    control = _read_control(stdout, engine, version)
    detail = _normalize(control.detail.encode(), owned_root)
    failures = {
        "INTERNAL_ERROR": WorkerInternalError(f"{control.diagnostic_kind}: {detail}"),
        "LIMIT_ERROR": WorkerLimitError(detail),
    }
    if failure := failures.get(control.outcome):
        raise failure
    if control.outcome == "PROVIDER_ERROR":
        _require_inventory(private_directory, set())
        values = (control.outcome, engine, version, control.diagnostic_kind, detail)
        return WorkerOutcome(*values, retained_stderr, stderr_truncated)
    artifact = _validated_artifact(private_directory, cast(ObservationMetadata, control.metadata))
    values = (control.outcome, engine, version, control.diagnostic_kind, detail)
    return WorkerOutcome(*values, retained_stderr, stderr_truncated, artifact, control.metadata)


def _read_control(stdout: _Capture, engine: str, version: str) -> WorkerControl:
    if stdout.truncated:
        raise WorkerProtocolError("worker stdout exceeds 16 KiB")
    raw = bytes(stdout.payload)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise WorkerProtocolError("worker must emit exactly one control record")
    control = WorkerControl.from_json(raw[:-1])
    if control.engine != engine or control.engine_version != version:
        raise WorkerProtocolError("worker control identity does not match the request")
    return control


def _spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(  # noqa: S603 - caller supplies a shell-free worker argv.
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError as error:
        raise WorkerInternalError("worker process could not be started") from error


def _wait_for_process(child: subprocess.Popen[bytes], timeout: int) -> tuple[int, bool, bool, bool]:
    try:
        try:
            return child.wait(timeout=float(timeout)), False, False, False
        except subprocess.TimeoutExpired:
            pass
        return_code, terminated, killed = _shutdown_group(child, reap=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        with suppress(OSError):
            os.killpg(child.pid, signal.SIGKILL)
        if child.returncode is None:
            with suppress(OSError, subprocess.TimeoutExpired):
                child.wait(timeout=TERMINATION_GRACE_SECONDS)
        raise WorkerInternalError("worker process group could not be shut down") from error
    return cast(int, return_code), True, terminated, killed


def _shutdown_group(
    process: subprocess.Popen[bytes], *, reap: bool
) -> tuple[int | None, bool, bool]:
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    terminated = _signal_group(process.pid, signal.SIGTERM)
    return_code: int | None = None
    if reap:
        with suppress(subprocess.TimeoutExpired):
            return_code = process.wait(timeout=TERMINATION_GRACE_SECONDS)
    if _wait_group_absent(process.pid, deadline) and (return_code is not None or not reap):
        return return_code, terminated, False
    killed = _signal_group(process.pid, signal.SIGKILL)
    if reap and return_code is None:
        return_code = process.wait(timeout=TERMINATION_GRACE_SECONDS)
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    if not _wait_group_absent(process.pid, deadline):
        raise OSError("worker process group did not exit")
    return return_code, terminated, killed


def _signal_group(group: int, requested: signal.Signals) -> bool:
    try:
        os.killpg(group, requested)
    except ProcessLookupError:
        return False
    return True


def _wait_group_absent(group: int, deadline: float) -> bool:
    while True:
        try:
            os.killpg(group, 0)
        except (PermissionError, ProcessLookupError):  # Owned PGID is no longer signalable.
            return True
        if (remaining := deadline - time.monotonic()) <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _validated_artifact(directory: Path, metadata: ObservationMetadata) -> bytes:
    _require_inventory(directory, {ARTIFACT_NAME})
    path = directory / ARTIFACT_NAME
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise WorkerProtocolError("worker artifact is not an owned regular file")
        if status.st_size > MAX_OBSERVATION_BYTES:
            raise WorkerLimitError("observation artifact exceeds 256 MiB")
        payload = path.read_bytes()
    except OSError as error:
        raise WorkerProtocolError("worker artifact could not be validated") from error
    digest_mismatch = hashlib.sha256(payload).hexdigest() != metadata.sha256
    if len(payload) != metadata.byte_count or digest_mismatch:
        raise WorkerProtocolError("worker artifact digest does not match its control record")
    return payload


def _require_inventory(directory: Path, expected: set[str]) -> None:
    try:
        names = {path.name for path in directory.iterdir()}
    except OSError as error:
        raise WorkerProtocolError("worker artifact inventory could not be read") from error
    if names != expected:
        raise WorkerProtocolError("worker artifact inventory is not exact")


def _normalize(payload: bytes, owned_root: Path) -> str:
    return payload.decode("utf-8", errors="replace").replace(str(owned_root), "<PARQUITY_TEMP>")


def _control_metadata(data: Mapping[str, object]) -> ObservationMetadata | None:
    keys = ("artifact_bytes", "artifact_sha256", "row_count", "column_count", "schema_sha256")
    values = tuple(data[key] for key in keys)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise WorkerProtocolError("worker observation metadata is incomplete")
    size, digest, rows, columns, schema = values
    if not isinstance(digest, str) or not isinstance(schema, str):
        raise WorkerProtocolError("worker observation digests are malformed")
    byte_count = codec.integer(size, "artifact bytes")
    counts = (codec.integer(rows, "row count"), codec.integer(columns, "column count"))
    return ObservationMetadata(byte_count, digest, *counts, schema)
