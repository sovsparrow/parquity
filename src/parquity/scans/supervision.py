from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NamedTuple, cast

from ..configuration import scan_timeout_is_valid
from ..evidence import digest_matches
from . import windows
from .control import (
    ARTIFACT_NAME,
    CONTROL_NAME,
    MAX_CONTROL_BYTES,
    WorkerControl,
    WorkerProtocolError,
)
from .limits import MAX_OBSERVATION_BYTES, MAX_STDERR_BYTES, MAX_STDOUT_BYTES
from .observations import ObservationMetadata
from .records import ReaderOutcomeKind

TERMINATION_GRACE_SECONDS = 1.0


class WorkerInternalError(RuntimeError): ...


class WorkerLimitError(ValueError): ...


class WorkerUnavailableError(RuntimeError): ...


class WorkerOutcome(NamedTuple):
    kind: ReaderOutcomeKind
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
    if not scan_timeout_is_valid(timeout_seconds):
        raise ValueError("worker timeout must be in [1, 300]")
    if not windows.IS_WINDOWS and (os.name != "posix" or not hasattr(os, "killpg")):
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
    supervised = _spawn(argv)
    try:
        return _supervise(supervised, private_directory, engine, version, timeout, owned_root)
    finally:
        # Closing the job is what releases the containment, and on Windows it also kills anything
        # still inside it, so it happens however this returns.
        supervised.release()


def _supervise(
    process: _Supervised,
    private_directory: Path,
    engine: str,
    version: str,
    timeout: int,
    owned_root: Path,
) -> WorkerOutcome:
    stdout = _Capture(MAX_STDOUT_BYTES, bytearray())
    stderr = _Capture(MAX_STDERR_BYTES, bytearray())
    streams = (cast(BinaryIO, process.process.stdout), cast(BinaryIO, process.process.stderr))
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
        if not timed_out and _control_present(private_directory):
            _read_control(private_directory, engine, version)
            raise WorkerProtocolError("worker control record conflicts with its exit status")
        kind = ReaderOutcomeKind.TIMEOUT if timed_out else ReaderOutcomeKind.PROCESS_ERROR
        values = (
            kind,
            engine,
            version,
            kind.value,
            retained_stderr,
            retained_stderr,
            stderr_truncated,
        )
        return WorkerOutcome(*values, terminated=terminated, killed=killed)
    control = _read_control(private_directory, engine, version)
    detail = _normalize(control.detail.encode(), owned_root)
    failures = {
        "INTERNAL_ERROR": WorkerInternalError(f"{control.diagnostic_kind}: {detail}"),
        "LIMIT_ERROR": WorkerLimitError(detail),
    }
    if failure := failures.get(control.outcome):
        raise failure
    if control.outcome == "PROVIDER_ERROR":
        _require_inventory(private_directory, set())
        values = (
            ReaderOutcomeKind.PROVIDER_ERROR,
            engine,
            version,
            control.diagnostic_kind,
            detail,
        )
        return WorkerOutcome(*values, retained_stderr, stderr_truncated)
    artifact = _validated_artifact(private_directory, cast(ObservationMetadata, control.metadata))
    values = (ReaderOutcomeKind.SUCCESS, engine, version, control.diagnostic_kind, detail)
    return WorkerOutcome(*values, retained_stderr, stderr_truncated, artifact, control.metadata)


def _control_present(directory: Path) -> bool:
    try:
        (directory / CONTROL_NAME).lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise WorkerProtocolError("worker control record could not be inspected") from error
    return True


def _read_control(directory: Path, engine: str, version: str) -> WorkerControl:
    path = directory / CONTROL_NAME
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise WorkerProtocolError("worker control record is not an owned regular file")
        if status.st_size > MAX_CONTROL_BYTES:
            raise WorkerProtocolError("worker control record exceeds 16 KiB")
        raw = path.read_bytes()
        path.unlink()
    except FileNotFoundError as error:
        raise WorkerProtocolError("worker control record is missing") from error
    except WorkerProtocolError:
        raise
    except OSError as error:
        raise WorkerProtocolError("worker control record could not be validated") from error
    control = WorkerControl.from_json(raw)
    if control.engine != engine or control.engine_version != version:
        raise WorkerProtocolError("worker control identity does not match the request")
    return control


@dataclass(slots=True)
class _Supervised:
    """A worker and the boundary that contains whatever it starts.

    POSIX puts the worker in its own session, so the tree is reachable through its process group.
    Windows has no process group that survives across processes, so the worker is placed in a job
    object instead, which terminates the tree the same way and, because it is created with
    KILL_ON_JOB_CLOSE, still does so if this supervisor dies first.
    """

    process: subprocess.Popen[bytes]
    job: windows.ProcessJob | None = None

    def request_stop(self) -> bool:
        """Asks the tree to exit. Windows has no polite equivalent, so it reports no attempt."""
        if self.job is not None:
            return False
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        return True

    def force_stop(self) -> bool:
        """Kills the tree outright."""
        if self.job is not None:
            return self.job.terminate()
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return False
        return True

    def gone(self) -> bool:
        """Whether nothing of the tree remains."""
        if self.job is not None:
            return self.job.active() == 0
        try:
            os.killpg(self.process.pid, 0)
        except (PermissionError, ProcessLookupError):  # Owned PGID is no longer signalable.
            return True
        return False

    def release(self) -> None:
        if self.job is not None:
            self.job.close()


def _spawn(argv: Sequence[str]) -> _Supervised:
    job = windows.ProcessJob() if windows.IS_WINDOWS else None
    try:
        process = subprocess.Popen(  # noqa: S603 - caller supplies a shell-free worker argv.
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            # Both are named on both platforms and each is inert on the one it does not belong to.
            # A new session on POSIX is what makes the process group reachable; a new process group
            # on Windows keeps a console signal aimed at this process from reaching the worker,
            # where containment itself is the job object's job.
            start_new_session=not windows.IS_WINDOWS,
            creationflags=windows.CREATE_NEW_PROCESS_GROUP if windows.IS_WINDOWS else 0,
        )
    except OSError as error:
        if job is not None:
            job.close()
        raise WorkerInternalError("worker process could not be started") from error
    if job is not None:
        # Assigned as soon as the process exists. The worker cannot have started anything of its
        # own yet -- it has not finished loading an interpreter -- so nothing escapes the job.
        job.assign(process.pid)
    return _Supervised(process, job)


def _wait_for_process(child: _Supervised, timeout: int) -> tuple[int, bool, bool, bool]:
    try:
        try:
            return child.process.wait(timeout=float(timeout)), False, False, False
        except subprocess.TimeoutExpired:
            pass
        return_code, terminated, killed = _shutdown_group(child, reap=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        with suppress(OSError):
            child.force_stop()
        if child.process.returncode is None:
            with suppress(OSError, subprocess.TimeoutExpired):
                child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
        raise WorkerInternalError("worker process group could not be shut down") from error
    return cast(int, return_code), True, terminated, killed


def _shutdown_group(child: _Supervised, *, reap: bool) -> tuple[int | None, bool, bool]:
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    terminated = child.request_stop()
    return_code: int | None = None
    if reap:
        with suppress(subprocess.TimeoutExpired):
            return_code = child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
    if _wait_group_absent(child, deadline) and (return_code is not None or not reap):
        return return_code, terminated, False
    killed = child.force_stop()
    if reap and return_code is None:
        return_code = child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    if not _wait_group_absent(child, deadline):
        raise OSError("worker process group did not exit")
    return return_code, terminated, killed


def _wait_group_absent(child: _Supervised, deadline: float) -> bool:
    while True:
        if child.gone():
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
    if not digest_matches(payload, metadata.sha256, metadata.byte_count):
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
    text = payload.decode("utf-8", errors="replace")
    # A provider writes the path the way it likes, and on Windows that is not always the way
    # str(Path) does: PyArrow reports 'C:/Users/...' where the owned root reads 'C:\\Users\\...'.
    # Redacting only one spelling leaves the other in the evidence, which both discloses a local
    # path and makes the detail -- and so the finding's identity -- change with every run, because
    # the temporary root is named afresh each time.
    for spelling in dict.fromkeys((str(owned_root), owned_root.as_posix())):
        text = text.replace(spelling, "<PARQUITY_TEMP>")
    return text
