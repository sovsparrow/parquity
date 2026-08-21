from __future__ import annotations

import shutil
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple, cast

from ..configuration import scan_timeout_is_valid
from ..evidence import digest_matches
from ..process import (
    ProcessOutcome,
    ProcessSupervisionError,
    ProcessUnavailableError,
    run_process,
)
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
    try:
        outcome = run_process(
            argv,
            timeout_seconds=timeout,
            stdout_limit=MAX_STDOUT_BYTES,
            stderr_limit=MAX_STDERR_BYTES,
        )
    except ProcessUnavailableError as error:
        raise WorkerUnavailableError(str(error)) from error
    except OSError as error:
        raise WorkerInternalError("worker process could not be started") from error
    except ProcessSupervisionError as error:
        cause = error.__cause__ if isinstance(error.__cause__, OSError) else error
        raise WorkerInternalError(f"worker supervision failed: {error}") from cause
    return _interpret_process(outcome, private_directory, engine, version, owned_root)


def _interpret_process(
    outcome: ProcessOutcome,
    private_directory: Path,
    engine: str,
    version: str,
    owned_root: Path,
) -> WorkerOutcome:
    normalized_stderr = _normalize(outcome.stderr, owned_root)
    encoded_stderr = normalized_stderr.encode("utf-8")
    retained_stderr = encoded_stderr[:MAX_STDERR_BYTES].decode("utf-8", errors="ignore")
    stderr_truncated = outcome.stderr_truncated or len(encoded_stderr) > MAX_STDERR_BYTES
    if outcome.timed_out or outcome.return_code:
        if not outcome.timed_out and _control_present(private_directory):
            _read_control(private_directory, engine, version)
            raise WorkerProtocolError("worker control record conflicts with its exit status")
        kind = ReaderOutcomeKind.TIMEOUT if outcome.timed_out else ReaderOutcomeKind.PROCESS_ERROR
        values = (
            kind,
            engine,
            version,
            kind.value,
            retained_stderr,
            retained_stderr,
            stderr_truncated,
        )
        return WorkerOutcome(*values, terminated=outcome.terminated, killed=outcome.killed)
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
