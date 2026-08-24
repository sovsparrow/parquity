from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import BinaryIO, Final, cast

IS_WINDOWS: Final = sys.platform == "win32"
TERMINATION_GRACE_SECONDS = 1.0


class ProcessUnavailableError(RuntimeError):
    """The platform cannot provide the required process-tree containment."""


class ProcessSupervisionError(RuntimeError):
    """A started process could not be contained, drained, or cleaned up safely."""


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    return_code: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    terminated: bool
    killed: bool


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


def run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
) -> ProcessOutcome:
    """Runs one command inside a contained process tree with bounded output capture."""
    if timeout_seconds <= 0:
        raise ValueError("process timeout must be positive")
    if stdout_limit < 0 or stderr_limit < 0:
        raise ValueError("process stream limits must not be negative")
    if not argv:
        raise OSError(errno.ENOENT, "process command is empty")
    if not IS_WINDOWS and (os.name != "posix" or not hasattr(os, "killpg")):
        raise ProcessUnavailableError("process-tree containment is unavailable")

    supervised = _spawn(argv)
    try:
        return _supervise(supervised, timeout_seconds, stdout_limit, stderr_limit)
    finally:
        # On Windows the job owns the containment boundary. Closing it releases that boundary and,
        # because it uses KILL_ON_JOB_CLOSE, kills anything still inside if supervision failed.
        supervised.release()


def _supervise(
    child: _Supervised,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
) -> ProcessOutcome:
    stdout = _Capture(stdout_limit, bytearray())
    stderr = _Capture(stderr_limit, bytearray())
    streams = (cast(BinaryIO, child.process.stdout), cast(BinaryIO, child.process.stderr))
    threads = tuple(
        threading.Thread(target=capture.drain, args=(stream,), daemon=True)
        for capture, stream in zip((stdout, stderr), streams, strict=True)
    )
    for thread in threads:
        thread.start()
    try:
        return_code, timed_out, terminated, killed = _wait_for_process(child, timeout_seconds)
    finally:
        for thread in threads:
            thread.join(TERMINATION_GRACE_SECONDS)

    drain_failed = any(thread.is_alive() for thread in threads) or stdout.error or stderr.error
    if drain_failed:
        try:
            _shutdown_tree(child, reap=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProcessSupervisionError("process streams could not be drained") from error
        for thread in threads:
            thread.join(TERMINATION_GRACE_SECONDS)
        raise ProcessSupervisionError("process streams could not be drained")

    return ProcessOutcome(
        return_code,
        bytes(stdout.payload),
        bytes(stderr.payload),
        stdout.truncated,
        stderr.truncated,
        timed_out,
        terminated,
        killed,
    )


@dataclass(slots=True)
class _Supervised:
    """A process and the boundary that contains whatever it starts.

    POSIX reaches descendants through a process group. Windows uses a job object instead, with
    KILL_ON_JOB_CLOSE so the tree is still terminated if supervision exits before normal cleanup.
    """

    process: subprocess.Popen[bytes]
    job: _ProcessJob | None = None

    def request_stop(self) -> bool:
        if self.job is not None:
            return False
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        return True

    def force_stop(self) -> bool:
        if self.job is not None:
            return self.job.terminate()
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return False
        return True

    def gone(self) -> bool:
        if self.job is not None:
            return self.job.active() == 0
        try:
            os.killpg(self.process.pid, 0)
        except (PermissionError, ProcessLookupError):
            return True
        return False

    def release(self) -> None:
        if self.job is not None:
            self.job.close()


def _spawn(argv: Sequence[str]) -> _Supervised:
    job: _ProcessJob | None = None
    if IS_WINDOWS:
        try:
            job = _ProcessJob()
        except OSError as error:
            raise ProcessSupervisionError("process containment could not be created") from error
    try:
        process = subprocess.Popen(  # noqa: S603 - caller supplies a shell-free argv.
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=not IS_WINDOWS,
            creationflags=_creation_flags(),
        )
    except OSError:
        if job is not None:
            job.close()
        raise
    if job is None:
        return _Supervised(process)
    return _contain(process, job)


def _creation_flags() -> int:
    if not IS_WINDOWS:
        return 0
    # The child must be inside the job before it can run code and start an uncontained descendant.
    # Assigning an already-running process leaves a window that POSIX does not have because
    # start_new_session is applied as part of process creation.
    return CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED


def _contain(process: subprocess.Popen[bytes], job: _ProcessJob) -> _Supervised:
    try:
        if not job.assign(process.pid):
            # False means not contained, whatever the reason. Continuing would let timeout kill an
            # empty job while the process it was meant to contain kept running.
            raise ProcessSupervisionError("process could not be placed in its containment job")
        if not _resume_process(process.pid):
            # ResumeThread can succeed for a thread that was already running. Zero means no thread
            # was proved suspended, so the pre-execution containment guarantee was lost.
            raise ProcessSupervisionError("process was not suspended while it was being contained")
    except OSError as error:
        _discard(process)
        job.close()
        raise ProcessSupervisionError("process could not be resumed once contained") from error
    except BaseException:
        _discard(process)
        job.close()
        raise
    return _Supervised(process, job)


def _discard(process: subprocess.Popen[bytes]) -> None:
    with suppress(OSError):
        process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def _wait_for_process(child: _Supervised, timeout_seconds: int) -> tuple[int, bool, bool, bool]:
    try:
        try:
            return child.process.wait(timeout=float(timeout_seconds)), False, False, False
        except subprocess.TimeoutExpired:
            pass
        return_code, terminated, killed = _shutdown_tree(child, reap=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        with suppress(OSError):
            child.force_stop()
        if child.process.returncode is None:
            with suppress(OSError, subprocess.TimeoutExpired):
                child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
        raise ProcessSupervisionError("process tree could not be shut down") from error
    return cast(int, return_code), True, terminated, killed


def _shutdown_tree(child: _Supervised, *, reap: bool) -> tuple[int | None, bool, bool]:
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    terminated = child.request_stop()
    return_code: int | None = None
    if reap:
        with suppress(subprocess.TimeoutExpired):
            return_code = child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
    if _wait_tree_absent(child, deadline) and (return_code is not None or not reap):
        return return_code, terminated, False
    killed = child.force_stop()
    if reap and return_code is None:
        return_code = child.process.wait(timeout=TERMINATION_GRACE_SECONDS)
    deadline = time.monotonic() + TERMINATION_GRACE_SECONDS
    if not _wait_tree_absent(child, deadline):
        raise OSError("process tree did not exit")
    return return_code, terminated, killed


def _wait_tree_absent(child: _Supervised, deadline: float) -> bool:
    while True:
        if child.gone():
            return True
        if (remaining := deadline - time.monotonic()) <= 0:
            return False
        time.sleep(min(0.01, remaining))


# subprocess exposes these constants only on Windows. Keeping the integers here lets type checking
# read this module on every platform while passing zero from `_creation_flags` elsewhere.
CREATE_NEW_PROCESS_GROUP: Final = 0x00000200
CREATE_SUSPENDED: Final = 0x00000004
_WINDOWS_UNAVAILABLE = "Windows process containment is unavailable on this platform"

if sys.platform == "win32":
    from ctypes import (
        POINTER,
        Structure,
        WinDLL,
        WinError,
        byref,
        c_int,
        c_int32,
        c_size_t,
        c_uint32,
        c_uint64,
        c_void_p,
        get_last_error,
        sizeof,
        wintypes,
    )

    _kernel32: Final = WinDLL("kernel32", use_last_error=True)
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD

    _TH32CS_SNAPTHREAD: Final = 0x00000004
    _THREAD_SUSPEND_RESUME: Final = 0x0002
    _RESUME_FAILED: Final = 0xFFFFFFFF
    _INVALID_HANDLE_VALUE: Final = c_void_p(-1).value
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: Final = 1
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9
    _TERMINATED_EXIT_CODE: Final = 1
    _PROCESS_ASSIGN_RIGHTS: Final = 0x0001 | 0x0100

    class _IoCounters(Structure):
        _fields_ = [
            ("ReadOperationCount", c_uint64),
            ("WriteOperationCount", c_uint64),
            ("OtherOperationCount", c_uint64),
            ("ReadTransferCount", c_uint64),
            ("WriteTransferCount", c_uint64),
            ("OtherTransferCount", c_uint64),
        ]

    class _BasicLimitInformation(Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", c_uint64),
            ("PerJobUserTimeLimit", c_uint64),
            ("LimitFlags", c_uint32),
            ("MinimumWorkingSetSize", c_size_t),
            ("MaximumWorkingSetSize", c_size_t),
            ("ActiveProcessLimit", c_uint32),
            ("Affinity", c_size_t),
            ("PriorityClass", c_uint32),
            ("SchedulingClass", c_uint32),
        ]

    class _ExtendedLimitInformation(Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", c_size_t),
            ("JobMemoryLimit", c_size_t),
            ("PeakProcessMemoryUsed", c_size_t),
            ("PeakJobMemoryUsed", c_size_t),
        ]

    class _ThreadEntry(Structure):
        _fields_ = [
            ("dwSize", c_uint32),
            ("cntUsage", c_uint32),
            ("th32ThreadID", c_uint32),
            ("th32OwnerProcessID", c_uint32),
            ("tpBasePri", c_int32),
            ("tpDeltaPri", c_int32),
            ("dwFlags", c_uint32),
        ]

    class _BasicAccountingInformation(Structure):
        _fields_ = [
            ("TotalUserTime", c_uint64),
            ("TotalKernelTime", c_uint64),
            ("ThisPeriodTotalUserTime", c_uint64),
            ("ThisPeriodTotalKernelTime", c_uint64),
            ("TotalPageFaultCount", c_uint32),
            ("TotalProcesses", c_uint32),
            ("ActiveProcesses", c_uint32),
            ("TotalTerminatedProcesses", c_uint32),
        ]

    _kernel32.Thread32First.argtypes = [wintypes.HANDLE, POINTER(_ThreadEntry)]
    _kernel32.Thread32First.restype = wintypes.BOOL
    _kernel32.Thread32Next.argtypes = [wintypes.HANDLE, POINTER(_ThreadEntry)]
    _kernel32.Thread32Next.restype = wintypes.BOOL

    def _resume_process(pid: int) -> int:
        """Resumes ``pid`` and returns how many threads were proved suspended.

        The process handle remains open while this runs, so Windows cannot reuse the process id.
        A process created suspended normally has one thread; the API does not guarantee that, so
        every owned thread is inspected.
        """
        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot is None or snapshot == _INVALID_HANDLE_VALUE:
            raise WinError(get_last_error())
        resumed = 0
        try:
            entry = _ThreadEntry()
            entry.dwSize = sizeof(_ThreadEntry)
            found = _kernel32.Thread32First(snapshot, byref(entry))
            while found:
                if entry.th32OwnerProcessID == pid:
                    resumed += _resume_thread(entry.th32ThreadID)
                entry = _ThreadEntry()
                entry.dwSize = sizeof(_ThreadEntry)
                found = _kernel32.Thread32Next(snapshot, byref(entry))
        finally:
            _kernel32.CloseHandle(snapshot)
        return resumed

    def _resume_thread(thread_id: int) -> int:
        thread = _kernel32.OpenThread(_THREAD_SUSPEND_RESUME, False, thread_id)
        if not thread:
            return 0
        try:
            # ResumeThread returns the suspend count from before the call. A positive value proves
            # the thread was suspended rather than accepting a successful no-op on a running one.
            previous = _kernel32.ResumeThread(thread)
            return int(previous != _RESUME_FAILED and previous > 0)
        finally:
            _kernel32.CloseHandle(thread)

    class _ProcessJob:
        """A Windows job object standing in for a POSIX process group."""

        def __init__(self) -> None:
            handle = _kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise WinError(get_last_error())
            self._handle: int | None = handle
            information = _ExtendedLimitInformation()
            information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not _kernel32.SetInformationJobObject(
                handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                byref(information),
                sizeof(information),
            ):
                error = get_last_error()
                self.close()
                raise WinError(error)

        def assign(self, pid: int) -> bool:
            """Places a process in the job, returning false whenever it is not contained."""
            if self._handle is None:
                return False
            process = _kernel32.OpenProcess(_PROCESS_ASSIGN_RIGHTS, False, pid)
            if not process:
                return False
            try:
                return bool(_kernel32.AssignProcessToJobObject(self._handle, process))
            finally:
                _kernel32.CloseHandle(process)

        def terminate(self) -> bool:
            if self._handle is None:
                return False
            return bool(_kernel32.TerminateJobObject(self._handle, _TERMINATED_EXIT_CODE))

        def active(self) -> int:
            if self._handle is None:
                return 0
            information = _BasicAccountingInformation()
            if not _kernel32.QueryInformationJobObject(
                self._handle,
                _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                byref(information),
                sizeof(information),
                None,
            ):
                raise WinError(get_last_error())
            return int(information.ActiveProcesses)

        def close(self) -> None:
            handle, self._handle = self._handle, None
            if handle is not None:
                _kernel32.CloseHandle(handle)

else:  # pragma: no cover - `run_process` refuses this path before these are reached

    def _resume_process(pid: int) -> int:
        del pid
        raise RuntimeError(_WINDOWS_UNAVAILABLE)

    class _ProcessJob:
        def __init__(self) -> None:
            raise RuntimeError(_WINDOWS_UNAVAILABLE)

        def assign(self, pid: int) -> bool:
            del pid
            raise RuntimeError(_WINDOWS_UNAVAILABLE)

        def terminate(self) -> bool:
            raise RuntimeError(_WINDOWS_UNAVAILABLE)

        def active(self) -> int:
            raise RuntimeError(_WINDOWS_UNAVAILABLE)

        def close(self) -> None:
            raise RuntimeError(_WINDOWS_UNAVAILABLE)


__all__ = [
    "IS_WINDOWS",
    "ProcessOutcome",
    "ProcessSupervisionError",
    "ProcessUnavailableError",
    "run_process",
]
