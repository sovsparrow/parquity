"""The two platform primitives scan needs, implemented for Windows.

POSIX reaches a worker's descendants through a process group and refuses to follow a symlink with
``O_NOFOLLOW``. Windows has neither, so containment uses a job object and admission uses
``FILE_FLAG_OPEN_REPARSE_POINT``.

``ctypes`` exposes ``WinDLL``, ``WinError`` and ``wintypes`` only on Windows, and both ``discovery``
and ``supervision`` import this module unconditionally to ask :data:`IS_WINDOWS`. Everything needing
those names therefore lives behind the guard, with stubs elsewhere that say so rather than failing
at import.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

IS_WINDOWS: Final = sys.platform == "win32"

#: ``subprocess.CREATE_NEW_PROCESS_GROUP``, which only exists on Windows and so cannot be named
#: from code a type checker reads on another platform. Declared here as the plain integer it is,
#: so ``supervision`` can pass it unconditionally and pass zero everywhere else.
CREATE_NEW_PROCESS_GROUP: Final = 0x00000200

_UNAVAILABLE = "the Windows scan primitives are not available on this platform"

# ``sys.platform`` rather than :data:`IS_WINDOWS`, which is the same test: a type checker narrows
# on the former and so reads only the branch belonging to the platform it is checking. Written the
# other way it reads both, and then the stubs below are a redeclaration of the real ones.
if sys.platform == "win32":
    from ctypes import (
        POINTER,
        Structure,
        WinDLL,
        WinError,
        byref,
        c_int,
        c_size_t,
        c_uint32,
        c_uint64,
        c_void_p,
        get_last_error,
        sizeof,
        wintypes,
    )

    # Not ``windll``, which shares one cached library across the whole process and is not created
    # with ``use_last_error``. Without that flag ``get_last_error`` reads ctypes' own copy, which
    # nothing ever writes, so every failure below would report success. Argument and return types
    # are declared for the same reason they always must be on 64-bit Windows: undeclared, ctypes
    # treats a HANDLE as a C ``int`` and truncates it, and a failing ``CreateFileW`` comes back as
    # -1 rather than INVALID_HANDLE_VALUE, so the failure check never fires.
    _kernel32: Final = WinDLL("kernel32", use_last_error=True)

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
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

    _GENERIC_READ: Final = 0x80000000
    _FILE_SHARE_ALL: Final = 0x00000001 | 0x00000002 | 0x00000004
    _OPEN_EXISTING: Final = 3
    _FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
    _INVALID_HANDLE_VALUE: Final = c_void_p(-1).value

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x00002000
    _JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: Final = 1
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final = 9
    _TERMINATED_EXIT_CODE: Final = 1
    _PROCESS_ASSIGN_RIGHTS: Final = 0x0001 | 0x0100  # TERMINATE | SET_QUOTA

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

    def open_without_following(path: Path) -> int:
        """Opens ``path`` for reading without traversing a reparse point.

        This is what ``O_NOFOLLOW`` buys the POSIX admission path: a symlink swapped in between the
        check and the open cannot redirect the read, because the reparse point itself is opened and
        then fails the regular-file check.
        """
        handle = _kernel32.CreateFileW(
            str(path),
            _GENERIC_READ,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle is None or handle == _INVALID_HANDLE_VALUE:
            raise WinError(get_last_error())
        try:
            import msvcrt  # noqa: PLC0415 - Windows-only, imported where it is used.

            return msvcrt.open_osfhandle(handle, os.O_RDONLY)
        except OSError:
            _kernel32.CloseHandle(handle)
            raise

    class ProcessJob:
        """A job object standing in for a POSIX process group.

        Whatever the worker starts is created inside the job, so terminating it reaches the whole
        tree the way ``killpg`` does. It is created with ``KILL_ON_JOB_CLOSE``, so a supervisor
        that dies without shutting down cleanly still takes the tree with it.
        """

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
            """Places a process, and everything it goes on to start, inside the job.

            Taken by process id rather than by handle, so this does not depend on a private
            attribute of whatever spawned it.
            """
            if self._handle is None:
                return False
            process = _kernel32.OpenProcess(_PROCESS_ASSIGN_RIGHTS, False, pid)
            if not process:
                # Already gone, which is nothing to report: there is nothing left to contain.
                return False
            try:
                return bool(_kernel32.AssignProcessToJobObject(self._handle, process))
            finally:
                _kernel32.CloseHandle(process)

        def terminate(self) -> bool:
            """Kills every process still in the job. False once the job is closed."""
            if self._handle is None:
                return False
            return bool(_kernel32.TerminateJobObject(self._handle, _TERMINATED_EXIT_CODE))

        def active(self) -> int:
            """How many processes the job still holds."""
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

else:  # pragma: no cover - every caller checks IS_WINDOWS before reaching these

    def open_without_following(path: Path) -> int:
        raise RuntimeError(_UNAVAILABLE)

    class ProcessJob:
        def __init__(self) -> None:
            raise RuntimeError(_UNAVAILABLE)

        def assign(self, pid: int) -> bool:
            raise RuntimeError(_UNAVAILABLE)

        def terminate(self) -> bool:
            raise RuntimeError(_UNAVAILABLE)

        def active(self) -> int:
            raise RuntimeError(_UNAVAILABLE)

        def close(self) -> None:
            raise RuntimeError(_UNAVAILABLE)


__all__ = ["IS_WINDOWS", "ProcessJob", "open_without_following"]
