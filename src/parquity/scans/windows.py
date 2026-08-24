"""Windows file-admission primitive used by scan discovery."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

IS_WINDOWS: Final = sys.platform == "win32"
_UNAVAILABLE = "Windows scan file admission is not available on this platform"

if sys.platform == "win32":
    from ctypes import WinDLL, WinError, c_void_p, get_last_error, wintypes

    # `use_last_error` and explicit HANDLE signatures are required on 64-bit Windows. Without
    # them, ctypes truncates handles and reports an unrelated or empty last-error value.
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

    _GENERIC_READ: Final = 0x80000000
    _FILE_SHARE_ALL: Final = 0x00000001 | 0x00000002 | 0x00000004
    _OPEN_EXISTING: Final = 3
    _FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000
    _INVALID_HANDLE_VALUE: Final = c_void_p(-1).value

    def open_without_following(path: Path) -> int:
        """Opens ``path`` for reading without traversing a reparse point."""
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

else:  # pragma: no cover - every caller checks IS_WINDOWS before reaching this

    def open_without_following(path: Path) -> int:
        del path
        raise RuntimeError(_UNAVAILABLE)


__all__ = ["IS_WINDOWS", "open_without_following"]
