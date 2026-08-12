from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_ACCENT = "\x1b[38;2;220;113;84m"
_GOOD = "\x1b[32m"
_WARN = "\x1b[33m"
_ERROR = "\x1b[31m"


class TerminalStream(Protocol):
    def isatty(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class Style:
    controls: bool

    def _wrap(self, value: str, code: str) -> str:
        return f"{code}{value}{_RESET}" if self.controls else value

    def bold(self, value: str) -> str:
        return self._wrap(value, _BOLD)

    def dim(self, value: str) -> str:
        return self._wrap(value, _DIM)

    def accent(self, value: str) -> str:
        return self._wrap(value, _ACCENT)

    def good(self, value: str) -> str:
        return self._wrap(value, _GOOD)

    def warn(self, value: str) -> str:
        return self._wrap(value, _WARN)

    def error(self, value: str) -> str:
        return self._wrap(value, _ERROR)


def controls_enabled(stream: TerminalStream) -> bool:
    return (
        "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb" and bool(stream.isatty())
    )


__all__ = ["Style", "controls_enabled"]
