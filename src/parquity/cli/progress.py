from __future__ import annotations

import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TextIO

_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_active: list[_Indicator | None] = [None]
_ACTIVE_LOCK = threading.Lock()


@dataclass(slots=True)
class _Indicator:
    label: str
    stream: TextIO
    stopped: threading.Event = field(default_factory=threading.Event)
    write_lock: threading.Lock = field(default_factory=threading.Lock)
    thread: threading.Thread | None = None
    width: int = 0

    def start(self) -> None:
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stopped.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=0.5)
        with self.write_lock:
            self._clear()

    def _animate(self) -> None:
        started = time.monotonic()
        frame = 0
        while not self.stopped.is_set():
            elapsed = _elapsed(time.monotonic() - started)
            self._replace(f"{_FRAMES[frame]} {self.label} · {elapsed}")
            frame = (frame + 1) % len(_FRAMES)
            self.stopped.wait(0.08)

    def _replace(self, value: str) -> None:
        with self.write_lock:
            padding = " " * max(0, self.width - len(value))
            try:
                self.stream.write(f"\r{value}{padding}")
                self.stream.flush()
            except (OSError, UnicodeError):
                self.stopped.set()
                return
            self.width = max(self.width, len(value))

    def _clear(self) -> None:
        if self.width == 0:
            return
        try:
            self.stream.write(f"\r{' ' * self.width}\r")
            self.stream.flush()
        except (OSError, UnicodeError):
            pass
        self.width = 0


@contextmanager
def indicator(label: str, *, enabled: bool) -> Generator[None, None, None]:
    if not enabled:
        yield
        return
    stop_active()
    item = _Indicator(label, sys.stderr)
    with _ACTIVE_LOCK:
        _active[0] = item
    item.start()
    try:
        yield
    finally:
        with _ACTIVE_LOCK:
            if _active[0] is item:
                _active[0] = None
        item.stop()


def stop_active() -> None:
    with _ACTIVE_LOCK:
        item, _active[0] = _active[0], None
    if item is not None:
        item.stop()


def _elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    return f"{minutes}m {remainder:02d}s"


__all__ = ["indicator", "stop_active"]
