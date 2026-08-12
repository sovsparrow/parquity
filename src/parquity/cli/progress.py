from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Protocol, TextIO

_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_active: list[_Indicator | None] = [None]
_ACTIVE_LOCK = threading.Lock()


def _animation_thread(target: Callable[[], None]) -> threading.Thread:
    return threading.Thread(target=target, daemon=True)


class _FuzzProgressView(Protocol):
    @property
    def phase(self) -> object: ...

    @property
    def evaluated_cases(self) -> int: ...

    @property
    def evaluated_cells(self) -> int: ...

    @property
    def retained_findings(self) -> int: ...

    @property
    def overflow_findings(self) -> int: ...

    @property
    def completed(self) -> int | None: ...

    @property
    def total(self) -> int | None: ...


@dataclass(slots=True)
class _Indicator:
    label: str
    stream: TextIO
    stopped: threading.Event = field(default_factory=threading.Event)
    write_lock: threading.Lock = field(default_factory=threading.Lock)
    thread: threading.Thread | None = None
    width: int = 0

    def start(self) -> None:
        self.thread = _animation_thread(self._animate)
        self.thread.start()

    def stop(self) -> None:
        self.stopped.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=0.5)
        with self.write_lock:
            self._clear()

    def update(self, label: str) -> None:
        with self.write_lock:
            self.label = label

    def _animate(self) -> None:
        started = time.monotonic()
        frame = 0
        while not self.stopped.is_set():
            self.render(frame, time.monotonic() - started)
            frame = (frame + 1) % len(_FRAMES)
            self.stopped.wait(0.08)

    def render(self, frame: int, elapsed_seconds: float) -> None:
        with self.write_lock:
            value = f"{_FRAMES[frame % len(_FRAMES)]} {self.label} · {_elapsed(elapsed_seconds)}"
            terminal_width = _terminal_width(self.stream)
            value = _bounded(value, terminal_width)
            visible_width = min(self.width, terminal_width)
            padding = " " * max(0, visible_width - len(value))
            try:
                self.stream.write(f"\r{value}{padding}")
                self.stream.flush()
            except (OSError, UnicodeError):
                self.stopped.set()
                return
            self.width = max(visible_width, len(value))

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
def indicator(label: str, *, enabled: bool) -> Generator[Callable[[str], None], None, None]:
    if not enabled:
        yield _ignore
        return
    stop_active()
    item = _Indicator(label, sys.stderr)
    with _ACTIVE_LOCK:
        _active[0] = item
    item.start()
    try:
        yield item.update
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


def _terminal_width(stream: TextIO) -> int:
    try:
        return max(20, os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError):
        return 80


def _bounded(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: width - 1] + "…"


def _ignore(_: str) -> None:
    return None


def fuzz_label(value: _FuzzProgressView) -> str:
    phase = str(value.phase)
    if phase == "DISCOVERY":
        cases = "Case" if value.evaluated_cases == 1 else "Cases"
        checks = "check" if value.evaluated_cells == 1 else "checks"
        findings = "finding" if value.retained_findings == 1 else "findings"
        additional = "additional finding" if value.overflow_findings == 1 else "additional findings"
        return (
            f"Discovering · {value.evaluated_cases} {cases} · "
            f"{value.evaluated_cells} {checks} · "
            f"{value.retained_findings} retained {findings} · "
            f"{value.overflow_findings} {additional}"
        )
    completed, total = _progress_bounds(value)
    if phase == "MINIMIZATION":
        findings = "finding" if total == 1 else "findings"
        return f"Minimizing · {completed}/{total} {findings}"
    findings = "finding" if total == 1 else "findings"
    if phase == "EVIDENCE_WRITING":
        return f"Writing evidence · {completed}/{total} {findings}"
    return f"Finalizing evidence · {total} {findings}"


def _progress_bounds(value: _FuzzProgressView) -> tuple[int, int]:
    if value.completed is None or value.total is None:
        raise TypeError("post-discovery progress is missing its bounds")
    return value.completed, value.total


__all__ = ["fuzz_label", "indicator", "stop_active"]
