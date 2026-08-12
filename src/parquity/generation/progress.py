from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias


class FuzzPhase(StrEnum):
    DISCOVERY = "DISCOVERY"
    MINIMIZATION = "MINIMIZATION"
    EVIDENCE_WRITING = "EVIDENCE_WRITING"
    FINALIZATION = "FINALIZATION"


@dataclass(frozen=True, slots=True)
class FuzzProgress:
    phase: FuzzPhase
    evaluated_cases: int
    evaluated_cells: int
    retained_findings: int
    overflow_findings: int
    completed: int | None = None
    total: int | None = None

    def __post_init__(self) -> None:
        counts = (
            self.evaluated_cases,
            self.evaluated_cells,
            self.retained_findings,
            self.overflow_findings,
        )
        if any(isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("fuzz progress counts must be non-negative integers")
        if (self.completed is None) != (self.total is None):
            raise ValueError("fuzz phase progress must provide both completed and total")
        if self.completed is not None and self.total is not None:
            bounded = (
                isinstance(self.completed, bool)
                or isinstance(self.total, bool)
                or self.completed < 0
                or self.completed > self.total
            )
            if bounded:
                raise ValueError("fuzz phase progress is outside its total")
        if self.phase is not FuzzPhase.DISCOVERY and self.completed is None:
            raise ValueError("post-discovery progress requires a completed count")


ProgressCallback: TypeAlias = Callable[[FuzzProgress], None]


@dataclass(slots=True)
class ProgressNotifier:
    callback: ProgressCallback | None

    def __call__(self, value: FuzzProgress) -> None:
        callback = self.callback
        if callback is None:
            return
        try:
            callback(value)
        except Exception:  # noqa: BLE001 - presentation failure cannot alter fuzzing.
            self.callback = None


def resilient_progress(callback: ProgressCallback | None) -> ProgressNotifier:
    if isinstance(callback, ProgressNotifier):
        return callback
    return ProgressNotifier(callback)


__all__ = [
    "FuzzPhase",
    "FuzzProgress",
    "ProgressCallback",
    "ProgressNotifier",
    "resilient_progress",
]
