from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias


class RunPublicationPhase(StrEnum):
    WRITING = "WRITING"
    FINALIZING = "FINALIZING"


@dataclass(frozen=True, slots=True)
class RunPublicationProgress:
    phase: RunPublicationPhase
    completed_findings: int
    total_findings: int

    def __post_init__(self) -> None:
        invalid = (
            isinstance(self.completed_findings, bool)
            or isinstance(self.total_findings, bool)
            or self.completed_findings < 0
            or self.completed_findings > self.total_findings
        )
        if invalid:
            raise ValueError("run publication progress is outside its total")


RunProgressCallback: TypeAlias = Callable[[RunPublicationProgress], None]


def notify(
    callback: RunProgressCallback | None,
    value: RunPublicationProgress,
) -> None:
    if callback is not None:
        callback(value)


__all__ = [
    "RunProgressCallback",
    "RunPublicationPhase",
    "RunPublicationProgress",
    "notify",
]
