from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..verdicts import MatrixRun

if TYPE_CHECKING:
    from ..model import Case

DEFAULT_MAX_FINDINGS = 8
MAX_FINDINGS = 64
MAX_SEED = 2**64 - 1


class CaseEvaluator(Protocol):
    def __call__(self, case: Case, directory: Path, /) -> MatrixRun: ...


__all__ = ["DEFAULT_MAX_FINDINGS", "MAX_FINDINGS", "MAX_SEED", "CaseEvaluator"]
