from __future__ import annotations

import tempfile
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from ...evidence import EngineVersion
from ...model import Case
from ...profiles import WriterProfilePlan
from ...verdicts import CaseEvaluator, MatrixRun

MAX_CACHED_EVALUATIONS = 4096


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    writer_profiles: WriterProfilePlan | None = None


@dataclass(slots=True)
class CampaignEvaluator:
    evaluator: CaseEvaluator
    max_entries: int = MAX_CACHED_EVALUATIONS
    context: EvaluationContext | None = None
    _runs: OrderedDict[bytes, MatrixRun] = field(default_factory=OrderedDict[bytes, MatrixRun])
    _bound_context: EvaluationContext | None = field(default=None, init=False, repr=False)
    hits: int = 0
    misses: int = 0

    def __post_init__(self) -> None:
        if self.max_entries < 1:
            raise ValueError("evaluation cache requires a positive entry bound")

    def __call__(self, case: Case) -> MatrixRun:
        key = case.canonical_bytes()
        cached = self._runs.get(key)
        if cached is not None:
            self._runs.move_to_end(key)
            self.hits += 1
            return cached
        run = evaluate_fresh(case, self.evaluator)
        observed = EvaluationContext(run.writers, run.readers, run.writer_profiles)
        expected = self.context if self.context is not None else self._bound_context
        if expected is None:
            self._bound_context = observed
        elif observed != expected:
            raise RuntimeError("campaign evaluation context changed")
        stable = MatrixRun(
            run.case_id,
            run.results,
            (),
            run.writers,
            run.readers,
            run.writer_profiles,
        )
        if len(self._runs) == self.max_entries:
            self._runs.popitem(last=False)
        self._runs[key] = stable
        self.misses += 1
        return stable


def evaluate_fresh(case: Case, evaluator: CaseEvaluator) -> MatrixRun:
    with tempfile.TemporaryDirectory(prefix="parquity-case-") as raw_directory:
        root = Path(raw_directory)
        run = evaluator(case, root / "evaluation")
        return run.normalized((root,))


__all__ = [
    "MAX_CACHED_EVALUATIONS",
    "CampaignEvaluator",
    "EvaluationContext",
    "evaluate_fresh",
]
