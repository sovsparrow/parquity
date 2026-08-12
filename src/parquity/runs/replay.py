from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..findings.replay import (
    ReplayClassification,
    ReplayOutcome,
    replay_validated_bundle,
    require_replay_profile_plan,
)
from ..model import Case
from ..profiles import WriterProfilePlan
from ..verdicts import CaseEvaluator
from .bundle import ValidatedRun, validate_run


@dataclass(frozen=True, slots=True)
class RunReplayOutcome:
    outcomes: tuple[ReplayOutcome, ...]
    exact_count: int
    related_count: int
    absent_count: int
    writer_profiles: WriterProfilePlan | None = None

    @property
    def reproduced(self) -> bool:
        return self.exact_count > 0


def replay_run(directory: Path, evaluator: CaseEvaluator) -> RunReplayOutcome:
    return replay_validated_run(validate_run(directory), evaluator)


def replay_validated_run(
    validated: ValidatedRun,
    evaluator: CaseEvaluator,
) -> RunReplayOutcome:
    def plan_bound_evaluator(case: Case, directory: Path):
        run = evaluator(case, directory)
        require_replay_profile_plan(validated.run.writer_profiles, run.writer_profiles)
        return run

    outcomes = tuple(
        replay_validated_bundle(child, plan_bound_evaluator) for child in validated.children
    )
    classifications = tuple(outcome.classification for outcome in outcomes)
    exact = sum(item is ReplayClassification.REPRODUCED for item in classifications)
    related = sum(item is ReplayClassification.RELATED_FAILURE for item in classifications)
    absent = sum(item is ReplayClassification.NOT_REPRODUCED for item in classifications)
    return RunReplayOutcome(
        outcomes,
        exact,
        related,
        absent,
        validated.run.writer_profiles,
    )


__all__ = [
    "RunReplayOutcome",
    "replay_run",
    "replay_validated_run",
]
