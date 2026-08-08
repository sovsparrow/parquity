from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..findings.replay import (
    ReplayClassification,
    ReplayOutcome,
    replay_validated_bundle,
    require_replay_profile_plan,
)
from ..generation import CaseEvaluator
from ..model import Case
from ..writer_profiles import WriterProfilePlan
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

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "exact": self.exact_count,
            "related": self.related_count,
            "absent": self.absent_count,
            "findings": [_outcome_data(outcome) for outcome in self.outcomes],
        }
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        return data


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
    exact = sum(outcome.classification is ReplayClassification.REPRODUCED for outcome in outcomes)
    related = sum(
        outcome.classification is ReplayClassification.RELATED_FAILURE for outcome in outcomes
    )
    absent = sum(
        outcome.classification is ReplayClassification.NOT_REPRODUCED for outcome in outcomes
    )
    return RunReplayOutcome(outcomes, exact, related, absent, validated.run.writer_profiles)


def _outcome_data(outcome: ReplayOutcome) -> dict[str, object]:
    data: dict[str, object] = {
        "finding_id": outcome.finding.finding_id,
        "classification": outcome.classification.value,
        "version_evidence": [item.to_data() for item in outcome.version_evidence],
        "version_drift": [item.to_data() for item in outcome.version_drift],
        "dependency_evidence": [item.to_data() for item in outcome.dependency_evidence],
        "dependency_drift": [item.to_data() for item in outcome.dependency_drift],
    }
    profile = outcome.finding.fingerprint.writer_profile
    if profile is not None:
        data["writer_profile"] = profile.to_data()
    return data


__all__ = ["RunReplayOutcome", "replay_run", "replay_validated_run"]
