from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..configuration import (
    fuzz_examples_is_valid,
    fuzz_saved_limit_is_valid,
    fuzz_seed_is_valid,
)
from ..evidence import is_sha256
from ..evidence import json_codec as codec
from ..model import Case

CHECK_COMPLETE = "CHECK_COMPLETE"
EXAMPLE_BOUND_REACHED = "EXAMPLE_BOUND_REACHED"
STRATEGY_EXHAUSTED = "STRATEGY_EXHAUSTED"
SAVED_EVIDENCE_LIMIT_REACHED = "SAVED_EVIDENCE_LIMIT_REACHED"
_V1_SAVED_EVIDENCE_LIMIT = "FINDING_CAP_REACHED"
DISCOVERY_OVERFLOW = "DISCOVERY"
MINIMIZATION_OVERFLOW = "MINIMIZATION"


@dataclass(frozen=True, slots=True)
class GenerationEvidence:
    profile: str
    schema_case_id: str

    def __post_init__(self) -> None:
        if self.profile != "schema":
            raise codec.FindingValidationError("generation profile is not recognized")
        _validate_sha256(self.schema_case_id, "schema Case identity")

    def to_data(self) -> dict[str, object]:
        return {"profile": self.profile, "schema_case_id": self.schema_case_id}

    def binds(self, *cases: Case) -> bool:
        return all(Case(case.fields, ()).case_id == self.schema_case_id for case in cases)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> GenerationEvidence:
        codec.require_exact_keys(data, {"profile", "schema_case_id"}, "generation evidence")
        return cls(
            codec.string(codec.required(data, "profile"), "generation profile"),
            codec.string(codec.required(data, "schema_case_id"), "schema_case_id"),
        )


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:
    examples: int | None
    seed: int | None
    max_saved: int | None
    stop_reason: str
    evaluated_cases: int | None = None
    evaluated_cells: int | None = None

    def __post_init__(self) -> None:
        if self.stop_reason == CHECK_COMPLETE:
            self._validate_check()
            return
        self._validate_fuzz()

    def _validate_check(self) -> None:
        if any(value is not None for value in (self.examples, self.seed, self.max_saved)):
            raise codec.FindingValidationError("check discovery evidence must not declare bounds")
        if self.evaluated_cases is not None or self.evaluated_cells is not None:
            raise codec.FindingValidationError("check discovery evidence declares counts")

    def _validate_fuzz(self) -> None:
        if self.stop_reason not in (
            EXAMPLE_BOUND_REACHED,
            STRATEGY_EXHAUSTED,
            SAVED_EVIDENCE_LIMIT_REACHED,
        ):
            raise codec.FindingValidationError("discovery stop reason is not recognized")
        if not fuzz_examples_is_valid(self.examples):
            raise codec.FindingValidationError("fuzz discovery requires a positive example bound")
        if not fuzz_seed_is_valid(self.seed):
            raise codec.FindingValidationError("fuzz discovery seed is outside the supported range")
        if not fuzz_saved_limit_is_valid(self.max_saved):
            raise codec.FindingValidationError(
                "fuzz discovery saved-evidence limit is outside the range"
            )
        if (self.evaluated_cases is None) != (self.evaluated_cells is None):
            raise codec.FindingValidationError("fuzz discovery counts must be recorded together")
        if any(isinstance(value, bool) for value in (self.evaluated_cases, self.evaluated_cells)):
            raise codec.FindingValidationError("fuzz discovery counts must be integers")
        if self.evaluated_cases is not None and not 1 <= self.evaluated_cases <= self.examples:
            raise codec.FindingValidationError("evaluated Case count is outside the example bound")
        if (
            self.evaluated_cases is not None
            and self.evaluated_cells is not None
            and self.evaluated_cells < self.evaluated_cases
        ):
            raise codec.FindingValidationError(
                "evaluated cell count is smaller than the Case count"
            )

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "examples": self.examples,
            "seed": self.seed,
            "max_findings": self.max_saved,
            "stop_reason": stop_reason_to_v1(self.stop_reason),
        }
        if self.evaluated_cases is not None:
            data["evaluated_cases"] = self.evaluated_cases
            data["evaluated_cells"] = self.evaluated_cells
        return data

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> DiscoveryEvidence:
        keys = {"examples", "seed", "max_findings", "stop_reason"}
        has_counts = "evaluated_cases" in data or "evaluated_cells" in data
        if has_counts:
            keys.update(("evaluated_cases", "evaluated_cells"))
        codec.require_exact_keys(data, keys, "discovery evidence")
        return cls(
            codec.optional_integer(codec.required(data, "examples"), "examples"),
            codec.optional_integer(codec.required(data, "seed"), "seed"),
            codec.optional_integer(codec.required(data, "max_findings"), "max_findings"),
            stop_reason_from_v1(codec.string(codec.required(data, "stop_reason"), "stop_reason")),
            (
                codec.integer(codec.required(data, "evaluated_cases"), "evaluated_cases")
                if has_counts
                else None
            ),
            (
                codec.integer(codec.required(data, "evaluated_cells"), "evaluated_cells")
                if has_counts
                else None
            ),
        )


def stop_reason_to_v1(value: str) -> str:
    if value == SAVED_EVIDENCE_LIMIT_REACHED:
        return _V1_SAVED_EVIDENCE_LIMIT
    if value == STRATEGY_EXHAUSTED:
        raise codec.FindingValidationError("v2 stop reason cannot be encoded as v1")
    return value


def stop_reason_from_v1(value: str) -> str:
    if value == _V1_SAVED_EVIDENCE_LIMIT:
        return SAVED_EVIDENCE_LIMIT_REACHED
    if value in (SAVED_EVIDENCE_LIMIT_REACHED, STRATEGY_EXHAUSTED):
        raise codec.FindingValidationError("v1 stop reason is not recognized")
    return value


def _validate_sha256(value: str, label: str) -> None:
    if not is_sha256(value):
        raise codec.FindingValidationError(f"{label} must be a lowercase SHA-256 value")
