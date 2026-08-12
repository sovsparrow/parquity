from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..evidence import EngineVersion, engine_versions_from_data
from ..evidence import json_codec as codec
from ..profiles import WriterProfilePlan, optional_writer_profile_plan_from_data
from ..verdicts import CellResult, FailureFingerprint, MatrixRun

MATRIX_FORMAT = "parquity.matrix.v1"


@dataclass(frozen=True, slots=True)
class MatrixRecord:
    case_id: str
    writers: tuple[EngineVersion, ...]
    readers: tuple[EngineVersion, ...]
    target: FailureFingerprint
    selection_order: tuple[FailureFingerprint, ...]
    results: tuple[CellResult, ...]
    writer_profiles: WriterProfilePlan | None = None

    def __post_init__(self) -> None:
        try:
            run = MatrixRun(
                self.case_id,
                self.results,
                (),
                self.writers,
                self.readers,
                self.writer_profiles,
            )
        except ValueError as error:
            raise codec.FindingValidationError("matrix result structure is invalid") from error
        observed = _fingerprints(run)
        if self.selection_order != observed:
            raise codec.FindingValidationError("matrix observation order is not canonical")
        if self.target not in observed:
            raise codec.FindingValidationError("matrix target is absent from the observations")
        if not self.writers or not self.readers:
            raise codec.FindingValidationError("matrix engine sets must not be empty")

    @classmethod
    def from_run(
        cls,
        run: MatrixRun,
        writers: tuple[EngineVersion, ...],
        readers: tuple[EngineVersion, ...],
        target: FailureFingerprint,
    ) -> MatrixRecord:
        if run.writers != writers or run.readers != readers:
            raise codec.FindingValidationError("matrix selections conflict with the evaluated run")
        observations = _fingerprints(run)
        return cls(
            run.case_id,
            writers,
            readers,
            target,
            observations,
            run.results,
            run.writer_profiles,
        )

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "format": MATRIX_FORMAT,
            "case_id": self.case_id,
            "writers": [engine.to_data() for engine in self.writers],
            "readers": [engine.to_data() for engine in self.readers],
            "target": self.target.to_data(),
            "selection_order": [fingerprint.to_data() for fingerprint in self.selection_order],
            "results": [result.to_data() for result in self.results],
        }
        if self.writer_profiles is not None:
            data["writer_profiles"] = self.writer_profiles.to_data()
        return data

    def canonical_bytes(self) -> bytes:
        return codec.canonical_bytes(self.to_data())

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> MatrixRecord:
        plan = optional_writer_profile_plan_from_data(data)
        keys = {
            "format",
            "case_id",
            "writers",
            "readers",
            "target",
            "selection_order",
            "results",
        }
        if plan is not None:
            keys.add("writer_profiles")
        codec.require_exact_keys(data, keys, "matrix evidence")
        if codec.required(data, "format") != MATRIX_FORMAT:
            raise codec.FindingValidationError(f"matrix format must be {MATRIX_FORMAT!r}")
        return cls(
            case_id=codec.string(codec.required(data, "case_id"), "case_id"),
            writers=engine_versions_from_data(codec.required(data, "writers"), "writers"),
            readers=engine_versions_from_data(codec.required(data, "readers"), "readers"),
            target=FailureFingerprint.from_data(
                codec.mapping(codec.required(data, "target"), "target"),
                allow_profile=plan is not None,
            ),
            selection_order=tuple(
                FailureFingerprint.from_data(
                    codec.mapping(value, "observation"), allow_profile=plan is not None
                )
                for value in codec.sequence(
                    codec.required(data, "selection_order"), "selection_order"
                )
            ),
            results=tuple(
                CellResult.from_data(
                    codec.mapping(value, "matrix result"), allow_profile=plan is not None
                )
                for value in codec.sequence(codec.required(data, "results"), "results")
            ),
            writer_profiles=plan,
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> MatrixRecord:
        try:
            return cls.from_data(codec.mapping(codec.decode(payload), "matrix"))
        except codec.FindingValidationError:
            raise
        except (TypeError, ValueError) as error:
            raise codec.FindingValidationError("matrix.json is malformed") from error


def _fingerprints(run: MatrixRun) -> tuple[FailureFingerprint, ...]:
    return tuple(
        fingerprint
        for result in run.distinct_failures
        if (fingerprint := result.fingerprint) is not None
    )


__all__ = ["MATRIX_FORMAT", "MatrixRecord"]
