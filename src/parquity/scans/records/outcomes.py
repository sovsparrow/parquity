from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from ...evidence import json_codec as codec
from ..limits import MAX_STDERR_BYTES
from ..observations import ObservationError, ObservationMetadata
from .support import reject as _reject
from .support import text as _text

_OUTCOME_FIELDS = "engine version kind diagnostic_kind detail stderr stderr_truncated row_count column_count schema_sha256 ipc_sha256 ipc_bytes observation_group"


class ReaderOutcomeKind(StrEnum):
    SUCCESS = "SUCCESS"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    PROCESS_ERROR = "PROCESS_CRASH"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True)
class ReaderOutcomeRecord:
    engine: str
    version: str
    kind: ReaderOutcomeKind
    diagnostic_kind: str
    detail: str
    stderr: str
    stderr_truncated: bool
    row_count: int | None = None
    column_count: int | None = None
    schema_sha256: str | None = None
    ipc_sha256: str | None = None
    ipc_bytes: int | None = None
    observation_group: str | None = None

    def __post_init__(self) -> None:
        _validate_outcome_record(self)

    def to_data(self) -> dict[str, object]:
        return {
            "engine": self.engine,
            "version": self.version,
            "kind": self.kind.value,
            "diagnostic_kind": self.diagnostic_kind,
            "detail": self.detail,
            "stderr": self.stderr,
            "stderr_truncated": self.stderr_truncated,
            "row_count": self.row_count,
            "column_count": self.column_count,
            "schema_sha256": self.schema_sha256,
            "ipc_sha256": self.ipc_sha256,
            "ipc_bytes": self.ipc_bytes,
            "observation_group": self.observation_group,
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> ReaderOutcomeRecord:
        codec.require_exact_keys(data, set(_OUTCOME_FIELDS.split()), "reader outcome")
        try:
            kind = ReaderOutcomeKind(_text(data, "kind"))
        except ValueError as error:
            raise codec.FindingValidationError("reader outcome kind is malformed") from error
        return cls(
            _text(data, "engine"),
            _text(data, "version"),
            kind,
            _text(data, "diagnostic_kind"),
            _text(data, "detail"),
            _text(data, "stderr"),
            codec.boolean(data["stderr_truncated"], "stderr truncated"),
            codec.optional_integer(data["row_count"], "row count"),
            codec.optional_integer(data["column_count"], "column count"),
            _optional_text(data["schema_sha256"], "schema SHA-256"),
            _optional_text(data["ipc_sha256"], "IPC SHA-256"),
            codec.optional_integer(data["ipc_bytes"], "IPC bytes"),
            _optional_text(data["observation_group"], "observation group"),
        )

    @property
    def observation_metadata(self) -> ObservationMetadata | None:
        if self.kind is not ReaderOutcomeKind.SUCCESS:
            return None
        return ObservationMetadata(
            _required_int(self.ipc_bytes),
            _required_str(self.ipc_sha256),
            _required_int(self.row_count),
            _required_int(self.column_count),
            _required_str(self.schema_sha256),
        )


def reader_outcomes(value: object) -> tuple[ReaderOutcomeRecord, ...]:
    values = codec.mappings(value, "outcomes")
    return tuple(ReaderOutcomeRecord.from_data(item) for item in values)


def _validate_outcome_record(outcome: ReaderOutcomeRecord) -> None:
    raw_kind = cast(object, outcome.kind)
    raw_truncated = cast(object, outcome.stderr_truncated)
    _reject(not isinstance(raw_kind, ReaderOutcomeKind), "reader outcome kind is malformed")
    _reject(not outcome.engine or not outcome.version, "reader outcome identity is malformed")
    evidence = (
        outcome.row_count,
        outcome.column_count,
        outcome.schema_sha256,
        outcome.ipc_sha256,
        outcome.ipc_bytes,
        outcome.observation_group,
    )
    success = outcome.kind is ReaderOutcomeKind.SUCCESS
    _reject(
        success != all(value is not None for value in evidence),
        "reader outcome evidence is malformed",
    )
    diagnostic_pair = (outcome.diagnostic_kind, outcome.detail)
    process_kind = outcome.kind in (ReaderOutcomeKind.PROCESS_ERROR, ReaderOutcomeKind.TIMEOUT)
    malformed = (
        not outcome.diagnostic_kind
        or (success and diagnostic_pair != (ReaderOutcomeKind.SUCCESS.value, ""))
        or (process_kind and diagnostic_pair != (outcome.kind.value, outcome.stderr))
        or not isinstance(raw_truncated, bool)
        or len(outcome.stderr.encode()) > MAX_STDERR_BYTES
    )
    _reject(malformed, "reader outcome diagnostics are malformed")
    if success:
        try:
            _ = outcome.observation_metadata
        except ObservationError as error:
            raise codec.FindingValidationError(str(error)) from error


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else codec.string(value, label)


def _required_int(value: int | None) -> int:
    if value is None:
        raise codec.FindingValidationError("reader outcome evidence is malformed")
    return value


def _required_str(value: str | None) -> str:
    if value is None:
        raise codec.FindingValidationError("reader outcome evidence is malformed")
    return value


__all__ = ["ReaderOutcomeKind", "ReaderOutcomeRecord", "reader_outcomes"]
