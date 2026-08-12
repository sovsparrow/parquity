from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple

from ..evidence import json_codec as codec
from .observations import ObservationMetadata
from .records import canonical_bytes

WORKER_CONTROL_FORMAT = "parquity.worker-control.v1"
ARTIFACT_NAME = "observation.arrow"
CONTROL_NAME = "control.json"
MAX_CONTROL_BYTES = 16 * 1024
_CONTROL_KEYS = "format outcome engine engine_version artifact artifact_bytes artifact_sha256 row_count column_count schema_sha256 diagnostic_kind detail"


class WorkerProtocolError(RuntimeError): ...


class WorkerControl(NamedTuple):
    outcome: str
    engine: str
    engine_version: str
    metadata: ObservationMetadata | None
    diagnostic_kind: str
    detail: str

    def to_data(self) -> dict[str, object]:
        metadata = self.metadata
        return {
            "format": WORKER_CONTROL_FORMAT,
            "outcome": self.outcome,
            "engine": self.engine,
            "engine_version": self.engine_version,
            "artifact": ARTIFACT_NAME if metadata is not None else None,
            "artifact_bytes": None if metadata is None else metadata.byte_count,
            "artifact_sha256": None if metadata is None else metadata.sha256,
            "row_count": None if metadata is None else metadata.row_count,
            "column_count": None if metadata is None else metadata.column_count,
            "schema_sha256": None if metadata is None else metadata.schema_sha256,
            "diagnostic_kind": self.diagnostic_kind,
            "detail": self.detail,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_data())

    @classmethod
    def from_json(cls, payload: bytes) -> WorkerControl:
        try:
            decoded = codec.decode(payload)
            data = codec.mapping(decoded, "worker control")
            if set(data) != set(_CONTROL_KEYS.split()) or data["format"] != WORKER_CONTROL_FORMAT:
                raise WorkerProtocolError("worker control fields are malformed")
            metadata = _control_metadata(data)
            if data["artifact"] != (ARTIFACT_NAME if metadata is not None else None):
                raise WorkerProtocolError("worker artifact evidence is malformed")
            control = cls(
                codec.string(data["outcome"], "outcome"),
                codec.string(data["engine"], "engine"),
                codec.string(data["engine_version"], "engine version"),
                metadata,
                codec.string(data["diagnostic_kind"], "diagnostic kind"),
                codec.string(data["detail"], "detail"),
            )
            allowed = ("SUCCESS", "PROVIDER_ERROR", "LIMIT_ERROR", "INTERNAL_ERROR")
            if (
                control.outcome not in allowed
                or not all((control.engine, control.engine_version, control.diagnostic_kind))
                or (control.outcome == "SUCCESS") != (metadata is not None)
            ):
                raise WorkerProtocolError("worker control identity is malformed")
        except WorkerProtocolError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise WorkerProtocolError("worker control is malformed") from error
        if control.canonical_bytes() != payload:
            raise WorkerProtocolError("worker control is not canonical")
        return control


def _control_metadata(data: Mapping[str, object]) -> ObservationMetadata | None:
    keys = ("artifact_bytes", "artifact_sha256", "row_count", "column_count", "schema_sha256")
    values = tuple(data[key] for key in keys)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise WorkerProtocolError("worker observation metadata is incomplete")
    size, digest, rows, columns, schema = values
    if not isinstance(digest, str) or not isinstance(schema, str):
        raise WorkerProtocolError("worker observation digests are malformed")
    byte_count = codec.integer(size, "artifact bytes")
    counts = (codec.integer(rows, "row count"), codec.integer(columns, "column count"))
    return ObservationMetadata(byte_count, digest, *counts, schema)


__all__ = [
    "ARTIFACT_NAME",
    "CONTROL_NAME",
    "MAX_CONTROL_BYTES",
    "WorkerControl",
    "WorkerProtocolError",
]
