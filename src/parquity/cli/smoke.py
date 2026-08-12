from __future__ import annotations

import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from ..engines import CORE_ENGINE_DESCRIPTORS, EngineResolution
from ..engines.base import EngineReader, EngineWriter
from ..matrix import run_matrix
from ..model import Case, Field, Kind, TypeSpec
from ..verdicts import MatrixRun
from .output import availability_data, emit, failure

ResolveEngines = Callable[[Sequence[str]], tuple[EngineResolution, ...]]


def run_smoke(resolve_engines: ResolveEngines) -> int:
    names = tuple(descriptor.name for descriptor in CORE_ENGINE_DESCRIPTORS)
    resolutions = resolve_engines(names)
    writers: list[EngineWriter] = []
    readers: list[EngineReader] = []
    unavailable: list[object] = []
    for resolution in resolutions:
        if not resolution.availability.available:
            unavailable.append(availability_data(resolution.availability))
        elif resolution.writer is None or resolution.reader is None:
            raise TypeError("core engine resolution is missing a declared direction")
        else:
            writers.append(resolution.writer)
            readers.append(resolution.reader)
    if unavailable:
        payload: dict[str, object] = {
            "command": "smoke",
            "status": "CONFIGURATION_ERROR",
            "engines": unavailable,
        }
        emit(payload)
        for resolution in resolutions:
            item = resolution.availability
            if not item.available:
                failure(f"{item.name}: {item.detail}. {item.installation_hint}")
        return 2
    with tempfile.TemporaryDirectory(prefix="parquity-smoke-") as raw_directory:
        run = execute_smoke(Path(raw_directory), writers, readers)
    emit({"command": "smoke", **_matrix_data(run)})
    return 0 if not run.failures else 1


def execute_smoke(
    directory: Path,
    writers: Sequence[EngineWriter],
    readers: Sequence[EngineReader],
) -> MatrixRun:
    return run_matrix(_smoke_case(), directory, writers, readers)


def _matrix_data(run: MatrixRun) -> dict[str, object]:
    data: dict[str, object] = {
        "case_id": run.case_id,
        "status": run.status,
        "writers": [engine.to_data() for engine in run.writers],
        "readers": [engine.to_data() for engine in run.readers],
        "results": [result.to_data() for result in run.results],
    }
    if run.writer_profiles is not None:
        data["writer_profiles"] = run.writer_profiles.to_data()
    return data


def _smoke_case() -> Case:
    fields = (
        Field("boolean_value", TypeSpec(Kind.BOOL)),
        Field("int32_value", TypeSpec(Kind.INT32)),
        Field("int64_value", TypeSpec(Kind.INT64)),
        Field("string_value", TypeSpec(Kind.STRING)),
        Field("binary_value", TypeSpec(Kind.BINARY)),
    )
    return Case(
        fields,
        (
            (True, 2**31 - 1, 2**63 - 1, "Parquity", b"\x00\xff"),
            (False, -(2**31), -(2**63), "", b""),
            (None, None, None, None, None),
        ),
    )


__all__ = ["execute_smoke", "run_smoke"]
