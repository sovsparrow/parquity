from __future__ import annotations

from collections.abc import Callable, Sequence
from importlib import import_module
from pathlib import Path

import pytest

from parquity.engines import EngineSelection
from parquity.engines.base import EngineReader, EngineWriter
from parquity.evidence import EngineVersion
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.profiles import WriterProfilePlan
from parquity.verdicts import MatrixRun

SCALAR_CASE = Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))

GeneratedEvaluator = Callable[[Case, Path, EngineSelection], MatrixRun]


def write_case(path: Path, case: Case = SCALAR_CASE) -> Case:
    path.write_bytes(case.canonical_bytes())
    return case


def selection_versions(
    selection: EngineSelection,
) -> tuple[tuple[EngineVersion, ...], tuple[EngineVersion, ...]]:
    writers = tuple(
        EngineVersion(engine.identity.name, engine.identity.version) for engine in selection.writers
    )
    readers = tuple(
        EngineVersion(engine.identity.name, engine.identity.version) for engine in selection.readers
    )
    return writers, readers


def patch_evaluator(
    monkeypatch: pytest.MonkeyPatch,
    evaluator: GeneratedEvaluator,
) -> None:
    workflow = import_module("parquity.generation.workflow")

    def run_matrix_adapter(
        case: Case,
        directory: Path,
        writers: Sequence[EngineWriter],
        readers: Sequence[EngineReader],
        writer_profiles: WriterProfilePlan | None = None,
    ) -> MatrixRun:
        del writer_profiles
        selection = EngineSelection(
            tuple(item.identity.name for item in writers),
            tuple(item.identity.name for item in readers),
            tuple(writers),
            tuple(readers),
        )
        return evaluator(case, directory, selection)

    monkeypatch.setattr(workflow, "run_matrix", run_matrix_adapter)


__all__ = [
    "SCALAR_CASE",
    "GeneratedEvaluator",
    "patch_evaluator",
    "selection_versions",
    "write_case",
]
