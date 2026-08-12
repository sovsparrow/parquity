from __future__ import annotations

from pathlib import Path

from ..evidence import EngineVersion
from ..reporting import ReproductionStep
from . import records


def render_reproduce() -> bytes:
    return _template("reproduce").encode()


def render_upstream_repro(engines: tuple[EngineVersion, ...]) -> bytes:
    return (
        _template("upstream_repro")
        .replace("__ENGINES__", repr(tuple(item.name for item in engines)))
        .encode()
    )


def reproduction_steps(record: records.ScanFindingRecord) -> tuple[ReproductionStep, ...]:
    replay = ReproductionStep(
        "Parquity replay",
        "python reproduce.py",
        "Replays this file with the recorded readers. Exit 1 means reproduced; "
        "exit 0 means not reproduced.",
    )
    readers = tuple(
        ReproductionStep(
            f"Provider-only: {engine.name}",
            f"python upstream_repro.py {engine.name}",
            f"Reads input.parquet with {engine.name} and prints JSON. "
            "Exit 1 means the reader failed; exit 0 means it returned a table.",
        )
        for engine in sorted(record.engines, key=lambda item: item.name)
    )
    return replay, *readers


def _template(name: str) -> str:
    return (Path(__file__).with_name("templates") / f"{name}.tmpl").read_text(encoding="utf-8")


__all__ = ["render_reproduce", "render_upstream_repro", "reproduction_steps"]
