"""Configuration helpers for driving the controllable bridge from a test."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from parquity.engines.external import reset_external_engine_caches
from parquity.engines.external.config import ENGINES_FILE_VARIABLE

BRIDGE = Path(__file__).with_name("bridge_program.py")
NAME = "controlled"


def bridge_command() -> tuple[str, ...]:
    return (sys.executable, str(BRIDGE))


def declaration(
    name: str = NAME,
    command: Sequence[str] | None = None,
    timeout_seconds: int | None = None,
) -> str:
    argv = json.dumps(list(bridge_command() if command is None else command))
    lines = [f"[engines.{name}]", f"command = {argv}"]
    if timeout_seconds is not None:
        lines.append(f"timeout_seconds = {timeout_seconds}")
    return "\n".join(lines) + "\n"


def configure(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    document: str | None = None,
    *,
    engine: str = NAME,
) -> Path:
    """Points Parquity at a bridge declaration and clears the memoized configuration and probe.

    The probe is cached per process so a run spawns each bridge once; a test that changes what the
    bridge reports has to invalidate it or it would observe the previous answer.
    """
    path = root / "engines.toml"
    path.write_text(declaration(engine) if document is None else document, encoding="utf-8")
    monkeypatch.setenv(ENGINES_FILE_VARIABLE, str(path))
    reset_external_engine_caches()
    return path


def fault(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("PARQUITY_TEST_BRIDGE_FAULT", raising=False)
    else:
        monkeypatch.setenv("PARQUITY_TEST_BRIDGE_FAULT", value)
    reset_external_engine_caches()


def directions(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PARQUITY_TEST_BRIDGE_DIRECTIONS", value)
    reset_external_engine_caches()


__all__ = [
    "BRIDGE",
    "NAME",
    "bridge_command",
    "configure",
    "declaration",
    "directions",
    "fault",
]
