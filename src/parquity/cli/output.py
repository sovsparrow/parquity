from __future__ import annotations

import json
import os
import sys
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import BinaryIO, cast

from ..verdicts import EngineAvailability
from .presentation import render
from .progress import indicator, stop_active
from .style import Style, controls_enabled

_FORCE_JSON = ContextVar("parquity_force_json", default=False)


def unavailable(command: str, engines: tuple[EngineAvailability, ...]) -> int:
    payload: dict[str, object] = {"command": command, "status": "CONFIGURATION_ERROR"}
    payload["engines"] = [item.to_data() for item in engines]
    emit(payload)
    for item in engines:
        failure(f"{item.name}: {item.detail}. {item.installation_hint}")
    return 2


def configuration(command: str, kind: str, detail: str) -> int:
    detail = _safe_detail(detail)
    payload = {"command": command, "status": "CONFIGURATION_ERROR"}
    emit({**payload, "error": {"kind": kind, "detail": detail}})
    failure(detail)
    return 2


def failure(detail: str) -> None:
    stop_active()
    detail = _safe_detail(detail)
    controls = controls_enabled() and bool(sys.stderr.isatty())
    print(f"{Style(controls).error('parquity:')} {detail}", file=sys.stderr)


def emit(value: dict[str, object]) -> None:
    stop_active()
    document = dict(value)
    document["format"] = "parquity.cli.v1"
    if not _FORCE_JSON.get() and _is_tty():
        output = render(document, controls=controls_enabled())
        if output:
            sys.stdout.write(output)
            sys.stdout.flush()
        return
    _emit_json(document)


@contextmanager
def output_mode(*, force_json: bool) -> Generator[None, None, None]:
    token = _FORCE_JSON.set(force_json)
    try:
        yield
    finally:
        stop_active()
        _FORCE_JSON.reset(token)


@contextmanager
def progress(label: str) -> Generator[None, None, None]:
    enabled = (
        not _FORCE_JSON.get()
        and "CI" not in os.environ
        and os.environ.get("TERM") != "dumb"
        and bool(sys.stdout.isatty())
        and bool(sys.stderr.isatty())
    )
    with indicator(label, enabled=enabled):
        yield


def _is_tty() -> bool:
    return bool(sys.stdout.isatty())


def _emit_json(document: dict[str, object]) -> None:
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        + b"\n"
    )
    raw = getattr(sys.stdout, "buffer", None)
    if raw is not None:
        output = cast(BinaryIO, raw)
        output.write(payload)
        output.flush()
        return
    sys.stdout.write(payload.decode("utf-8"))
    sys.stdout.flush()


def _safe_detail(value: str) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:500] or "operation failed"


__all__ = ["configuration", "emit", "failure", "output_mode", "progress", "unavailable"]
