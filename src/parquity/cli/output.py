from __future__ import annotations

import os
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import BinaryIO, cast

from ..engines import EngineAvailability
from ..evidence import json_codec
from ..reporting import EvidenceReportView, RunReportView
from .presentation import render, render_evidence, render_report
from .progress import indicator, stop_active
from .style import Style, controls_enabled

_FORCE_JSON = ContextVar("parquity_force_json", default=False)


def availability_data(item: EngineAvailability) -> dict[str, object]:
    return {
        "name": item.name,
        "distribution": item.distribution,
        "tier": item.tier,
        "reader": item.reader,
        "writer": item.writer,
        "available": item.available,
        "version": item.version,
        "installation_hint": item.installation_hint,
        "detail": item.detail,
    }


def unavailable(command: str, engines: tuple[EngineAvailability, ...]) -> int:
    payload: dict[str, object] = {"command": command, "status": "CONFIGURATION_ERROR"}
    payload["engines"] = [availability_data(item) for item in engines]
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
    controls = controls_enabled(sys.stderr)
    print(f"{Style(controls).error('parquity:')} {detail}", file=sys.stderr)


def emit(
    value: dict[str, object],
    report: RunReportView | EvidenceReportView | None = None,
) -> None:
    stop_active()
    document = dict(value)
    document["format"] = "parquity.cli.v1"
    if not _FORCE_JSON.get() and _is_tty():
        controls = controls_enabled(sys.stdout)
        if report is None:
            output = render(document, controls=controls)
        else:
            command = document.get("command")
            status = document.get("status")
            if not isinstance(command, str) or not isinstance(status, str):
                raise TypeError("typed report output requires command and status")
            if isinstance(report, RunReportView):
                output = render_report(
                    report,
                    command=command,
                    status=status,
                    controls=controls,
                    output=document.get("output"),
                )
            else:
                output = render_evidence(
                    report,
                    command=command,
                    status=status,
                    controls=controls,
                )
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
def progress(label: str) -> Generator[Callable[[str], None], None, None]:
    enabled = (
        not _FORCE_JSON.get()
        and "CI" not in os.environ
        and controls_enabled(sys.stdout)
        and controls_enabled(sys.stderr)
    )
    with indicator(label, enabled=enabled) as update:
        yield update


def _is_tty() -> bool:
    return bool(sys.stdout.isatty())


def _emit_json(document: dict[str, object]) -> None:
    payload = json_codec.canonical_bytes(document) + b"\n"
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


__all__ = [
    "availability_data",
    "configuration",
    "emit",
    "failure",
    "output_mode",
    "progress",
    "unavailable",
]
