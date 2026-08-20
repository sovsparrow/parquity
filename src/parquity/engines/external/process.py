from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from .protocol import MAX_STREAM_BYTES, ExternalEngineProtocolError

MAX_DETAIL_BYTES = 2048


class BridgeUnavailableError(RuntimeError):
    """The configured command could not be executed at all."""


@dataclass(frozen=True, slots=True)
class BridgeOutcome:
    exit_code: int
    stdout: bytes
    stderr: str
    timed_out: bool


def run_bridge(
    command: Sequence[str], arguments: Sequence[str], timeout_seconds: int
) -> BridgeOutcome:
    argv = (*command, *arguments)
    try:
        completed = subprocess.run(  # noqa: S603 - configured shell-free bridge argv.
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as expired:
        return BridgeOutcome(-1, b"", _text(expired.stderr), True)
    except OSError as error:
        raise BridgeUnavailableError(f"bridge command could not be executed: {error}") from error
    stdout = completed.stdout
    if len(stdout) > MAX_STREAM_BYTES:
        raise ExternalEngineProtocolError(f"bridge stdout exceeds {MAX_STREAM_BYTES} bytes")
    return BridgeOutcome(completed.returncode, stdout, _text(completed.stderr), False)


def _text(payload: bytes | str | None) -> str:
    if payload is None:
        return ""
    raw = payload if isinstance(payload, bytes) else payload.encode("utf-8", "replace")
    return raw[:MAX_STREAM_BYTES].decode("utf-8", "replace")


def diagnostic(detail: str, stderr: str) -> str:
    tail = " ".join(stderr.split())[-MAX_DETAIL_BYTES:]
    if not tail:
        return detail
    return f"{detail}; stderr: {tail}" if detail else f"stderr: {tail}"


__all__ = [
    "MAX_DETAIL_BYTES",
    "BridgeOutcome",
    "BridgeUnavailableError",
    "diagnostic",
    "run_bridge",
]
