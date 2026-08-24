"""A controllable ``parquity.bridge.v1`` implementation, run as a real subprocess.

Faults are selected through ``PARQUITY_TEST_BRIDGE_FAULT`` so a test can drive one behaviour
without a second program. Blocking paths are bounded by the supervising test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

PROTOCOL = "parquity.bridge.v1"
ENGINE = os.environ.get("PARQUITY_TEST_BRIDGE_ENGINE", "controlled")
VERSION = os.environ.get("PARQUITY_TEST_BRIDGE_VERSION", "9.9.9")
DIRECTIONS = os.environ.get("PARQUITY_TEST_BRIDGE_DIRECTIONS", "read,write")
PROFILES: dict[str, dict[str, object]] = {
    "compression-gzip": {"compression": "gzip"},
    "row-group-2": {"row_group_size": 2},
}


def emit(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def fail(kind: str, detail: str, code: int) -> int:
    emit({"status": "ERROR", "kind": kind, "detail": detail})
    return code


def argument(argv: list[str], flag: str) -> str | None:
    if flag not in argv:
        return None
    index = argv.index(flag)
    return argv[index + 1] if index + 1 < len(argv) else None


def info(fault: str | None) -> int:
    if fault == "info-exit":
        sys.stderr.write("probe refused\n")
        return 3
    if fault == "info-garbage":
        sys.stdout.write("not json")
        return 0
    payload: dict[str, object] = {
        "protocol": "wrong.protocol.v9" if fault == "info-protocol" else PROTOCOL,
        "engine": "someone-else" if fault == "info-engine" else ENGINE,
        "version": VERSION,
        "directions": [item for item in DIRECTIONS.split(",") if item],
        "writer_profiles": {"nonexistent-profile": {"x": 1}}
        if fault == "info-profile"
        else PROFILES,
    }
    emit(payload)
    return 0


def transfer(source: str, target: str) -> None:
    Path(target).write_bytes(Path(source).read_bytes())


def _provider() -> int:
    return fail("ControlledProviderError", "controlled provider failure", 1)


def _reject() -> int:
    return fail("UsageError", "controlled request rejection", 2)


def _garbage() -> int:
    sys.stdout.write("not json at all")
    return 0


def _silent() -> int:
    emit({"status": "OK"})
    return 0


def _crash() -> int:
    sys.stderr.write("controlled crash\n")
    return 42


def _malformed_failure() -> int:
    emit({"status": "ERROR", "kind": "not a valid kind!", "detail": "x"})
    return 1


def _slow() -> int:
    time.sleep(30)
    return 0


def _oversized_stdout() -> int:
    os.write(1, b"x" * (64 * 1024 + 1))
    return 0


def _descendant() -> int:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, threading; "
            "signal.signal(signal.SIGTERM, lambda signum, frame: None); "
            "threading.Event().wait()",
        ],
        stdin=subprocess.DEVNULL,
    )
    ready = Path(os.environ["PARQUITY_TEST_BRIDGE_READY"])
    ready.write_text(f"{os.getpid()} {child.pid}", encoding="utf-8")
    threading.Event().wait()
    return 0


OPERATION_FAULTS: dict[str, Callable[[], int]] = {
    "provider": _provider,
    "reject": _reject,
    "garbage": _garbage,
    "silent": _silent,
    "crash": _crash,
    "malformed-failure": _malformed_failure,
    "slow": _slow,
    "oversized-stdout": _oversized_stdout,
    "descendant": _descendant,
}


def main(argv: list[str]) -> int:
    fault = os.environ.get("PARQUITY_TEST_BRIDGE_FAULT")
    if not argv:
        return fail("UsageError", "no operation", 2)
    operation, rest = argv[0], argv[1:]

    if operation == "info":
        return info(fault)
    if operation not in ("read", "write"):
        return fail("UsageError", f"unknown operation: {operation}", 2)

    injected = OPERATION_FAULTS.get(fault or "")
    if injected is not None:
        return injected()

    # The tables themselves are opaque here: every operation copies its input to its output, so a
    # round trip through the adapter is exercised without a Parquet implementation.
    incoming = "--parquet" if operation == "read" else "--arrow"
    outgoing = "--arrow" if operation == "read" else "--parquet"
    source, target = argument(rest, incoming), argument(rest, outgoing)
    if source is None or target is None:
        return fail("UsageError", f"{operation} requires {incoming} and {outgoing}", 2)

    profile = argument(rest, "--profile")
    if profile is not None and profile not in PROFILES:
        return fail("UsageError", f"undeclared profile: {profile}", 2)
    if profile is not None:
        Path(target).with_suffix(".profile").write_text(profile, encoding="utf-8")

    transfer(source, target)
    emit({"status": "OK"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
