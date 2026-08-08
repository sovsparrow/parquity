from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import cast


def _control(outcome: str, artifact: bytes | None = None) -> bytes:
    metadata: tuple[int, str, int, int, str] | None = None
    if artifact is not None:
        metadata = (len(artifact), hashlib.sha256(artifact).hexdigest(), 2, 1, "a" * 64)
    value = {
        "format": "parquity.worker-control.v1",
        "outcome": outcome,
        "engine": "reader",
        "engine_version": "1.0",
        "artifact": None if artifact is None else "observation.arrow",
        "artifact_bytes": None if metadata is None else metadata[0],
        "artifact_sha256": None if metadata is None else metadata[1],
        "row_count": None if metadata is None else metadata[2],
        "column_count": None if metadata is None else metadata[3],
        "schema_sha256": None if metadata is None else metadata[4],
        "diagnostic_kind": "SUCCESS" if outcome == "SUCCESS" else "ControlledError",
        "detail": "controlled detail",
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _changed_control(outcome: str, artifact: bytes | None = None, **changes: object) -> bytes:
    value = cast(dict[str, object], json.loads(_control(outcome, artifact)))
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    mode = sys.argv[1]
    directory = Path(sys.argv[2])
    if mode in {"block", "resist", "descendant"}:
        return _block(mode)
    return _complete(mode, directory)


def _complete(mode: str, directory: Path) -> int:
    if mode in {"malformed", "extra", "oversized", "noncanonical", "wrong-engine", "incomplete"}:
        return _control_failure(mode)
    if mode in {
        "bad-digest",
        "bad-control-digest",
        "extra-artifact",
        "artifact-directory",
        "artifact-symlink",
    }:
        return _artifact_failure(mode, directory)
    if mode == "success":
        artifact = b"controlled artifact"
        (directory / "observation.arrow").write_bytes(artifact)
        sys.stdout.buffer.write(_control("SUCCESS", artifact) + b"\n")
    elif mode == "provider":
        sys.stdout.buffer.write(_control("PROVIDER_ERROR") + b"\n")
    elif mode == "internal":
        sys.stdout.buffer.write(_control("INTERNAL_ERROR") + b"\n")
    elif mode == "exit":
        raise SystemExit(7)
    elif mode == "empty":
        pass
    elif mode in {"invalid-stderr", "crash", "stderr"}:
        return _diagnostic(mode, directory)
    else:
        raise ValueError(mode)
    return 0


def _diagnostic(mode: str, directory: Path) -> int:
    if mode == "invalid-stderr":
        sys.stderr.buffer.write(b"\xff" * (64 * 1024))
        sys.stderr.buffer.flush()
        raise SystemExit(7)
    if mode == "crash":
        os.abort()
    sys.stderr.write(str(directory) + "x" * (64 * 1024 + 1))
    sys.stderr.flush()
    sys.stdout.buffer.write(_control("PROVIDER_ERROR") + b"\n")
    return 0


def _control_failure(mode: str) -> int:
    if mode == "malformed":
        sys.stdout.write("not-json\n")
    elif mode == "extra":
        sys.stdout.buffer.write(_control("PROVIDER_ERROR") + b"\nextra\n")
    elif mode == "oversized":
        sys.stdout.write("x" * (16 * 1024 + 1))
    elif mode == "noncanonical":
        sys.stdout.write(json.dumps(json.loads(_control("PROVIDER_ERROR")), indent=2) + "\n")
    elif mode == "wrong-engine":
        sys.stdout.buffer.write(_changed_control("PROVIDER_ERROR", engine="other") + b"\n")
    else:
        sys.stdout.buffer.write(_changed_control("PROVIDER_ERROR", artifact_bytes=1) + b"\n")
    return 0


def _artifact_failure(mode: str, directory: Path) -> int:
    artifact = b"controlled artifact"
    if mode == "bad-digest":
        (directory / "observation.arrow").write_bytes(artifact + b"changed")
        control = _control("SUCCESS", artifact)
    elif mode == "bad-control-digest":
        (directory / "observation.arrow").write_bytes(artifact)
        control = _changed_control("SUCCESS", artifact, artifact_sha256=1)
    elif mode == "extra-artifact":
        (directory / "unexpected").write_text("extra")
        control = _control("PROVIDER_ERROR")
    elif mode == "artifact-directory":
        (directory / "observation.arrow").mkdir()
        control = _control("SUCCESS", artifact)
    else:
        target = Path(sys.argv[3])
        target.write_bytes(artifact)
        (directory / "observation.arrow").symlink_to(target)
        control = _control("SUCCESS", artifact)
    sys.stdout.buffer.write(control + b"\n")
    return 0


def _block(mode: str) -> int:
    if mode == "resist":
        signal.signal(signal.SIGTERM, lambda signum, frame: None)
    ready = Path(sys.argv[3])
    if mode == "descendant" and os.fork() == 0:
        signal.signal(signal.SIGTERM, lambda signum, frame: None)
        ready.write_text(f"{os.getppid()} {os.getpid()}", encoding="utf-8")
    elif mode != "descendant":
        ready.write_text("ready", encoding="utf-8")
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
