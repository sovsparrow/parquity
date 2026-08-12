from __future__ import annotations

import sys
from pathlib import Path

from ..engines import resolve_engine
from ..engines.base import ProviderOperationError
from ..evidence import bounded_detail
from .control import CONTROL_NAME, WorkerControl
from .observations import ObservationError, encode_observation


def main() -> int:
    arguments = tuple(sys.argv[1:])
    engine, version, source, directory = _arguments(arguments)
    try:
        resolution = resolve_engine(engine)
        reader = resolution.reader
        if (
            not resolution.availability.available
            or reader is None
            or reader.identity.version != version
        ):
            raise RuntimeError("recorded reader is unavailable or changed")
        try:
            table = reader.read(source)
        except ProviderOperationError as error:
            if error.engine != engine or error.operation != "read":
                raise RuntimeError("provider error ownership conflicts with the request") from error
            return _error(
                directory,
                "PROVIDER_ERROR",
                engine,
                version,
                error.provider_type,
                error.detail,
            )
        payload, metadata = encode_observation(table)
        (directory / "observation.arrow").write_bytes(payload)
        return _emit(directory, WorkerControl("SUCCESS", engine, version, metadata, "SUCCESS", ""))
    except ObservationError as error:
        return _error(directory, "LIMIT_ERROR", engine, version, type(error).__name__, error)
    except Exception as error:  # noqa: BLE001 - child reports unexpected failures to its parent.
        return _error(directory, "INTERNAL_ERROR", engine, version, type(error).__name__, error)


def _arguments(arguments: tuple[str, ...]) -> tuple[str, str, Path, Path]:
    if len(arguments) != 8 or arguments[::2] != ("--engine", "--version", "--input", "--out"):
        raise ValueError("worker arguments are malformed")
    engine, version, source, directory = arguments[1::2]
    if not engine or not version:
        raise ValueError("worker identity is incomplete")
    return engine, version, Path(source), Path(directory)


def _emit(directory: Path, control: WorkerControl) -> int:
    with (directory / CONTROL_NAME).open("xb") as stream:
        stream.write(control.canonical_bytes())
    return 0


def _error(
    directory: Path,
    outcome: str,
    engine: str,
    version: str,
    kind: str,
    detail: object,
) -> int:
    return _emit(
        directory,
        WorkerControl(outcome, engine, version, None, kind, bounded_detail(detail)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
