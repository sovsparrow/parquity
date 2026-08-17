from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pyarrow as pa

from ...profiles import WriterProfileIdentity
from ..base import EngineIdentity, ProviderOperationError
from .config import ExternalEngineSpec
from .process import BridgeUnavailableError, diagnostic, run_bridge
from .protocol import (
    CRASH_KIND,
    TIMEOUT_KIND,
    BridgeInfo,
    ExternalEngineProtocolError,
    parse_failure,
    parse_success,
)

ARTIFACT_NAME = "table.arrow"


class ExternalEngineFailure(Exception):
    """A failure the bridge reported about itself."""


@dataclass(frozen=True, slots=True)
class ExternalEngine:
    identity: EngineIdentity
    spec: ExternalEngineSpec
    info: BridgeInfo

    def read(self, path: Path) -> pa.Table:
        with tempfile.TemporaryDirectory(prefix="parquity-bridge-") as directory:
            artifact = Path(directory) / ARTIFACT_NAME
            self._invoke("read", ("--parquet", str(path), "--arrow", str(artifact)))
            if not artifact.is_file():
                raise ExternalEngineProtocolError(
                    f"{self.identity.name} reported success without writing an Arrow IPC file"
                )
            return _read_ipc(artifact, self.identity.name)

    def write(self, table: pa.Table, path: Path) -> None:
        self._write(table, path, None)

    def writer_profile(self, name: str) -> WriterProfileIdentity | None:
        options = self.info.writer_profiles.get(name)
        return None if options is None else WriterProfileIdentity(name, options)

    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        if profile != self.writer_profile(profile.name):
            raise ValueError("writer profile does not match the bridge declaration")
        self._write(table, path, profile.name)

    def _write(self, table: pa.Table, path: Path, profile: str | None) -> None:
        with tempfile.TemporaryDirectory(prefix="parquity-bridge-") as directory:
            source = Path(directory) / ARTIFACT_NAME
            _write_ipc(table, source)
            arguments = ["--arrow", str(source), "--parquet", str(path)]
            if profile is not None:
                arguments.extend(("--profile", profile))
            self._invoke("write", arguments)
        if not path.is_file():
            raise ExternalEngineProtocolError(
                f"{self.identity.name} reported success without writing a Parquet file: {path}"
            )

    def _invoke(self, operation: str, arguments: Sequence[str]) -> None:
        try:
            outcome = run_bridge(
                self.spec.command, (operation, *arguments), self.spec.timeout_seconds
            )
        except BridgeUnavailableError as error:
            raise ExternalEngineProtocolError(str(error)) from error
        if outcome.timed_out:
            raise self._failure(
                operation,
                TIMEOUT_KIND,
                f"{operation} exceeded {self.spec.timeout_seconds} seconds",
                outcome.stderr,
            )
        if outcome.exit_code == 0:
            parse_success(outcome.stdout)
            return
        failure = parse_failure(outcome.stdout)
        if outcome.exit_code == 2:
            reported = "" if failure is None else f": {failure.detail}"
            raise ExternalEngineProtocolError(
                diagnostic(f"bridge rejected the {operation} request{reported}", outcome.stderr)
            )
        if outcome.exit_code == 1 and failure is not None:
            raise self._failure(operation, failure.kind, failure.detail, outcome.stderr)
        raise self._failure(
            operation,
            CRASH_KIND,
            f"bridge exited {outcome.exit_code} without a well-formed response",
            outcome.stderr,
        )

    def _failure(
        self, operation: str, kind: str, detail: str, stderr: str
    ) -> ProviderOperationError:
        cause = ExternalEngineFailure(diagnostic(detail, stderr))
        return ProviderOperationError(self.identity.name, operation, cause, provider_type=kind)


def _read_ipc(path: Path, engine: str) -> pa.Table:
    try:
        with pa.OSFile(str(path), "rb") as source:
            return pa.ipc.open_file(source).read_all()
    except (pa.ArrowException, OSError) as error:
        raise ExternalEngineProtocolError(
            f"{engine} produced an Arrow IPC file that could not be read"
        ) from error


def _write_ipc(table: pa.Table, path: Path) -> None:
    with (
        pa.OSFile(str(path), "wb") as sink,
        pa.ipc.new_file(sink, table.schema) as writer,
    ):
        writer.write_table(table)


def create_engine(spec: ExternalEngineSpec, info: BridgeInfo) -> ExternalEngine:
    return ExternalEngine(EngineIdentity(spec.name, info.version), spec, info)


__all__ = ["ARTIFACT_NAME", "ExternalEngine", "ExternalEngineFailure", "create_engine"]
