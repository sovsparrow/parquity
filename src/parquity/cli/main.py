from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from importlib import metadata
from pathlib import Path
from typing import cast

from ..engines import (
    PYTHON_SUPPORT,
    EngineSelectionError,
    ReaderSelection,
    discover_engines,
    resolve_engine_selection,
    resolve_engines,
    resolve_reader_selection,
)
from ..writer_profile_contracts import WriterProfileContractViolation
from . import output as _output
from . import parser
from .output import configuration as _configuration
from .output import emit as _emit
from .output import failure as _failure
from .output import unavailable as _unavailable

__all__ = ["main", "resolve_engine_selection"]
parse = parser.parse


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = tuple(sys.argv[1:] if argv is None else argv)
    with _output.output_mode(force_json="--json" in raw_arguments):
        return _main(raw_arguments)


def _main(raw_arguments: tuple[str, ...]) -> int:
    command: parser.Command | None = None
    try:
        _, arguments_without_json = parser.extract_json_flag(raw_arguments)
        command, arguments = parse(arguments_without_json)
        return _dispatch(command, arguments)
    except parser.UsageError as error:
        return _configuration("usage", "USAGE_ERROR", str(error))
    except WriterProfileContractViolation as error:
        name = "parquity" if command is None else command.value
        _emit(
            {
                "command": name,
                "status": "INTERNAL_ERROR",
                "error": {"kind": error.kind, "detail": error.detail},
            }
        )
        _failure(error.detail)
        return 3
    except Exception as error:  # noqa: BLE001 - public CLI boundary maps internal failures.
        name = "parquity" if command is None else command.value
        kind = type(error).__name__
        _emit({"command": name, "status": "INTERNAL_ERROR", "error": {"kind": kind}})
        _failure(kind)
        return 3


def _dispatch(command: parser.Command, arguments: object) -> int:
    if command is parser.Command.HELP and isinstance(arguments, parser.HelpArguments):
        from .help import render

        render(arguments)
        return 0
    if command is parser.Command.VERSION:
        _emit({"command": "version", "status": "OK", "version": metadata.version("parquity")})
        return 0
    if command is parser.Command.ENGINES:
        _emit(
            {
                "command": "engines",
                "status": "OK",
                "engines": [item.to_data() for item in discover_engines()],
                "python_support": PYTHON_SUPPORT,
            }
        )
        return 0
    if command is parser.Command.SMOKE:
        from .smoke import run_smoke

        with _output.progress("Running engine matrix"):
            return run_smoke(resolve_engines)
    if command is parser.Command.CHECK and isinstance(arguments, parser.CheckArguments):
        from .generated import run_check

        with _output.progress("Checking Case"):
            return run_check(arguments, resolve_engine_selection)
    if command is parser.Command.FUZZ and isinstance(arguments, parser.FuzzArguments):
        return _run_fuzz(arguments)
    if command is parser.Command.SCAN and isinstance(arguments, parser.ScanArguments):
        return _run_scan(arguments)
    if command is parser.Command.REPLAY and isinstance(arguments, Path):
        with _output.progress("Replaying evidence"):
            return _route_replay(arguments)
    if command is parser.Command.TRIAGE and isinstance(arguments, parser.TriageArguments):
        with _output.progress("Grouping findings"):
            return _run_triage(arguments)
    raise TypeError("parsed command arguments are inconsistent")


def _route_replay(directory: Path) -> int:
    if (directory / "scan.json").is_file():
        return _run_scan_replay(directory, aggregate=True)
    try:
        finding_data = json.loads((directory / "finding.json").read_bytes())
        scan_format = finding_data.get("format") == "parquity.scan-finding.v1"
    except (AttributeError, OSError, ValueError):
        scan_format = False
    if scan_format:
        return _run_scan_replay(directory, aggregate=False)
    from .generated import run_replay

    return run_replay(directory, resolve_engine_selection)


def _run_fuzz(arguments: parser.FuzzArguments) -> int:
    from ..generation.schema import SchemaProfileError, load_schema

    try:
        schema = None if arguments.schema is None else load_schema(arguments.schema)
    except SchemaProfileError as error:
        return _configuration("fuzz", error.kind, error.detail)
    from .generated import run_fuzz

    with _output.progress("Running fuzz campaign"):
        return run_fuzz(arguments, schema, resolve_engine_selection)


def _run_scan(arguments: parser.ScanArguments) -> int:
    from ..scans.discovery import ScanConfigurationError
    from ..scans.workflow import execute_scan

    selection = _reader_selection("scan", arguments.engines)
    if isinstance(selection, int):
        return selection
    try:
        with _output.progress("Scanning Parquet inputs"):
            result = execute_scan(
                arguments.source,
                arguments.destination,
                selection,
                timeout_seconds=arguments.timeout,
                max_findings=arguments.max_findings,
            )
    except ScanConfigurationError as error:
        return _configuration("scan", error.kind, error.detail)
    payload = {"command": "scan", "readers": list(selection.reader_names), **result.to_data()}
    if result.run is not None:
        payload["output"] = str(arguments.destination)
    _emit(payload)
    return int(result.run is not None)


def _run_triage(arguments: parser.TriageArguments) -> int:
    from ..triage import TriageError, triage_run

    try:
        result = triage_run(arguments.directory, arguments.focus, arguments.replay_evidence)
    except TriageError as error:
        return _configuration("triage", error.kind, error.detail)
    _emit({"command": "triage", "status": "TRIAGED", **result})
    return 0


def _run_scan_replay(directory: Path, *, aggregate: bool) -> int:
    from ..scans.bundle import (
        ScanBundleError,
        ValidatedScanRun,
        validate_finding,
        validate_run,
    )

    try:
        target = validate_run(directory) if aggregate else validate_finding(directory)
    except ScanBundleError as error:
        return _configuration("replay", "INVALID_BUNDLE", str(error))
    record = target.children[0].record if isinstance(target, ValidatedScanRun) else target.record
    names = tuple(item.name for item in record.engines)
    selection = _reader_selection("replay", names)
    if isinstance(selection, int):
        return selection
    if selection.reader_names != names:
        return _configuration("replay", "INVALID_BUNDLE", "recorded engine order is not canonical")
    from ..scans.discovery import ScanConfigurationError
    from ..scans.workflow import replay_finding, replay_run

    try:
        outcomes = (
            replay_run(target, selection)
            if isinstance(target, ValidatedScanRun)
            else (replay_finding(target, selection),)
        )
    except ScanConfigurationError as error:
        return _configuration("replay", error.kind, error.detail)
    classifications = {item["classification"] for item in outcomes}
    status = classifications.pop() if len(classifications) == 1 else "RELATED_FAILURE"
    payload: dict[str, object] = {"command": "replay", "status": status, "results": list(outcomes)}
    payload["scan_id" if aggregate else "finding_id"] = (
        target.record.data["scan_id"] if isinstance(target, ValidatedScanRun) else record.finding_id
    )
    _emit(payload)
    return int(_has_exact_reproduction(outcomes))


def _has_exact_reproduction(outcomes: Sequence[Mapping[str, object]]) -> bool:
    for outcome in outcomes:
        results = cast(Sequence[Mapping[str, object]], outcome["occurrence_results"])
        if any(item.get("classification") == "REPRODUCED" for item in results):
            return True
    return False


def _reader_selection(command: str, readers: str | Sequence[str] | None) -> ReaderSelection | int:
    try:
        return resolve_reader_selection(readers)
    except EngineSelectionError as error:
        if error.unavailable:
            return _unavailable(command, error.unavailable)
        return _configuration(command, error.kind, error.detail)
