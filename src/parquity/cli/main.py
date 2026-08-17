from __future__ import annotations

import sys
from collections.abc import Sequence
from importlib import metadata
from pathlib import Path
from shlex import join as shell_join

from ..engines import (
    PYTHON_SUPPORT,
    EngineSelectionError,
    ExternalEngineConfigurationError,
    ExternalEngineProtocolError,
    ReaderSelection,
    discover_engines,
    resolve_engine_selection,
    resolve_engines,
    resolve_reader_selection,
)
from ..profiles.contracts import WriterProfileContractViolation
from . import output as _output
from . import parser
from .output import configuration as _configuration
from .output import emit as _emit
from .output import failure as _failure
from .output import unavailable as _unavailable
from .progress import fuzz_label

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
        command_line = shell_join(("parquity", *raw_arguments))
        return _dispatch(command, arguments, command_line)
    except parser.UsageError as error:
        return _configuration("usage", "USAGE_ERROR", str(error))
    except ExternalEngineConfigurationError as error:
        name = "parquity" if command is None else command.value
        return _configuration(name, "EXTERNAL_ENGINE_CONFIGURATION_ERROR", str(error))
    except ExternalEngineProtocolError as error:
        # A bridge broke its contract. Report it instead of filing evidence that
        # would name the wrong cause.
        name = "parquity" if command is None else command.value
        detail = str(error)
        _emit(
            {
                "command": name,
                "status": "INTERNAL_ERROR",
                "error": {"kind": "EXTERNAL_ENGINE_PROTOCOL_ERROR", "detail": detail},
            }
        )
        _failure(detail)
        return 3
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


def _dispatch(command: parser.Command, arguments: object, command_line: str) -> int:
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
                "engines": [_output.availability_data(item) for item in discover_engines()],
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
            return run_check(arguments, resolve_engine_selection, command_line=command_line)
    if command is parser.Command.FUZZ and isinstance(arguments, parser.FuzzArguments):
        return _run_fuzz(arguments, command_line)
    if command is parser.Command.SCAN and isinstance(arguments, parser.ScanArguments):
        return _run_scan(arguments, command_line)
    if command is parser.Command.REPLAY and isinstance(arguments, Path):
        with _output.progress("Replaying evidence"):
            return _route_replay(arguments)
    raise TypeError("parsed command arguments are inconsistent")


def _route_replay(directory: Path) -> int:
    from ..evidence.target import EvidenceTarget, EvidenceTargetError, classify_evidence_target

    try:
        target = classify_evidence_target(directory)
    except EvidenceTargetError as error:
        detail = _replay_target_detail(directory, error.reason, error.error)
        return _configuration("replay", "INVALID_BUNDLE", detail)
    if target is EvidenceTarget.SCAN_RUN:
        return _run_scan_replay(directory, aggregate=True)
    if target is EvidenceTarget.GENERATED_RUN:
        from .generated import run_replay

        return run_replay(directory, resolve_engine_selection, aggregate=True)
    finding_format = _standalone_finding_format(directory)
    if isinstance(finding_format, int):
        return finding_format
    from ..findings import FINDING_FORMAT
    from ..scans.records import SCAN_FINDING_FORMATS

    if finding_format == FINDING_FORMAT:
        from .generated import run_replay

        return run_replay(directory, resolve_engine_selection, aggregate=False)
    if finding_format in SCAN_FINDING_FORMATS:
        return _run_scan_replay(directory, aggregate=False)
    return _configuration(
        "replay", "INVALID_BUNDLE", f"finding format is not supported: {finding_format!r}"
    )


def _standalone_finding_format(directory: Path) -> str | int:
    from ..evidence import json_codec as codec

    try:
        payload = (directory / "finding.json").read_bytes()
        document = codec.mapping(codec.decode(payload), "finding manifest")
        return codec.string(codec.required(document, "format"), "finding format")
    except OSError:
        return _configuration("replay", "INVALID_BUNDLE", "finding.json could not be read")
    except (TypeError, ValueError):
        return _configuration("replay", "INVALID_BUNDLE", "finding.json is malformed")


def _replay_target_detail(directory: Path, reason: str, error: OSError | None) -> str:
    if reason == "missing":
        return f"replay input path does not exist: {directory}"
    if reason == "not_directory":
        return f"replay input must be an evidence directory: {directory}"
    if reason == "unrecognized":
        return (
            f"replay input directory contains no run.json, scan.json, or finding.json: {directory}"
        )
    if reason == "conflicting_runs":
        return "replay input directory contains conflicting run.json and scan.json manifests"
    return f"replay input could not be inspected: {error}"


def _run_fuzz(arguments: parser.FuzzArguments, command_line: str) -> int:
    from ..generation.schema import SchemaProfileError, load_schema

    try:
        schema = None if arguments.schema is None else load_schema(arguments.schema)
    except SchemaProfileError as error:
        return _configuration("fuzz", error.kind, error.detail)
    from .generated import run_fuzz

    with _output.progress("Starting fuzz campaign") as update:
        return run_fuzz(
            arguments,
            schema,
            resolve_engine_selection,
            lambda value: update(fuzz_label(value)),
            command_line=command_line,
        )


def _run_scan(arguments: parser.ScanArguments, command_line: str) -> int:
    from ..scans.discovery import ScanConfigurationError
    from ..scans.report import build_clean_run_report_view, build_run_report_view
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
                max_saved=arguments.max_saved,
                report_command=command_line,
            )
    except ScanConfigurationError as error:
        return _configuration("scan", error.kind, error.detail)
    view = (
        build_clean_run_report_view(
            result,
            timeout_seconds=arguments.timeout,
            max_saved=arguments.max_saved,
            command_line=command_line,
        )
        if result.run is None
        else build_run_report_view(result.run, command_line=command_line)
    )
    payload: dict[str, object] = {
        "command": "scan",
        "status": "AGREEMENT",
        "readers": list(selection.reader_names),
        "discovered_files": len(result.discovery.files),
        "evaluated_files": result.evaluated_files,
        "skipped_symlinks": result.discovery.skipped_symlinks,
        "visited_entries": result.discovery.visited_entries,
        "report_finding_count": view.finding_count,
        "occurrence_count": view.occurrence_count,
        "evidence_bundle_count": view.evidence_bundle_count,
        "affected_input_count": view.affected_input_count,
    }
    if result.run is not None:
        from ..scans import records

        record = result.run.record.data
        payload.update(
            status="RUN_PUBLISHED",
            run_status=records.status_to_v1(
                records.status_from_data(
                    records.text(record, "status"), records.text(record, "format")
                )
            ),
            scan_id=record["scan_id"],
            finding_count=len(result.run.children),
            overflow_count=len(result.discovery.files) - result.evaluated_files,
            output=str(arguments.destination),
        )
    _emit(payload, view)
    return int(result.run is not None)


def _run_scan_replay(directory: Path, *, aggregate: bool) -> int:
    from ..scans import replay as scan_replay
    from ..scans.bundle import (
        ScanBundleError,
        ValidatedScanRun,
        validate_finding,
        validate_run,
    )
    from ..scans.report import (
        build_replay_overlay,
        build_run_report_view,
        build_standalone_report_view,
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

    try:
        if isinstance(target, ValidatedScanRun):
            replayed = scan_replay.replay_run(target, selection)
            outcomes = replayed.results
            status = replayed.classification
            exact = replayed.has_exact_reproduction
        else:
            finding_outcome = scan_replay.replay_finding(target, selection)
            outcomes = (finding_outcome,)
            status = finding_outcome.classification
            exact = finding_outcome.has_exact_reproduction
    except ScanConfigurationError as error:
        return _configuration("replay", error.kind, error.detail)
    payload: dict[str, object] = {
        "command": "replay",
        "status": status.value,
        "results": [_scan_replay_data(item) for item in outcomes],
    }
    payload["scan_id" if aggregate else "finding_id"] = (
        target.record.data["scan_id"] if isinstance(target, ValidatedScanRun) else record.finding_id
    )
    overlay = build_replay_overlay(outcomes)
    view = (
        build_run_report_view(target, overlay)
        if isinstance(target, ValidatedScanRun)
        else build_standalone_report_view(target, overlay)
    )
    _emit(payload, view)
    return int(exact)


def _scan_replay_data(outcome: object) -> dict[str, object]:
    from ..scans.replay import ScanFindingReplayOutcome

    if not isinstance(outcome, ScanFindingReplayOutcome):
        raise TypeError("scan replay returned an unexpected outcome")
    return {
        "finding_id": outcome.finding_id,
        "classification": outcome.classification.value,
        "package_version": dict(outcome.package_version),
        "version_evidence": [dict(item) for item in outcome.version_evidence],
        "occurrence_results": [dict(item) for item in outcome.occurrence_results],
        "new_observations": [dict(item) for item in outcome.new_observations],
    }


def _reader_selection(command: str, readers: str | Sequence[str] | None) -> ReaderSelection | int:
    try:
        return resolve_reader_selection(readers)
    except EngineSelectionError as error:
        if error.unavailable:
            return _unavailable(command, error.unavailable)
        return _configuration(command, error.kind, error.detail)
