from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib import import_module
from pathlib import Path
from typing import cast


class Command(StrEnum):
    CHECK = "check"
    ENGINES = "engines"
    FUZZ = "fuzz"
    HELP = "help"
    REPLAY = "replay"
    SCAN = "scan"
    SMOKE = "smoke"
    TRIAGE = "triage"
    VERSION = "version"


class UsageError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CheckArguments:
    case_path: Path
    destination: Path
    writers: str | None
    readers: str | None
    writer_profiles: str | None


@dataclass(frozen=True, slots=True)
class FuzzArguments:
    schema: Path | None
    destination: Path
    examples: int
    seed: int
    max_findings: int
    writers: str | None
    readers: str | None
    writer_profiles: str | None


@dataclass(frozen=True, slots=True)
class ScanArguments:
    source: Path
    destination: Path
    engines: str | None
    timeout: int
    max_findings: int


@dataclass(frozen=True, slots=True)
class TriageArguments:
    directory: Path
    focus: str
    replay_evidence: Path | None


@dataclass(frozen=True, slots=True)
class HelpArguments:
    command: str | None


ParsedArguments = (
    CheckArguments | FuzzArguments | HelpArguments | ScanArguments | TriageArguments | Path | None
)

_HELP_COMMANDS = ("engines", "smoke", "check", "fuzz", "scan", "replay", "triage")


def extract_json_flag(arguments: tuple[str, ...]) -> tuple[bool, tuple[str, ...]]:
    count = arguments.count("--json")
    if count > 1:
        raise UsageError("--json appears more than once")
    return count == 1, tuple(value for value in arguments if value != "--json")


def parse(arguments: tuple[str, ...]) -> tuple[Command, ParsedArguments]:
    simple: dict[tuple[str, ...], Command] = {
        ("--version",): Command.VERSION,
        ("engines",): Command.ENGINES,
        ("smoke",): Command.SMOKE,
    }
    if arguments in (("--help",), ("-h",)):
        return Command.HELP, HelpArguments(None)
    if len(arguments) == 2 and arguments[1] in ("--help", "-h") and arguments[0] in _HELP_COMMANDS:
        return Command.HELP, HelpArguments(arguments[0])
    if command := simple.get(arguments):
        return command, None
    if arguments[:1] == ("check",):
        return Command.CHECK, _check_arguments(arguments)
    if arguments[:1] == ("fuzz",):
        return Command.FUZZ, _fuzz_arguments(arguments)
    if arguments[:1] == ("scan",):
        return Command.SCAN, _scan_arguments(arguments)
    if arguments[:1] == ("triage",):
        return Command.TRIAGE, _triage_arguments(arguments)
    if len(arguments) == 2 and arguments[0] == "replay":
        return Command.REPLAY, Path(arguments[1])
    raise UsageError("invalid arguments; run 'parquity --help'")


def _check_arguments(arguments: tuple[str, ...]) -> CheckArguments:
    if len(arguments) < 4:
        raise UsageError("check requires CASE_FILE and --out OUTPUT_DIR")
    options = _options(
        arguments[2:],
        allowed=("--out", "--writers", "--readers", "--writer-profiles"),
        required=("--out",),
        command="check",
    )
    return CheckArguments(
        Path(arguments[1]),
        Path(options["--out"]),
        options.get("--writers"),
        options.get("--readers"),
        options.get("--writer-profiles"),
    )


def _fuzz_arguments(arguments: tuple[str, ...]) -> FuzzArguments:
    bounds = import_module("parquity.generation")
    default_max_findings = cast(int, vars(bounds)["DEFAULT_MAX_FINDINGS"])
    max_findings_limit = cast(int, vars(bounds)["MAX_FINDINGS"])
    max_seed = cast(int, vars(bounds)["MAX_SEED"])

    options = _options(
        arguments[1:],
        allowed=(
            "--examples",
            "--seed",
            "--schema",
            "--out",
            "--max-findings",
            "--writers",
            "--readers",
            "--writer-profiles",
        ),
        required=("--examples", "--seed", "--out"),
        command="fuzz",
    )
    examples = _integer(options["--examples"], "--examples")
    seed = _integer(options["--seed"], "--seed")
    max_findings = _integer(
        options.get("--max-findings", str(default_max_findings)), "--max-findings"
    )
    if examples < 1:
        raise UsageError("--examples must be positive")
    if not 0 <= seed <= max_seed:
        raise UsageError(f"--seed must be in [0, {max_seed}]")
    if not 1 <= max_findings <= max_findings_limit:
        raise UsageError(f"--max-findings must be in [1, {max_findings_limit}]")
    return FuzzArguments(
        None if "--schema" not in options else Path(options["--schema"]),
        Path(options["--out"]),
        examples,
        seed,
        max_findings,
        options.get("--writers"),
        options.get("--readers"),
        options.get("--writer-profiles"),
    )


def _scan_arguments(arguments: tuple[str, ...]) -> ScanArguments:
    if len(arguments) < 4:
        raise UsageError("scan requires FILE_OR_DIR and --out")
    options = _options(
        arguments[2:],
        allowed=("--engines", "--timeout", "--max-findings", "--out"),
        required=("--out",),
        command="scan",
    )
    timeout = _integer(options.get("--timeout", "30"), "--timeout")
    max_findings = _integer(options.get("--max-findings", "32"), "--max-findings")
    if not 1 <= timeout <= 300:
        raise UsageError("--timeout must be in [1, 300]")
    if not 1 <= max_findings <= 64:
        raise UsageError("--max-findings must be in [1, 64]")
    return ScanArguments(
        Path(arguments[1]),
        Path(options["--out"]),
        options.get("--engines"),
        timeout,
        max_findings,
    )


def _triage_arguments(arguments: tuple[str, ...]) -> TriageArguments:
    if len(arguments) < 2:
        raise UsageError("triage requires RUN_DIR")
    options = _options(
        arguments[2:],
        allowed=("--focus", "--replay-evidence"),
        required=(),
        command="triage",
    )
    focus = options.get("--focus", "all")
    if focus not in ("all", "execution", "data", "schema"):
        raise UsageError("--focus must be all, execution, data, or schema")
    replay = options.get("--replay-evidence")
    return TriageArguments(Path(arguments[1]), focus, None if replay is None else Path(replay))


def _options(
    arguments: tuple[str, ...],
    *,
    allowed: tuple[str, ...],
    required: tuple[str, ...],
    command: str,
) -> dict[str, str]:
    if len(arguments) % 2:
        raise UsageError(f"{command} options require a value")
    options: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        name, value = arguments[index : index + 2]
        if name not in allowed:
            raise UsageError(f"unknown {command} option: {name}")
        if name in options:
            raise UsageError(f"{command} option appears more than once: {name}")
        options[name] = value
    missing = [name for name in required if name not in options]
    if missing:
        raise UsageError(f"{command} requires {', '.join(missing)}")
    return options


def _integer(value: str, name: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise UsageError(f"{name} must be an integer") from error
