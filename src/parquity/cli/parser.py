from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..configuration import (
    fuzz_examples_is_valid,
    fuzz_saved_limit_is_valid,
    fuzz_seed_is_valid,
)
from .spec import (
    CHECK,
    ENGINES,
    EXAMPLES,
    FUZZ,
    FUZZ_MAX_SAVED,
    HELP_COMMANDS,
    HELP_FLAGS,
    JSON,
    OUT,
    READERS,
    SCAN,
    SCAN_MAX_SAVED,
    SCAN_TIMEOUT,
    SCHEMA,
    SEED,
    VERSION_FLAG,
    WRITER_PROFILES,
    WRITERS,
    Command,
    OptionSpec,
)


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
    max_saved: int
    writers: str | None
    readers: str | None
    writer_profiles: str | None


@dataclass(frozen=True, slots=True)
class ScanArguments:
    source: Path
    destination: Path
    engines: str | None
    timeout: int
    max_saved: int


@dataclass(frozen=True, slots=True)
class HelpArguments:
    command: str | None


ParsedArguments = CheckArguments | FuzzArguments | HelpArguments | ScanArguments | Path | None


def extract_json_flag(arguments: tuple[str, ...]) -> tuple[bool, tuple[str, ...]]:
    count = arguments.count(JSON.name)
    if count > 1:
        raise UsageError(f"{JSON.name} appears more than once")
    return count == 1, tuple(value for value in arguments if value != JSON.name)


def parse(arguments: tuple[str, ...]) -> tuple[Command, ParsedArguments]:
    simple: dict[tuple[str, ...], Command] = {
        (VERSION_FLAG,): Command.VERSION,
        (Command.ENGINES.value,): Command.ENGINES,
        (Command.SMOKE.value,): Command.SMOKE,
    }
    if arguments in tuple((flag,) for flag in HELP_FLAGS):
        return Command.HELP, HelpArguments(None)
    if len(arguments) == 2 and arguments[1] in HELP_FLAGS and arguments[0] in HELP_COMMANDS:
        return Command.HELP, HelpArguments(arguments[0])
    if command := simple.get(arguments):
        return command, None
    if arguments[:1] == (Command.CHECK.value,):
        return Command.CHECK, _check_arguments(arguments)
    if arguments[:1] == (Command.FUZZ.value,):
        return Command.FUZZ, _fuzz_arguments(arguments)
    if arguments[:1] == (Command.SCAN.value,):
        return Command.SCAN, _scan_arguments(arguments)
    if len(arguments) == 2 and arguments[0] == Command.REPLAY.value:
        return Command.REPLAY, Path(arguments[1])
    raise UsageError("invalid arguments; run 'parquity --help'")


def _check_arguments(arguments: tuple[str, ...]) -> CheckArguments:
    if len(arguments) < 4:
        raise UsageError("check requires CASE_FILE and --out OUTPUT_DIR")
    options = _options(
        arguments[2:],
        allowed=CHECK.option_names,
        required=CHECK.required_names,
        command="check",
    )
    return CheckArguments(
        Path(arguments[1]),
        Path(options[OUT.name]),
        options.get(WRITERS.name),
        options.get(READERS.name),
        options.get(WRITER_PROFILES.name),
    )


def _fuzz_arguments(arguments: tuple[str, ...]) -> FuzzArguments:
    options = _options(
        arguments[1:],
        allowed=FUZZ.option_names,
        required=FUZZ.required_names,
        command="fuzz",
    )
    examples = _integer(options[EXAMPLES.name], EXAMPLES.name)
    seed = _integer(options[SEED.name], SEED.name)
    max_saved = _integer(
        options.get(FUZZ_MAX_SAVED.name, _default(FUZZ_MAX_SAVED)),
        FUZZ_MAX_SAVED.name,
    )
    if not fuzz_examples_is_valid(examples):
        raise UsageError("--examples must be positive")
    if not fuzz_seed_is_valid(seed):
        raise UsageError(f"--seed must be in [{SEED.minimum}, {SEED.maximum}]")
    if not fuzz_saved_limit_is_valid(max_saved):
        raise UsageError(
            f"--max-saved must be in [{FUZZ_MAX_SAVED.minimum}, {FUZZ_MAX_SAVED.maximum}]"
        )
    return FuzzArguments(
        None if SCHEMA.name not in options else Path(options[SCHEMA.name]),
        Path(options[OUT.name]),
        examples,
        seed,
        max_saved,
        options.get(WRITERS.name),
        options.get(READERS.name),
        options.get(WRITER_PROFILES.name),
    )


def _scan_arguments(arguments: tuple[str, ...]) -> ScanArguments:
    if len(arguments) < 4:
        raise UsageError("scan requires FILE_OR_DIR and --out")
    options = _options(
        arguments[2:],
        allowed=SCAN.option_names,
        required=SCAN.required_names,
        command="scan",
    )
    timeout = _integer(options.get(SCAN_TIMEOUT.name, _default(SCAN_TIMEOUT)), SCAN_TIMEOUT.name)
    max_saved = _integer(
        options.get(SCAN_MAX_SAVED.name, _default(SCAN_MAX_SAVED)),
        SCAN_MAX_SAVED.name,
    )
    if not _within(timeout, SCAN_TIMEOUT):
        raise UsageError(f"--timeout must be in [{SCAN_TIMEOUT.minimum}, {SCAN_TIMEOUT.maximum}]")
    if not _within(max_saved, SCAN_MAX_SAVED):
        raise UsageError(
            f"--max-saved must be in [{SCAN_MAX_SAVED.minimum}, {SCAN_MAX_SAVED.maximum}]"
        )
    return ScanArguments(
        Path(arguments[1]),
        Path(options[OUT.name]),
        options.get(ENGINES.name),
        timeout,
        max_saved,
    )


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


def _default(option: OptionSpec) -> str:
    if option.default is None:
        raise TypeError("CLI option has no default")
    return option.default


def _within(value: int, option: OptionSpec) -> bool:
    return option.accepts(value)
