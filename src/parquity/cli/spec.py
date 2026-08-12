from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..configuration import (
    DEFAULT_FUZZ_SAVED_LIMIT,
    DEFAULT_SCAN_SAVED_LIMIT,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    MAX_FUZZ_SAVED_LIMIT,
    MAX_FUZZ_SEED,
    MAX_SCAN_SAVED_LIMIT,
    MAX_SCAN_TIMEOUT_SECONDS,
    MIN_FUZZ_EXAMPLES,
    MIN_FUZZ_SAVED_LIMIT,
    MIN_FUZZ_SEED,
    MIN_SCAN_SAVED_LIMIT,
    MIN_SCAN_TIMEOUT_SECONDS,
)
from ..engines import default_engine_names


class Command(StrEnum):
    CHECK = "check"
    ENGINES = "engines"
    FUZZ = "fuzz"
    HELP = "help"
    REPLAY = "replay"
    SCAN = "scan"
    SMOKE = "smoke"
    VERSION = "version"


@dataclass(frozen=True, slots=True)
class OptionSpec:
    name: str
    default: str | None = None
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()

    def accepts(self, value: int) -> bool:
        return (self.minimum is None or self.minimum <= value) and (
            self.maximum is None or value <= self.maximum
        )


@dataclass(frozen=True, slots=True)
class CommandSpec:
    command: Command
    options: tuple[OptionSpec, ...] = ()
    required: tuple[OptionSpec, ...] = ()

    @property
    def option_names(self) -> tuple[str, ...]:
        return tuple(option.name for option in self.options)

    @property
    def required_names(self) -> tuple[str, ...]:
        return tuple(option.name for option in self.required)


NO_WRITER_PROFILES = "none"
JSON = OptionSpec("--json")
HELP_FLAGS = ("--help", "-h")
VERSION_FLAG = "--version"

OUT = OptionSpec("--out")
WRITERS = OptionSpec("--writers", ",".join(default_engine_names("writer")))
READERS = OptionSpec("--readers", ",".join(default_engine_names("reader")))
WRITER_PROFILES = OptionSpec("--writer-profiles", NO_WRITER_PROFILES)
EXAMPLES = OptionSpec("--examples", minimum=MIN_FUZZ_EXAMPLES)
SEED = OptionSpec("--seed", minimum=MIN_FUZZ_SEED, maximum=MAX_FUZZ_SEED)
SCHEMA = OptionSpec("--schema")
FUZZ_MAX_SAVED = OptionSpec(
    "--max-saved",
    default=str(DEFAULT_FUZZ_SAVED_LIMIT),
    minimum=MIN_FUZZ_SAVED_LIMIT,
    maximum=MAX_FUZZ_SAVED_LIMIT,
)
ENGINES = OptionSpec("--engines", ",".join(default_engine_names("reader")))
SCAN_TIMEOUT = OptionSpec(
    "--timeout",
    default=str(DEFAULT_SCAN_TIMEOUT_SECONDS),
    minimum=MIN_SCAN_TIMEOUT_SECONDS,
    maximum=MAX_SCAN_TIMEOUT_SECONDS,
)
SCAN_MAX_SAVED = OptionSpec(
    "--max-saved",
    default=str(DEFAULT_SCAN_SAVED_LIMIT),
    minimum=MIN_SCAN_SAVED_LIMIT,
    maximum=MAX_SCAN_SAVED_LIMIT,
)
CHECK = CommandSpec(
    Command.CHECK,
    (OUT, WRITERS, READERS, WRITER_PROFILES),
    (OUT,),
)
FUZZ = CommandSpec(
    Command.FUZZ,
    (EXAMPLES, SEED, SCHEMA, OUT, FUZZ_MAX_SAVED, WRITERS, READERS, WRITER_PROFILES),
    (EXAMPLES, SEED, OUT),
)
SCAN = CommandSpec(Command.SCAN, (ENGINES, SCAN_TIMEOUT, SCAN_MAX_SAVED, OUT), (OUT,))

COMMAND_SPECS = (
    CommandSpec(Command.ENGINES),
    CommandSpec(Command.SMOKE),
    CHECK,
    FUZZ,
    SCAN,
    CommandSpec(Command.REPLAY),
)
HELP_COMMANDS = tuple(spec.command.value for spec in COMMAND_SPECS)


__all__ = [
    "CHECK",
    "COMMAND_SPECS",
    "ENGINES",
    "EXAMPLES",
    "FUZZ",
    "FUZZ_MAX_SAVED",
    "HELP_COMMANDS",
    "HELP_FLAGS",
    "JSON",
    "NO_WRITER_PROFILES",
    "OUT",
    "READERS",
    "SCAN",
    "SCAN_MAX_SAVED",
    "SCAN_TIMEOUT",
    "SCHEMA",
    "SEED",
    "VERSION_FLAG",
    "WRITERS",
    "WRITER_PROFILES",
    "Command",
    "CommandSpec",
    "OptionSpec",
]
