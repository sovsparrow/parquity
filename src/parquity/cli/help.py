from __future__ import annotations

import re
import sys

from .parser import HelpArguments
from .spec import (
    COMMAND_SPECS,
    ENGINES,
    EXAMPLES,
    FUZZ_MAX_SAVED,
    HELP_FLAGS,
    JSON,
    NO_WRITER_PROFILES,
    OUT,
    READERS,
    SCAN_MAX_SAVED,
    SCAN_TIMEOUT,
    SCHEMA,
    SEED,
    VERSION_FLAG,
    WRITER_PROFILES,
    WRITERS,
    Command,
)
from .style import Style, controls_enabled

_COMMAND_DESCRIPTIONS = {
    Command.ENGINES: "Report installed Parquet engines and their capabilities.",
    Command.SMOKE: "Run the built-in compatibility case across the core engines.",
    Command.CHECK: "Check a known table against selected writers and readers.",
    Command.FUZZ: "Search generated tables for engine disagreements.",
    Command.SCAN: "Compare reader observations of existing Parquet files.",
    Command.REPLAY: "Re-evaluate a saved reproducer or run.",
}
_COMMAND_LINES = "\n".join(
    f"  {spec.command.value:<8} {_COMMAND_DESCRIPTIONS[spec.command]}" for spec in COMMAND_SPECS
)
_TOP_LEVEL = f"""Usage: parquity COMMAND [OPTIONS] [{JSON.name}]
       parquity {HELP_FLAGS[0]} | {HELP_FLAGS[1]} | {VERSION_FLAG} [{JSON.name}]

Commands:
{_COMMAND_LINES}

Options:
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}  Show this help and exit.
  {JSON.name}      Force canonical JSON output, including on a terminal.
  {VERSION_FLAG}   Show the installed Parquity version and exit.

Run 'parquity COMMAND {HELP_FLAGS[0]}' for command-specific help.
"""

_SECTION = re.compile(r"^(Usage|Commands|Operands|Required options|Options|Examples|Exit status):")
_ENTRY = re.compile(r"^(  )(\S(?:.*?\S)?)( {2,})(\S.*)$")
_OPTION_ENTRY = re.compile(r"^  (--[a-z-]+)(?:\s|,)")

_EXIT_GENERAL = """Exit status:
  0  The command completed without a failure.
  1  At least one failure was recorded.
  2  Usage, input, provider, resource, output, or evidence validation failed.
  3  An unexpected internal failure prevented a valid result.
"""

_HELP = {
    Command.ENGINES.value: f"""Usage: parquity engines [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Report installed Parquet engines, versions, capabilities, and Python support.

Options:
  {JSON.name}      Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}  Show this help and exit.

Exit status:
  0  Engine information was reported.
  1  Not used by this command.
  2  Not used by this command.
  3  An unexpected internal failure prevented a valid result.
""",
    Command.SMOKE.value: f"""Usage: parquity smoke [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Run the built-in compatibility case across the core writers and readers.

Options:
  {JSON.name}      Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}  Show this help and exit.

Exit status:
  0  Every smoke-test cell passed.
  1  A smoke-test disagreement was observed.
  2  A required core provider was unavailable.
  3  An unexpected internal failure prevented a valid result.
""",
    Command.CHECK.value: f"""Usage: parquity check CASE_FILE {OUT.name} OUTPUT_DIR [{WRITERS.name} NAMES] [{READERS.name} NAMES]
       [{WRITER_PROFILES.name} NAMES] [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Check a known table against selected Parquet writers and readers.

Operands:
  CASE_FILE              Path to a JSON table description with expected schema and rows.

Required options:
  {OUT.name} OUTPUT_DIR       Destination for check results and reproducers.

Options:
  {WRITERS.name} NAMES        Comma-separated writer engine names
                         (default: {WRITERS.default}).
  {READERS.name} NAMES        Comma-separated reader engine names
                         (default: {READERS.default}).
  {WRITER_PROFILES.name} NAMES
                         Comma-separated writer profile names (default: {NO_WRITER_PROFILES}).
  {JSON.name}                 Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}             Show this help and exit.

Examples:
  parquity check ./case.json {OUT.name} ./check-run

"""
    + _EXIT_GENERAL,
    Command.FUZZ.value: f"""Usage: parquity fuzz {EXAMPLES.name} N {SEED.name} N {OUT.name} OUTPUT_DIR [{SCHEMA.name} CASE_FILE]
       [{FUZZ_MAX_SAVED.name} N] [{WRITERS.name} NAMES] [{READERS.name} NAMES]
       [{WRITER_PROFILES.name} NAMES] [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Search generated tables for semantic disagreements between Parquet engines.

Required options:
  {EXAMPLES.name} N           Maximum number of discovery examples.
  {SEED.name} N               Seed in [{SEED.minimum}, {SEED.maximum}].
  {OUT.name} OUTPUT_DIR       Destination for fuzz results and reproducers.

Options:
  {SCHEMA.name} CASE_FILE     Generate rows under Case grammar with `rows: []`;
                         omit to generate both schema and rows.
  {FUZZ_MAX_SAVED.name} N          Save {FUZZ_MAX_SAVED.minimum} to {FUZZ_MAX_SAVED.maximum} reproducers
                         (default: {FUZZ_MAX_SAVED.default}).
  {WRITERS.name} NAMES        Comma-separated writer engine names
                         (default: {WRITERS.default}).
  {READERS.name} NAMES        Comma-separated reader engine names
                         (default: {READERS.default}).
  {WRITER_PROFILES.name} NAMES
                         Comma-separated writer profile names (default: {NO_WRITER_PROFILES}).
  {JSON.name}                 Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}             Show this help and exit.

Equivalent generated failures share one reproducer. The selected exact failure
remains the minimization and replay input. Discovery stops after finding a
distinct failure beyond the {FUZZ_MAX_SAVED.name} limit, or after the requested
examples are evaluated. Each reproducer includes the exact table and result.

The schema file is a parquity.case.v1 Case whose rows array must be empty.

"""
    + _EXIT_GENERAL,
    Command.SCAN.value: f"""Usage: parquity scan FILE_OR_DIR {OUT.name} OUTPUT_DIR [{ENGINES.name} NAMES]
       [{SCAN_TIMEOUT.name} SECONDS] [{SCAN_MAX_SAVED.name} N] [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Compare independent reader observations of existing Parquet files.

Operands:
  FILE_OR_DIR            Parquet file or directory to scan.

Required options:
  {OUT.name} OUTPUT_DIR       Destination for scan results and reproducers.

Options:
  {ENGINES.name} NAMES        Comma-separated reader engine names
                         (default: {ENGINES.default}).
  {SCAN_TIMEOUT.name} SECONDS      Per reader-file timeout in [{SCAN_TIMEOUT.minimum}, {SCAN_TIMEOUT.maximum}] (default: {SCAN_TIMEOUT.default}).
  {SCAN_MAX_SAVED.name} N          Save evidence for {SCAN_MAX_SAVED.minimum} to {SCAN_MAX_SAVED.maximum} source files (default: {SCAN_MAX_SAVED.default}).
  {JSON.name}                 Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}             Show this help and exit.

"""
    + _EXIT_GENERAL,
    Command.REPLAY.value: f"""Usage: parquity replay RUN_DIR [{JSON.name}] [{HELP_FLAGS[0]} | {HELP_FLAGS[1]}]

Re-evaluate a saved reproducer or run against its recorded failure.

Operands:
  RUN_DIR     Saved reproducer or run directory.

Options:
  {JSON.name}      Force canonical JSON output.
  {HELP_FLAGS[0]}, {HELP_FLAGS[1]}  Show this help and exit.

Exit status:
  0  No recorded target reproduced exactly.
  1  At least one recorded target reproduced exactly.
  2  Provider, run, or recorded evidence validation failed.
  3  An unexpected internal failure prevented a valid result.
""",
}


def _section_options(document: str, heading: str) -> set[str]:
    marker = f"\n{heading}:\n"
    if marker not in document:
        return set()
    body = document.split(marker, 1)[1].split("\n\n", 1)[0]
    return {
        matched.group(1)
        for line in body.splitlines()
        if (matched := _OPTION_ENTRY.match(line)) is not None
    }


def _validate_help_inventory() -> None:
    for spec in COMMAND_SPECS:
        document = _HELP[spec.command.value]
        required = set(spec.required_names)
        optional = set(spec.option_names) - required
        optional.update((JSON.name, HELP_FLAGS[0]))
        if _section_options(document, "Required options") != required:
            raise RuntimeError(f"{spec.command.value} help required options conflict with spec")
        if _section_options(document, "Options") != optional:
            raise RuntimeError(f"{spec.command.value} help options conflict with spec")


_validate_help_inventory()


def _banner(style: Style) -> str:
    return (
        f"  {style.bold('╭────╮')}\n"
        f"  {style.bold('│    │')}   {style.bold('parquity')}\n"
        f"  {style.bold('╰────┤')}   Find and reproduce semantic disagreements\n"
        f"       {style.bold('│')}{style.accent('╲')}  between Parquet engines.\n"
        f"       {style.bold('│')} {style.accent('╲')}\n\n"
    )


def _colorize(document: str, style: Style) -> str:
    rendered: list[str] = []
    for line in document.splitlines(keepends=True):
        content = line.removesuffix("\n")
        ending = "\n" if line.endswith("\n") else ""
        if section := _SECTION.match(content):
            label = section.group(0)
            content = f"{style.bold(label)}{content[len(label) :]}"
        elif entry := _ENTRY.match(content):
            content = (
                f"{entry.group(1)}{style.accent(entry.group(2))}{entry.group(3)}{entry.group(4)}"
            )
        elif content.startswith("  --"):
            content = f"  {style.accent(content[2:])}"
        rendered.append(content + ending)
    return "".join(rendered)


def render(arguments: HelpArguments) -> None:
    style = Style(controls_enabled(sys.stdout))
    document = _TOP_LEVEL if arguments.command is None else _HELP[arguments.command]
    output = _colorize(document, style) if style.controls else document
    if arguments.command is None:
        output = _banner(style) + output
    print(output, end="")


__all__ = ["render"]
