from __future__ import annotations

import os
import re
import sys

from .parser import HelpArguments

_TOP_LEVEL = """Usage: parquity COMMAND [OPTIONS] [--json]
       parquity --help | -h | --version [--json]

Commands:
  engines  Report installed Parquet engines and their capabilities.
  smoke    Run the built-in compatibility case across the core engines.
  check    Check a known Case against selected writers and readers.
  fuzz     Search generated Cases for engine disagreements.
  scan     Compare reader observations of existing Parquet files.
  replay   Re-evaluate a saved finding or aggregate run.
  triage   Inspect or filter symptom families in a saved aggregate run.

Options:
  --help, -h  Show this help and exit.
  --json      Force canonical JSON output, including on a terminal.
  --version   Show the installed Parquity version and exit.

Run 'parquity COMMAND --help' for command-specific help.
"""

_SECTION = re.compile(r"^(Usage|Commands|Operands|Required options|Options|Examples|Exit status):")
_ENTRY = re.compile(r"^(  )(\S(?:.*?\S)?)( {2,})(\S.*)$")
_BOLD = "\x1b[1m"
_ACCENT = "\x1b[38;2;220;113;84m"
_RESET = "\x1b[0m"

_EXIT_GENERAL = """Exit status:
  0  The command completed without a finding.
  1  A finding was observed.
  2  Usage, input, provider, resource, output, or evidence validation failed.
  3  An unexpected internal failure prevented a valid result.
"""

_HELP = {
    "engines": """Usage: parquity engines [--json] [--help | -h]

Report installed Parquet engines, versions, capabilities, and Python support.

Options:
  --json      Force canonical JSON output.
  --help, -h  Show this help and exit.

Exit status:
  0  Engine information was reported.
  1  Not used by this command.
  2  Not used by this command.
  3  An unexpected internal failure prevented a valid result.
""",
    "smoke": """Usage: parquity smoke [--json] [--help | -h]

Run the built-in compatibility case across the core writers and readers.

Options:
  --json      Force canonical JSON output.
  --help, -h  Show this help and exit.

Exit status:
  0  Every smoke-test cell passed.
  1  A smoke-test disagreement was observed.
  2  A required core provider was unavailable.
  3  An unexpected internal failure prevented a valid result.
""",
    "check": """Usage: parquity check CASE_FILE --out OUTPUT_DIR [--writers NAMES] [--readers NAMES]
       [--writer-profiles NAMES] [--json] [--help | -h]

Check a known Case against selected Parquet writers and readers.

Operands:
  CASE_FILE              Path to a Case file containing the expected schema and rows.

Required options:
  --out OUTPUT_DIR       Destination for a published finding run.

Options:
  --writers NAMES        Comma-separated writer engine names
                         (default: pyarrow,duckdb,polars).
  --readers NAMES        Comma-separated reader engine names
                         (default: pyarrow,duckdb,polars).
  --writer-profiles NAMES
                         Comma-separated writer profile names (default: none).
  --json                 Force canonical JSON output.
  --help, -h             Show this help and exit.

Examples:
  parquity check ./case.json --out ./check-run

"""
    + _EXIT_GENERAL,
    "fuzz": """Usage: parquity fuzz --examples N --seed N --out OUTPUT_DIR [--schema CASE_FILE]
       [--max-findings N] [--writers NAMES] [--readers NAMES]
       [--writer-profiles NAMES] [--json] [--help | -h]

Search generated Cases for semantic disagreements between Parquet engines.

Required options:
  --examples N           Maximum number of discovery examples.
  --seed N               Seed in [0, 18446744073709551615].
  --out OUTPUT_DIR       Destination for a published finding run.

Options:
  --schema CASE_FILE     Generate rows under the Case file's fixed schema;
                         omit to generate both schema and rows.
  --max-findings N       Retain 1 to 64 findings (default: 8).
  --writers NAMES        Comma-separated writer engine names
                         (default: pyarrow,duckdb,polars).
  --readers NAMES        Comma-separated reader engine names
                         (default: pyarrow,duckdb,polars).
  --writer-profiles NAMES
                         Comma-separated writer profile names (default: none).
  --json                 Force canonical JSON output.
  --help, -h             Show this help and exit.

The example limit and finding cap are competing bounds. A fingerprint beyond
the finding cap is recorded as overflow and stops discovery early. Overflow is
a known lower bound, not a count of every result that remained undiscovered.

"""
    + _EXIT_GENERAL,
    "scan": """Usage: parquity scan FILE_OR_DIR --out OUTPUT_DIR [--engines NAMES]
       [--timeout SECONDS] [--max-findings N] [--json] [--help | -h]

Compare independent reader observations of existing Parquet files.

Operands:
  FILE_OR_DIR            Parquet file or directory to scan.

Required options:
  --out OUTPUT_DIR       Destination for a published scan run.

Options:
  --engines NAMES        Comma-separated reader engine names
                         (default: pyarrow,duckdb,polars).
  --timeout SECONDS      Per reader-file timeout in [1, 300] (default: 30).
  --max-findings N       Retain 1 to 64 findings (default: 32).
  --json                 Force canonical JSON output.
  --help, -h             Show this help and exit.

"""
    + _EXIT_GENERAL,
    "replay": """Usage: parquity replay RUN_DIR [--json] [--help | -h]

Re-evaluate a saved finding or aggregate run against its recorded target.

Operands:
  RUN_DIR     Saved finding or aggregate run directory.

Options:
  --json      Force canonical JSON output.
  --help, -h  Show this help and exit.

Exit status:
  0  No recorded target reproduced exactly.
  1  At least one recorded target reproduced exactly.
  2  Provider, bundle, or recorded evidence validation failed.
  3  An unexpected internal failure prevented a valid result.
""",
    "triage": """Usage: parquity triage RUN_DIR [--focus all|execution|data|schema]
       [--replay-evidence FILE] [--json] [--help | -h]

Inspect or filter symptom families in a saved aggregate run.

Operands:
  RUN_DIR                 Saved aggregate run directory.

Options:
  --focus all|execution|data|schema
                          Select displayed families (default: all).
  --replay-evidence FILE  Bind canonical replay JSON to the triage view;
                          omit to report replay state as NOT_CHECKED.
  --json                  Force canonical JSON output.
  --help, -h              Show this help and exit.

Exit status:
  0  Triage completed.
  1  Not used by this command.
  2  Bundle, focus, or replay-evidence validation failed.
  3  An unexpected internal failure prevented a valid result.
""",
}


def _styled(value: str, code: str, enabled: bool) -> str:
    return f"{code}{value}{_RESET}" if enabled else value


def _banner(color: bool) -> str:
    def bold(value: str) -> str:
        return _styled(value, _BOLD, color)

    def accent(value: str) -> str:
        return _styled(value, _ACCENT, color)

    return (
        f"  {bold('╭────╮')}\n"
        f"  {bold('│    │')}   {bold('parquity')}\n"
        f"  {bold('╰────┤')}   Find and reproduce semantic disagreements\n"
        f"       {bold('│')}{accent('╲')}  between Parquet engines.\n"
        f"       {bold('│')} {accent('╲')}\n\n"
    )


def _colorize(document: str) -> str:
    rendered: list[str] = []
    for line in document.splitlines(keepends=True):
        content = line.removesuffix("\n")
        ending = "\n" if line.endswith("\n") else ""
        if section := _SECTION.match(content):
            label = section.group(0)
            content = f"{_BOLD}{label}{_RESET}{content[len(label) :]}"
        elif entry := _ENTRY.match(content):
            content = (
                f"{entry.group(1)}{_ACCENT}{entry.group(2)}{_RESET}{entry.group(3)}{entry.group(4)}"
            )
        elif content.startswith("  --"):
            content = f"  {_ACCENT}{content[2:]}{_RESET}"
        rendered.append(content + ending)
    return "".join(rendered)


def _use_color() -> bool:
    return "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb" and sys.stdout.isatty()


def render(arguments: HelpArguments) -> None:
    color = _use_color()
    document = _TOP_LEVEL if arguments.command is None else _HELP[arguments.command]
    output = _colorize(document) if color else document
    if arguments.command is None:
        output = _banner(color) + output
    print(output, end="")


__all__ = ["render"]
