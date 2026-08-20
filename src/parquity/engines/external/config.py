from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Mapping, Set
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ENGINES_FILE_VARIABLE = "PARQUITY_ENGINES_FILE"
DEFAULT_TIMEOUT_SECONDS = 60
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 300
MAX_NAME_LENGTH = 32
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*$")
_ENGINE_KEYS = frozenset({"command", "timeout_seconds"})

# The declarations a run was configured with, read once. A run records evidence against the
# engines it was given, so re-reading the file mid-run would let that set change underneath it --
# and it would be read again for every enumeration, which is several times in a single command.
# Keyed by path, so pointing the variable somewhere else still takes effect.
_DECLARATIONS: dict[Path, Mapping[str, Mapping[str, object]]] = {}


class ExternalEngineConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ExternalEngineSpec:
    name: str
    command: tuple[str, ...]
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not name_is_valid(self.name):
            raise ExternalEngineConfigurationError(f"external engine name is invalid: {self.name}")
        if not self.command or any(not item for item in self.command):
            raise ExternalEngineConfigurationError(
                f"external engine command must be a non-empty argument vector: {self.name}"
            )
        if not MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ExternalEngineConfigurationError(
                f"external engine timeout must be in "
                f"[{MIN_TIMEOUT_SECONDS}, {MAX_TIMEOUT_SECONDS}]: {self.name}"
            )

    @property
    def command_variable(self) -> str:
        return f"PARQUITY_ENGINE_{self.name.upper().replace('-', '_')}_COMMAND"


def name_is_valid(value: str) -> bool:
    return len(value) <= MAX_NAME_LENGTH and _NAME_PATTERN.fullmatch(value) is not None


def configured_specs(reserved: Set[str]) -> tuple[ExternalEngineSpec, ...]:
    location = os.environ.get(ENGINES_FILE_VARIABLE)
    if not location:
        return ()
    declarations = _declarations(Path(location))
    return tuple(
        _spec(name, declarations[name], reserved) for name in sorted(declarations, key=str.encode)
    )


def reset_declaration_cache() -> None:
    """Forgets the engines file, so a caller that rewrites it is read again."""
    _DECLARATIONS.clear()


def _declarations(path: Path) -> Mapping[str, Mapping[str, object]]:
    cached = _DECLARATIONS.get(path)
    if cached is not None:
        return cached
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ExternalEngineConfigurationError(
            f"{ENGINES_FILE_VARIABLE} could not be read: {path}"
        ) from error
    try:
        # utf-8-sig tolerates the byte-order mark that Windows editors add and is
        # otherwise identical to utf-8.
        document: Mapping[str, object] = tomllib.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ExternalEngineConfigurationError(
            f"{ENGINES_FILE_VARIABLE} is not valid UTF-8 TOML: {path}"
        ) from error
    if set(document) - {"engines"}:
        raise ExternalEngineConfigurationError(
            f"{ENGINES_FILE_VARIABLE} accepts only an engines table: {path}"
        )
    engines = _mapping(document.get("engines", {}))
    if engines is None:
        raise ExternalEngineConfigurationError(f"engines must be a table of engines: {path}")
    # Only a file that parsed is remembered, so a malformed one is reported every time it is
    # asked for rather than once.
    declarations = {name: _table(name, engines[name]) for name in engines}
    _DECLARATIONS[path] = declarations
    return declarations


def _mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return None
    return cast(Mapping[str, object], raw)


def _table(name: str, value: object) -> Mapping[str, object]:
    declaration = _mapping(value)
    if declaration is None:
        raise ExternalEngineConfigurationError(f"external engine must be a table: {name}")
    unknown = set(declaration) - _ENGINE_KEYS
    if unknown:
        raise ExternalEngineConfigurationError(
            f"external engine has unknown keys: {name}: {', '.join(sorted(unknown))}"
        )
    return declaration


def _spec(name: str, declaration: Mapping[str, object], reserved: Set[str]) -> ExternalEngineSpec:
    if name in reserved:
        raise ExternalEngineConfigurationError(
            f"external engine name is already a built-in provider: {name}"
        )
    if not name_is_valid(name):
        raise ExternalEngineConfigurationError(f"external engine name is invalid: {name}")
    spec = ExternalEngineSpec(name, _command(name, declaration), _timeout(name, declaration))
    override = os.environ.get(spec.command_variable)
    if override is None:
        return spec
    return ExternalEngineSpec(name, _override(spec, override), spec.timeout_seconds)


def _command(name: str, declaration: Mapping[str, object]) -> tuple[str, ...]:
    if "command" not in declaration:
        raise ExternalEngineConfigurationError(f"external engine requires a command: {name}")
    command = _string_array(declaration["command"])
    if command is None:
        raise ExternalEngineConfigurationError(
            f"external engine command must be an array of strings: {name}"
        )
    return command


def _string_array(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    items = cast(list[object], value)
    if any(not isinstance(item, str) for item in items):
        return None
    return tuple(cast(list[str], items))


def _timeout(name: str, declaration: Mapping[str, object]) -> int:
    value = declaration.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ExternalEngineConfigurationError(
            f"external engine timeout_seconds must be an integer: {name}"
        )
    return value


def _override(spec: ExternalEngineSpec, value: str) -> tuple[str, ...]:
    if not value.strip().startswith("["):
        return (value,)
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise ExternalEngineConfigurationError(
            f"{spec.command_variable} is not a JSON array of strings"
        ) from error
    command = _string_array(decoded)
    if command is None or not command or any(not item for item in command):
        raise ExternalEngineConfigurationError(
            f"{spec.command_variable} is not a JSON array of strings"
        )
    return command


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "ENGINES_FILE_VARIABLE",
    "MAX_NAME_LENGTH",
    "MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "ExternalEngineConfigurationError",
    "ExternalEngineSpec",
    "configured_specs",
    "name_is_valid",
    "reset_declaration_cache",
]
