from __future__ import annotations

import json
from pathlib import Path

import pytest

from parquity.engines.external.config import (
    DEFAULT_TIMEOUT_SECONDS,
    ENGINES_FILE_VARIABLE,
    ExternalEngineConfigurationError,
    ExternalEngineSpec,
    configured_specs,
)

BUILTIN = frozenset({"pyarrow", "duckdb", "polars", "datafusion", "fastparquet"})
_COMMAND = '["/opt/bridge"]'


def _declare(document: str, root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = root / "engines.toml"
    path.write_text(document, encoding="utf-8")
    monkeypatch.setenv(ENGINES_FILE_VARIABLE, str(path))
    return path


def test_no_declaration_file_means_no_external_engines(monkeypatch: pytest.MonkeyPatch) -> None:
    # Discovery must not search the working directory: a declaration names a command that will be
    # executed, so it is opted into by pointing at it explicitly.
    monkeypatch.delenv(ENGINES_FILE_VARIABLE, raising=False)
    assert configured_specs(BUILTIN) == ()
    monkeypatch.setenv(ENGINES_FILE_VARIABLE, "")
    assert configured_specs(BUILTIN) == ()


def test_declarations_are_read_in_canonical_order_with_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(
        "[engines.zulu]\n"
        'command = ["/opt/zulu", "serve"]\n'
        "[engines.alpha]\n"
        f"command = {_COMMAND}\n"
        "timeout_seconds = 12\n",
        tmp_path,
        monkeypatch,
    )
    specs = configured_specs(BUILTIN)

    assert [item.name for item in specs] == ["alpha", "zulu"]
    assert specs[0] == ExternalEngineSpec("alpha", ("/opt/bridge",), 12)
    assert specs[1].command == ("/opt/zulu", "serve")
    assert specs[1].timeout_seconds == DEFAULT_TIMEOUT_SECONDS


def test_a_byte_order_mark_is_tolerated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Several Windows editors and PowerShell's own utf8 encoding prepend one, and tomllib rejects it.
    path = tmp_path / "engines.toml"
    path.write_bytes(b"\xef\xbb\xbf" + f"[engines.alpha]\ncommand = {_COMMAND}\n".encode())
    monkeypatch.setenv(ENGINES_FILE_VARIABLE, str(path))

    assert [item.name for item in configured_specs(BUILTIN)] == ["alpha"]


@pytest.mark.parametrize(
    ("document", "message"),
    (
        ("engines = 1\n", "engines must be a table"),
        ("[other]\nx = 1\n", "accepts only an engines table"),
        ("[engines]\nalpha = 1\n", "must be a table"),
        ("[engines.alpha]\n", "requires a command"),
        ("[engines.alpha]\ncommand = 1\n", "array of strings"),
        ("[engines.alpha]\ncommand = [1]\n", "array of strings"),
        (f"[engines.alpha]\ncommand = {_COMMAND}\nunknown = 1\n", "unknown keys"),
        (f"[engines.alpha]\ncommand = {_COMMAND}\ntimeout_seconds = 'x'\n", "must be an integer"),
        (f"[engines.alpha]\ncommand = {_COMMAND}\ntimeout_seconds = 0\n", "timeout must be in"),
        (f"[engines.alpha]\ncommand = {_COMMAND}\ntimeout_seconds = 301\n", "timeout must be in"),
        ('[engines.Alpha]\ncommand = ["/x"]\n', "name is invalid"),
        ('[engines."1alpha"]\ncommand = ["/x"]\n', "name is invalid"),
        (f'[engines."{"a" * 33}"]\ncommand = {_COMMAND}\n', "name is invalid"),
        (f"[engines.pyarrow]\ncommand = {_COMMAND}\n", "already a built-in provider"),
        ("[engines.alpha]\ncommand = [\n", "not valid UTF-8 TOML"),
        ("[engines.alpha]\ncommand = []\n", "non-empty argument vector"),
    ),
)
def test_malformed_declarations_are_configuration_errors(
    document: str, message: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(document, tmp_path, monkeypatch)
    with pytest.raises(ExternalEngineConfigurationError, match=message):
        configured_specs(BUILTIN)


def test_an_unreadable_declaration_file_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENGINES_FILE_VARIABLE, str(tmp_path / "absent.toml"))
    with pytest.raises(ExternalEngineConfigurationError, match="could not be read"):
        configured_specs(BUILTIN)


def test_the_command_override_accepts_a_bare_path_or_a_json_vector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(f"[engines.alpha-one]\ncommand = {_COMMAND}\n", tmp_path, monkeypatch)
    variable = "PARQUITY_ENGINE_ALPHA_ONE_COMMAND"
    assert configured_specs(BUILTIN)[0].command_variable == variable

    # A bare value is taken whole, so a path containing spaces needs no quoting.
    monkeypatch.setenv(variable, r"C:\Program Files\bridge.exe")
    assert configured_specs(BUILTIN)[0].command == (r"C:\Program Files\bridge.exe",)

    monkeypatch.setenv(variable, json.dumps(["java", "-jar", "/opt/bridge.jar"]))
    assert configured_specs(BUILTIN)[0].command == ("java", "-jar", "/opt/bridge.jar")


@pytest.mark.parametrize("value", ("[", "[1]", "[]", '[""]'))
def test_a_malformed_command_override_is_a_configuration_error(
    value: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declare(f"[engines.alpha]\ncommand = {_COMMAND}\n", tmp_path, monkeypatch)
    monkeypatch.setenv("PARQUITY_ENGINE_ALPHA_COMMAND", value)
    with pytest.raises(ExternalEngineConfigurationError, match="JSON array of strings"):
        configured_specs(BUILTIN)
