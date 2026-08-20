from __future__ import annotations

import json

import pytest

from parquity.engines.external.process import BridgeUnavailableError, diagnostic, run_bridge
from parquity.engines.external.protocol import (
    BRIDGE_PROTOCOL,
    MAX_STREAM_BYTES,
    ExternalEngineProtocolError,
    kind_is_valid,
    parse_failure,
    parse_info,
    parse_success,
)
from tests.support import external_engine as bridge

_INFO: dict[str, object] = {
    "protocol": BRIDGE_PROTOCOL,
    "engine": "controlled",
    "version": "9.9.9",
    "directions": ["read", "write"],
}


def _payload(**changes: object) -> bytes:
    document = {**_INFO, **changes}
    return json.dumps(document).encode()


def test_a_well_formed_info_response_declares_directions_and_profiles() -> None:
    payload = _payload(writer_profiles={"row-group-2": {"row_group_size": 2}})
    info = parse_info(payload, "controlled")

    assert (info.engine, info.version) == ("controlled", "9.9.9")
    assert (info.reader, info.writer) == (True, True)
    assert info.writer_profiles == {"row-group-2": {"row_group_size": 2}}


@pytest.mark.parametrize(
    ("directions", "expected"),
    ((["read"], (True, False)), (["write"], (False, True)), (["write", "read"], (True, True))),
)
def test_a_single_direction_is_reported_alone(
    directions: list[str], expected: tuple[bool, bool]
) -> None:
    info = parse_info(_payload(directions=directions), "controlled")
    assert (info.reader, info.writer) == expected


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"protocol": "other.v1"}, "bridge protocol must be"),
        ({"engine": "different"}, "reports engine"),
        ({"version": ""}, "must be a non-empty string"),
        ({"directions": []}, "read, write, or both"),
        ({"directions": ["read", "read"]}, "read, write, or both"),
        ({"directions": ["sideways"]}, "read, write, or both"),
        ({"directions": "read"}, "must be an array"),
        ({"writer_profiles": {"not-a-profile": {"x": 1}}}, "unregistered writer profile"),
        ({"writer_profiles": {"row-group-2": {}}}, "must not be empty"),
        ({"writer_profiles": {"row-group-2": 2}}, "must be an object"),
        ({"writer_profiles": {"row-group-2": {"x": 1.5}}}, "boolean, integer, or string"),
        ({"writer_profiles": []}, "must be an object"),
        ({"unexpected": 1}, "fields are malformed"),
    ),
)
def test_a_malformed_info_response_is_a_protocol_error(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ExternalEngineProtocolError, match=message):
        parse_info(_payload(**changes), "controlled")


def test_info_requires_every_mandatory_field() -> None:
    document = dict(_INFO)
    del document["version"]
    with pytest.raises(ExternalEngineProtocolError, match="fields are malformed"):
        parse_info(json.dumps(document).encode(), "controlled")


@pytest.mark.parametrize("payload", (b"", b"not json", b"[]", b'{"status": "OK"'))
def test_a_response_that_is_not_an_object_is_a_protocol_error(payload: bytes) -> None:
    with pytest.raises(ExternalEngineProtocolError, match="not a JSON object"):
        parse_info(payload, "controlled")


def test_an_oversized_response_is_refused_before_parsing() -> None:
    with pytest.raises(ExternalEngineProtocolError, match="exceeds"):
        parse_info(b" " * (MAX_STREAM_BYTES + 1), "controlled")


def test_success_is_exactly_the_ok_object() -> None:
    parse_success(b'{"status":"OK"}')
    for payload in (b'{"status":"ERROR"}', b'{"status":"OK","extra":1}', b"{}"):
        with pytest.raises(ExternalEngineProtocolError, match="success response is malformed"):
            parse_success(payload)


def test_a_failure_object_carries_the_engines_own_error_kind() -> None:
    failure = parse_failure(b'{"status":"ERROR","kind":"ParquetFormatException","detail":"bad"}')
    assert failure is not None
    assert (failure.kind, failure.detail) == ("ParquetFormatException", "bad")


@pytest.mark.parametrize(
    "payload",
    (
        b'{"status":"OK"}',
        b'{"status":"ERROR","kind":"x"}',
        b'{"status":"ERROR","kind":"not valid","detail":"d"}',
        b'{"status":"ERROR","kind":1,"detail":"d"}',
        b"garbage",
    ),
)
def test_an_unusable_failure_object_is_reported_as_absent(payload: bytes) -> None:
    # The adapter treats this as a crash rather than evidence, so it must not raise here.
    assert parse_failure(payload) is None


@pytest.mark.parametrize(
    ("kind", "valid"),
    (
        ("ArrowInvalid", True),
        ("System.NotSupportedException", True),
        ("_private", True),
        ("1Leading", False),
        ("has space", False),
        ("has-dash", False),
        ("", False),
        ("k" * 65, False),
    ),
)
def test_a_reported_kind_must_be_a_bounded_identifier(kind: str, valid: bool) -> None:
    assert kind_is_valid(kind) is valid


def test_running_a_bridge_captures_its_streams_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PARQUITY_TEST_BRIDGE_FAULT", "info-exit")
    outcome = run_bridge(bridge.bridge_command(), ("info",), 30)

    assert (outcome.exit_code, outcome.timed_out) == (3, False)
    assert "probe refused" in outcome.stderr


def test_a_bridge_that_exceeds_its_timeout_is_reported_as_timed_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PARQUITY_TEST_BRIDGE_FAULT", "slow")
    outcome = run_bridge(bridge.bridge_command(), ("read",), 1)

    assert outcome.timed_out


def test_a_command_that_cannot_be_executed_is_reported_as_unavailable() -> None:
    with pytest.raises(BridgeUnavailableError, match="could not be executed"):
        run_bridge(("./no-such-bridge-executable",), ("info",), 30)


def test_diagnostics_join_a_detail_with_a_bounded_stderr_tail() -> None:
    assert diagnostic("failed", "") == "failed"
    assert diagnostic("", "  noisy \n output ") == "stderr: noisy output"
    assert diagnostic("failed", "why") == "failed; stderr: why"
