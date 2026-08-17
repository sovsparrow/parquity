from __future__ import annotations

from collections.abc import Set
from dataclasses import dataclass

from ...evidence import bounded_detail
from ..base import EngineDescriptor
from .config import (
    ENGINES_FILE_VARIABLE,
    ExternalEngineConfigurationError,
    ExternalEngineSpec,
    configured_specs,
)
from .process import BridgeUnavailableError, diagnostic, run_bridge
from .protocol import BridgeInfo, ExternalEngineProtocolError, parse_info

EXTERNAL_TIER = "external"
_ADAPTER_MODULE = "parquity.engines.external.adapter"
_PROBE_CACHE: dict[tuple[str, tuple[str, ...], int], ExternalRegistration] = {}


@dataclass(frozen=True, slots=True)
class ExternalRegistration:
    spec: ExternalEngineSpec
    info: BridgeInfo | None
    detail: str

    @property
    def descriptor(self) -> EngineDescriptor:
        info = self.info
        # A bridge whose probe failed declares both directions so that selecting it
        # reports the probe failure rather than a misleading capability error. Its
        # availability is False, which is what stops the run.
        return EngineDescriptor(
            name=self.spec.name,
            distribution=self.spec.name,
            import_name="",
            adapter_module=_ADAPTER_MODULE,
            installation_hint=(
                f"Check the {self.spec.name} bridge command in {ENGINES_FILE_VARIABLE}"
            ),
            tier=EXTERNAL_TIER,
            reader=True if info is None else info.reader,
            writer=True if info is None else info.writer,
        )


def external_registrations(reserved: Set[str]) -> tuple[ExternalRegistration, ...]:
    return tuple(_registration(spec) for spec in configured_specs(reserved))


def external_registration(name: str, reserved: Set[str]) -> ExternalRegistration | None:
    return next((item for item in external_registrations(reserved) if item.spec.name == name), None)


def reset_probe_cache() -> None:
    _PROBE_CACHE.clear()


def _registration(spec: ExternalEngineSpec) -> ExternalRegistration:
    key = (spec.name, spec.command, spec.timeout_seconds)
    cached = _PROBE_CACHE.get(key)
    if cached is None:
        cached = _probe(spec)
        _PROBE_CACHE[key] = cached
    return cached


def _probe(spec: ExternalEngineSpec) -> ExternalRegistration:
    try:
        outcome = run_bridge(spec.command, ("info",), spec.timeout_seconds)
    except (BridgeUnavailableError, ExternalEngineProtocolError) as error:
        return ExternalRegistration(spec, None, bounded_detail(error))
    if outcome.timed_out:
        return ExternalRegistration(
            spec, None, f"info probe exceeded {spec.timeout_seconds} seconds"
        )
    if outcome.exit_code != 0:
        return ExternalRegistration(
            spec, None, diagnostic(f"info probe exited {outcome.exit_code}", outcome.stderr)
        )
    try:
        info = parse_info(outcome.stdout, spec.name)
    except ExternalEngineProtocolError as error:
        return ExternalRegistration(spec, None, bounded_detail(error))
    return ExternalRegistration(spec, info, "bridge info probe succeeded")


__all__ = [
    "ENGINES_FILE_VARIABLE",
    "EXTERNAL_TIER",
    "BridgeInfo",
    "ExternalEngineConfigurationError",
    "ExternalEngineProtocolError",
    "ExternalEngineSpec",
    "ExternalRegistration",
    "external_registration",
    "external_registrations",
    "reset_probe_cache",
]
