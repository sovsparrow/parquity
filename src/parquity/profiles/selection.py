from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from ..engines.base import EngineWriter, ProfiledEngineWriter
from ..evidence.model import EngineVersion
from . import (
    OPTION_UNAVAILABLE,
    PROFILE_REGISTRY,
    PROFILE_REGISTRY_SIZE,
    PROFILE_REGISTRY_SIZE_LABEL,
    CapabilityStatus,
    WriterProfileCapability,
    WriterProfileError,
    WriterProfileIdentity,
    WriterProfilePlan,
    missing_supported_profiles,
    registry_order,
)


def parse_requested_profiles(value: str | Sequence[str] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    names = [item.strip() for item in value.split(",")] if isinstance(value, str) else list(value)
    if not names or any(not name for name in names):
        raise _invalid_profile_set("writer profile set contains an empty name")
    if "default" in names:
        raise WriterProfileError("INVALID_WRITER_PROFILE_SET", "default writer profile is implicit")
    if len(names) != len(set(names)):
        raise _invalid_profile_set("writer profile set contains a duplicate name")
    if len(names) > PROFILE_REGISTRY_SIZE:
        raise _invalid_profile_set(
            f"writer profile set exceeds {PROFILE_REGISTRY_SIZE_LABEL} names"
        )
    unknown = [name for name in names if name not in PROFILE_REGISTRY]
    if unknown:
        raise WriterProfileError(
            "UNKNOWN_WRITER_PROFILE", f"unknown writer profile: {', '.join(unknown)}"
        )
    return registry_order(names)


def build_writer_profile_plan(
    requested: tuple[str, ...] | None, writers: Sequence[EngineWriter]
) -> WriterProfilePlan | None:
    if requested is None:
        return None
    capabilities: list[WriterProfileCapability] = []
    for writer in writers:
        engine = writer.identity
        for name in requested:
            profile = (
                writer.writer_profile(name) if isinstance(writer, ProfiledEngineWriter) else None
            )
            declared_profile = cast(object, profile)
            if declared_profile is not None and not isinstance(
                declared_profile, WriterProfileIdentity
            ):
                raise TypeError("writer profile declaration is malformed")
            capabilities.append(_capability(engine, name, declared_profile))
    missing = missing_supported_profiles(requested, capabilities)
    if missing:
        names = ", ".join(missing)
        raise WriterProfileError(
            "WRITER_PROFILE_UNSUPPORTED",
            f"requested writer profile has no supporting endpoint: {names}",
        )
    return WriterProfilePlan(requested, tuple(capabilities))


def _capability(
    engine: EngineVersion, name: str, profile: WriterProfileIdentity | None
) -> WriterProfileCapability:
    if profile is not None:
        return WriterProfileCapability(engine, name, CapabilityStatus.SUPPORTED, profile)
    return WriterProfileCapability(
        engine, name, CapabilityStatus.UNSUPPORTED, reason_code=OPTION_UNAVAILABLE
    )


def _invalid_profile_set(detail: str) -> WriterProfileError:
    return WriterProfileError("INVALID_WRITER_PROFILE_SET", detail)


__all__ = ["build_writer_profile_plan", "parse_requested_profiles"]
