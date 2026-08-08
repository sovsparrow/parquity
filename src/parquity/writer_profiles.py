from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from .engines.base import EngineWriter, ProfiledEngineWriter
from .verdicts import EngineVersion

PROFILE_REGISTRY = (
    "compression-gzip",
    "compression-brotli",
    "row-group-2",
    "min-max-statistics-off",
)
OPTION_UNAVAILABLE = "OPTION_UNAVAILABLE"
OptionValue = bool | int | str
CanonicalOptions = tuple[tuple[str, OptionValue], ...]


class WriterProfileError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


class CapabilityStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True, init=False, eq=False)
class WriterProfileIdentity:
    name: str
    canonical_effective_options: CanonicalOptions

    def __init__(
        self,
        name: str,
        effective_options: Mapping[str, OptionValue] | Sequence[tuple[str, OptionValue]],
    ) -> None:
        if name not in PROFILE_REGISTRY:
            raise ValueError("writer profile name is not recognized")
        options = _canonical_options(effective_options)
        if not options:
            raise ValueError("writer profile effective options must not be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "canonical_effective_options", options)

    @property
    def effective_options(self) -> dict[str, OptionValue]:
        return dict(self.canonical_effective_options)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WriterProfileIdentity):
            return NotImplemented
        return self._identity_key() == other._identity_key()

    def __hash__(self) -> int:
        return hash(self._identity_key())

    def _identity_key(self) -> tuple[object, ...]:
        typed = tuple((key, type(value), value) for key, value in self.canonical_effective_options)
        return self.name, typed

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "effective_options": self.effective_options}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> WriterProfileIdentity:
        _exact_keys(data, {"name", "effective_options"}, "writer profile")
        return cls(_string(data["name"], "profile name"), _options(data["effective_options"]))


@dataclass(frozen=True, slots=True)
class WriterProfileCapability:
    writer: EngineVersion
    profile_name: str
    status: CapabilityStatus
    profile_identity: WriterProfileIdentity | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        status = cast(object, self.status)
        if not isinstance(status, CapabilityStatus):
            raise ValueError("writer capability status is malformed")
        if self.profile_name not in PROFILE_REGISTRY:
            raise ValueError("writer capability profile is not recognized")
        if status is CapabilityStatus.SUPPORTED:
            valid = (
                isinstance(self.profile_identity, WriterProfileIdentity)
                and self.profile_identity.name == self.profile_name
                and self.reason_code is None
            )
        else:
            valid = self.profile_identity is None and self.reason_code == OPTION_UNAVAILABLE
        if not valid:
            raise ValueError("writer capability union is malformed")

    @property
    def effective_options(self) -> dict[str, OptionValue] | None:
        return None if self.profile_identity is None else self.profile_identity.effective_options

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "writer": self.writer.to_data(),
            "profile": self.profile_name,
            "status": self.status.value,
        }
        if self.status is CapabilityStatus.SUPPORTED:
            data["effective_options"] = self.effective_options
        else:
            data["reason_code"] = self.reason_code
        return data

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> WriterProfileCapability:
        status = CapabilityStatus(_string(data.get("status"), "capability status"))
        option = "effective_options" if status is CapabilityStatus.SUPPORTED else "reason_code"
        _exact_keys(data, {"writer", "profile", "status", option}, "writer capability")
        writer = _engine_version(_mapping(data["writer"], "capability writer"))
        name = _string(data["profile"], "capability profile")
        if status is CapabilityStatus.SUPPORTED:
            return cls(writer, name, status, WriterProfileIdentity(name, _options(data[option])))
        return cls(writer, name, status, reason_code=_string(data[option], "reason_code"))


@dataclass(frozen=True, slots=True)
class WriterExecutionIdentity:
    writer: EngineVersion
    writer_profile: WriterProfileIdentity | None = None


@dataclass(frozen=True, slots=True)
class WriterProfilePlan:
    requested_profiles: tuple[str, ...]
    capabilities: tuple[WriterProfileCapability, ...]

    def __post_init__(self) -> None:
        if len(self.requested_profiles) != len(set(self.requested_profiles)):
            raise ValueError("writer profile request contains duplicates")
        canonical = _registry_order(self.requested_profiles)
        if not self.requested_profiles or self.requested_profiles != canonical:
            raise ValueError("writer profile request is empty or noncanonical")
        expected = tuple(
            (writer, profile) for writer in self.writers for profile in self.requested_profiles
        )
        actual = tuple((item.writer, item.profile_name) for item in self.capabilities)
        if not self.writers or actual != expected:
            raise ValueError("writer profile capability grid is incomplete or noncanonical")
        for profile in self.requested_profiles:
            if not any(
                item.profile_name == profile and item.status is CapabilityStatus.SUPPORTED
                for item in self.capabilities
            ):
                raise ValueError("a requested writer profile has no supported execution")

    @property
    def writers(self) -> tuple[EngineVersion, ...]:
        width = len(self.requested_profiles)
        return tuple(
            self.capabilities[index].writer for index in range(0, len(self.capabilities), width)
        )

    def validate_writers(self, writers: tuple[EngineVersion, ...]) -> None:
        if self.writers != writers:
            raise ValueError("writer profile plan conflicts with selected writers")

    def executions(self, writers: tuple[EngineVersion, ...]) -> tuple[WriterExecutionIdentity, ...]:
        self.validate_writers(writers)
        return tuple(
            WriterExecutionIdentity(writer, profile)
            for writer in writers
            for profile in (
                None,
                *(
                    item.profile_identity
                    for item in self.capabilities
                    if item.writer == writer and item.profile_identity is not None
                ),
            )
        )

    def to_data(self) -> dict[str, object]:
        return {
            "requested": list(self.requested_profiles),
            "capabilities": [item.to_data() for item in self.capabilities],
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> WriterProfilePlan:
        _exact_keys(data, {"requested", "capabilities"}, "writer profile plan")
        requested = tuple(
            _string(value, "requested profile")
            for value in _sequence(data["requested"], "requested")
        )
        capabilities = tuple(
            WriterProfileCapability.from_data(_mapping(value, "writer capability"))
            for value in _sequence(data["capabilities"], "capabilities")
        )
        return cls(requested, capabilities)

    def replay_equivalent(self, other: WriterProfilePlan) -> bool:
        left = tuple(_replay_key(item) for item in self.capabilities)
        right = tuple(_replay_key(item) for item in other.capabilities)
        return self.requested_profiles == other.requested_profiles and left == right


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
    if len(names) > len(PROFILE_REGISTRY):
        raise _invalid_profile_set("writer profile set exceeds four names")
    unknown = [name for name in names if name not in PROFILE_REGISTRY]
    if unknown:
        raise WriterProfileError(
            "UNKNOWN_WRITER_PROFILE", f"unknown writer profile: {', '.join(unknown)}"
        )
    return _registry_order(tuple(names))


def build_writer_profile_plan(
    requested: tuple[str, ...] | None, writers: Sequence[EngineWriter]
) -> WriterProfilePlan | None:
    if requested is None:
        return None
    capabilities: list[WriterProfileCapability] = []
    for writer in writers:
        engine = EngineVersion(writer.identity.name, writer.identity.version)
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
    missing = tuple(
        name
        for name in requested
        if not any(
            item.profile_name == name and item.status is CapabilityStatus.SUPPORTED
            for item in capabilities
        )
    )
    if missing:
        names = ", ".join(missing)
        raise WriterProfileError(
            "WRITER_PROFILE_UNSUPPORTED",
            f"requested writer profile has no supporting endpoint: {names}",
        )
    return WriterProfilePlan(requested, tuple(capabilities))


def _replay_key(capability: WriterProfileCapability) -> tuple[object, ...]:
    return (
        capability.writer.name,
        capability.profile_name,
        capability.status,
        capability.profile_identity,
        capability.reason_code,
    )


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


def _canonical_options(
    value: Mapping[str, OptionValue] | Sequence[tuple[str, OptionValue]],
) -> CanonicalOptions:
    items = tuple(value.items()) if isinstance(value, Mapping) else tuple(value)
    if any(not _valid_option(key, item) for key, item in items):
        raise ValueError("writer profile effective options are malformed")
    keys = [key for key, _ in items]
    if len(keys) != len(set(keys)):
        raise ValueError("writer profile effective options contain duplicate keys")
    return tuple(sorted(items))


def _registry_order(names: Sequence[str]) -> tuple[str, ...]:
    selected = set(names)
    return tuple(name for name in PROFILE_REGISTRY if name in selected)


def _engine_version(data: Mapping[str, object]) -> EngineVersion:
    _exact_keys(data, {"name", "version"}, "capability writer")
    return EngineVersion(
        _string(data["name"], "writer name"), _string(data["version"], "writer version")
    )


def _options(value: object) -> Mapping[str, OptionValue]:
    data = _mapping(value, "effective_options")
    if any(not isinstance(item, bool | int | str) for item in data.values()):
        raise ValueError("writer profile effective options are malformed")
    return cast(Mapping[str, OptionValue], data)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise ValueError(f"{label} must be an object")
    return cast(Mapping[str, object], raw)


def _valid_option(key: object, value: object) -> bool:
    return isinstance(key, str) and bool(key) and isinstance(value, bool | int | str)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise ValueError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _exact_keys(data: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(data) != expected:
        raise ValueError(f"{label} fields are malformed")
