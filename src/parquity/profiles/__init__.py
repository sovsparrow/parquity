from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from ..evidence import json_codec
from ..evidence.model import EngineVersion

PROFILE_REGISTRY = (
    "compression-gzip",
    "compression-brotli",
    "row-group-2",
    "min-max-statistics-off",
)
PROFILE_REGISTRY_SIZE = len(PROFILE_REGISTRY)
PROFILE_REGISTRY_SIZE_LABEL = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
}.get(PROFILE_REGISTRY_SIZE, str(PROFILE_REGISTRY_SIZE))
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
        json_codec.require_exact_keys(data, {"name", "effective_options"}, "writer profile")
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
        json_codec.require_exact_keys(
            data, {"writer", "profile", "status", option}, "writer capability"
        )
        writer = _engine_version(json_codec.mapping(data["writer"], "capability writer"))
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
        canonical = registry_order(self.requested_profiles)
        if not self.requested_profiles or self.requested_profiles != canonical:
            raise ValueError("writer profile request is empty or noncanonical")
        expected = tuple(
            (writer, profile) for writer in self.writers for profile in self.requested_profiles
        )
        actual = tuple((item.writer, item.profile_name) for item in self.capabilities)
        if not self.writers or actual != expected:
            raise ValueError("writer profile capability grid is incomplete or noncanonical")
        if missing_supported_profiles(self.requested_profiles, self.capabilities):
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
        json_codec.require_exact_keys(data, {"requested", "capabilities"}, "writer profile plan")
        requested = tuple(
            _string(value, "requested profile")
            for value in json_codec.sequence(data["requested"], "requested")
        )
        capabilities = tuple(
            WriterProfileCapability.from_data(json_codec.mapping(value, "writer capability"))
            for value in json_codec.sequence(data["capabilities"], "capabilities")
        )
        return cls(requested, capabilities)

    def replay_equivalent(self, other: WriterProfilePlan) -> bool:
        left = tuple(_replay_key(item) for item in self.capabilities)
        right = tuple(_replay_key(item) for item in other.capabilities)
        return self.requested_profiles == other.requested_profiles and left == right


def registry_order(names: Sequence[str]) -> tuple[str, ...]:
    selected = set(names)
    return tuple(name for name in PROFILE_REGISTRY if name in selected)


def missing_supported_profiles(
    requested: Sequence[str],
    capabilities: Sequence[WriterProfileCapability],
) -> tuple[str, ...]:
    return tuple(
        name
        for name in requested
        if not any(
            item.profile_name == name and item.status is CapabilityStatus.SUPPORTED
            for item in capabilities
        )
    )


def optional_writer_profile_plan_from_data(
    data: Mapping[str, object],
) -> WriterProfilePlan | None:
    if "writer_profiles" not in data:
        return None
    return WriterProfilePlan.from_data(
        json_codec.mapping(data["writer_profiles"], "writer_profiles")
    )


def _replay_key(capability: WriterProfileCapability) -> tuple[object, ...]:
    return (
        capability.writer.name,
        capability.profile_name,
        capability.status,
        capability.profile_identity,
        capability.reason_code,
    )


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


def _engine_version(data: Mapping[str, object]) -> EngineVersion:
    try:
        return EngineVersion.from_data(data)
    except ValueError as error:
        raise ValueError("capability writer is malformed") from error


def _options(value: object) -> Mapping[str, OptionValue]:
    data = json_codec.mapping(value, "effective_options")
    if any(not isinstance(item, bool | int | str) for item in data.values()):
        raise ValueError("writer profile effective options are malformed")
    return cast(Mapping[str, OptionValue], data)


def _valid_option(key: object, value: object) -> bool:
    if not isinstance(key, str) or not key or not isinstance(value, bool | int | str):
        return False
    try:
        json_codec.string(key, "writer profile option name")
        if isinstance(value, str):
            json_codec.string(value, "writer profile option value")
    except json_codec.EvidenceValidationError:
        return False
    return True


def _string(value: object, label: str) -> str:
    value = json_codec.string(value, label)
    if not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


__all__ = [
    "OPTION_UNAVAILABLE",
    "PROFILE_REGISTRY",
    "PROFILE_REGISTRY_SIZE",
    "PROFILE_REGISTRY_SIZE_LABEL",
    "CapabilityStatus",
    "WriterExecutionIdentity",
    "WriterProfileCapability",
    "WriterProfileError",
    "WriterProfileIdentity",
    "WriterProfilePlan",
    "missing_supported_profiles",
    "optional_writer_profile_plan_from_data",
    "registry_order",
]
