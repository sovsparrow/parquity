from __future__ import annotations

import platform
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from importlib import metadata
from typing import Protocol

from . import json_codec

_DEPENDENCY_ORDER = ("pyarrow", "pandas")


class ReplayClassification(StrEnum):
    REPRODUCED = "REPRODUCED"
    RELATED_FAILURE = "RELATED_FAILURE"
    NOT_REPRODUCED = "NOT_REPRODUCED"


@dataclass(frozen=True, slots=True)
class DifferenceEvidence:
    expected: str
    observed: str

    def __post_init__(self) -> None:
        if not self.expected or not self.observed:
            raise ValueError("difference evidence values must not be empty")

    def to_data(self) -> dict[str, object]:
        return {"expected": self.expected, "observed": self.observed}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> DifferenceEvidence:
        if set(data) != {"expected", "observed"}:
            raise ValueError("difference evidence fields are malformed")
        expected = data["expected"]
        observed = data["observed"]
        if not isinstance(expected, str) or not isinstance(observed, str):
            raise ValueError("difference evidence values must be strings")
        return cls(expected, observed)


@dataclass(frozen=True, slots=True)
class EngineVersion:
    name: str
    version: str

    def __post_init__(self) -> None:
        if not self.name or not self.version:
            raise ValueError("engine name and version must not be empty")

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "version": self.version}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> EngineVersion:
        if set(data) != {"name", "version"}:
            raise ValueError("engine version fields are malformed")
        name = data["name"]
        version = data["version"]
        if not isinstance(name, str):
            raise ValueError("engine name must be a string")
        if not isinstance(version, str):
            raise ValueError("engine version must be a string")
        try:
            return cls(name, version)
        except ValueError as error:
            raise ValueError("engine version evidence is malformed") from error


@dataclass(frozen=True, slots=True)
class DependencyVersion:
    package: str
    version: str

    def __post_init__(self) -> None:
        if self.package not in _DEPENDENCY_ORDER or not self.version:
            raise json_codec.FindingValidationError("dependency evidence is malformed")

    def to_data(self) -> dict[str, object]:
        return {"package": self.package, "version": self.version}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> DependencyVersion:
        json_codec.require_exact_keys(data, {"package", "version"}, "dependency evidence")
        return cls(
            json_codec.string(json_codec.required(data, "package"), "dependency package"),
            json_codec.string(json_codec.required(data, "version"), "dependency version"),
        )


@dataclass(frozen=True, slots=True)
class EnvironmentEvidence:
    parquity_version: str
    hypothesis_version: str
    python_version: str
    platform: str
    providers: tuple[EngineVersion, ...]
    dependencies: tuple[DependencyVersion, ...]

    def __post_init__(self) -> None:
        values = (
            self.parquity_version,
            self.hypothesis_version,
            self.python_version,
            self.platform,
        )
        if any(not value for value in values):
            raise json_codec.FindingValidationError("environment evidence fields must not be empty")
        if not engine_selection_is_valid(self.providers):
            raise json_codec.FindingValidationError("environment providers must be unique")
        names = [provider.name for provider in self.providers]
        expected = ("pyarrow",) + (("pandas",) if "fastparquet" in names else ())
        dependency_names = tuple(item.package for item in self.dependencies)
        if dependency_names != expected:
            raise json_codec.FindingValidationError("environment dependencies are not canonical")
        provider_versions = {provider.name: provider.version for provider in self.providers}
        dependency_versions = {item.package: item.version for item in self.dependencies}
        if (
            "pyarrow" in provider_versions
            and provider_versions["pyarrow"] != dependency_versions["pyarrow"]
        ):
            raise json_codec.FindingValidationError(
                "PyArrow provider and dependency versions differ"
            )

    def to_data(self) -> dict[str, object]:
        return {
            "parquity_version": self.parquity_version,
            "hypothesis_version": self.hypothesis_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "providers": [provider.to_data() for provider in self.providers],
            "dependencies": [item.to_data() for item in self.dependencies],
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> EnvironmentEvidence:
        keys = {
            "parquity_version",
            "hypothesis_version",
            "python_version",
            "platform",
            "providers",
            "dependencies",
        }
        json_codec.require_exact_keys(data, keys, "environment evidence")
        return cls(
            json_codec.string(json_codec.required(data, "parquity_version"), "parquity_version"),
            json_codec.string(
                json_codec.required(data, "hypothesis_version"), "hypothesis_version"
            ),
            json_codec.string(json_codec.required(data, "python_version"), "python_version"),
            json_codec.string(json_codec.required(data, "platform"), "platform"),
            engine_versions_from_data(json_codec.required(data, "providers"), "providers"),
            tuple(
                DependencyVersion.from_data(json_codec.mapping(value, "dependency"))
                for value in json_codec.sequence(
                    json_codec.required(data, "dependencies"), "dependencies"
                )
            ),
        )


def capture_environment(providers: tuple[EngineVersion, ...]) -> EnvironmentEvidence:
    dependency_names = ("pyarrow",) + (
        ("pandas",) if any(provider.name == "fastparquet" for provider in providers) else ()
    )
    return EnvironmentEvidence(
        parquity_version=metadata.version("parquity"),
        hypothesis_version=metadata.version("hypothesis"),
        python_version=platform.python_version(),
        platform=platform.platform(),
        providers=providers,
        dependencies=tuple(
            DependencyVersion(package, metadata.version(package)) for package in dependency_names
        ),
    )


def engine_versions_from_data(value: object, label: str) -> tuple[EngineVersion, ...]:
    try:
        return tuple(
            EngineVersion.from_data(json_codec.mapping(item, label))
            for item in json_codec.sequence(value, label)
        )
    except json_codec.EvidenceValidationError:
        raise
    except ValueError as error:
        raise json_codec.EvidenceValidationError(str(error)) from error


def provider_inventory_matches(
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    providers: tuple[EngineVersion, ...],
) -> bool:
    if not engine_selection_is_valid(writers) or not engine_selection_is_valid(readers):
        return False
    selected: dict[str, str] = {}
    for engines in (writers, readers):
        for engine in engines:
            current = selected.get(engine.name)
            if current is not None and current != engine.version:
                return False
            selected[engine.name] = engine.version
    inventory = {provider.name: provider.version for provider in providers}
    return len(inventory) == len(providers) and inventory == selected


def engine_selection_is_valid(engines: tuple[EngineVersion, ...]) -> bool:
    names = tuple(engine.name for engine in engines)
    return bool(names) and len(names) == len(set(names))


class _FingerprintSelection(Protocol):
    @property
    def writer(self) -> str: ...

    @property
    def writer_version(self) -> str: ...

    @property
    def reader(self) -> str: ...

    @property
    def reader_version(self) -> str: ...

    @property
    def writer_profile(self) -> object | None: ...


class _WriterExecution(Protocol):
    @property
    def writer(self) -> EngineVersion: ...

    @property
    def writer_profile(self) -> object | None: ...


class _WriterProfilePlan(Protocol):
    def executions(self, writers: tuple[EngineVersion, ...]) -> Iterable[_WriterExecution]: ...


class FingerprintSelectionIssue(StrEnum):
    WRITER = "writer"
    READER = "reader"
    PROFILE_PLAN = "profile_plan"
    PROFILE = "profile"


def fingerprint_selection_issue(
    fingerprint: _FingerprintSelection,
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    writer_profiles: _WriterProfilePlan | None,
) -> FingerprintSelectionIssue | None:
    writer_versions = {engine.name: engine.version for engine in writers}
    if writer_versions.get(fingerprint.writer) != fingerprint.writer_version:
        return FingerprintSelectionIssue.WRITER
    if writer_profiles is None:
        if fingerprint.writer_profile is not None:
            return FingerprintSelectionIssue.PROFILE_PLAN
    elif not any(
        item.writer.name == fingerprint.writer
        and item.writer.version == fingerprint.writer_version
        and item.writer_profile == fingerprint.writer_profile
        for item in writer_profiles.executions(writers)
    ):
        return FingerprintSelectionIssue.PROFILE
    if fingerprint.reader == "*":
        return None
    reader_versions = {engine.name: engine.version for engine in readers}
    if reader_versions.get(fingerprint.reader) != fingerprint.reader_version:
        return FingerprintSelectionIssue.READER
    return None


__all__ = [
    "DependencyVersion",
    "DifferenceEvidence",
    "EngineVersion",
    "EnvironmentEvidence",
    "FingerprintSelectionIssue",
    "ReplayClassification",
    "capture_environment",
    "engine_selection_is_valid",
    "engine_versions_from_data",
    "fingerprint_selection_issue",
    "provider_inventory_matches",
]
