from __future__ import annotations

import platform
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata

from ..generation import MAX_FINDINGS, MAX_SEED
from ..model import Case
from ..verdicts import EngineVersion
from . import json_codec as codec

CHECK_COMPLETE = "CHECK_COMPLETE"
EXAMPLE_BOUND_REACHED = "EXAMPLE_BOUND_REACHED"
FINDING_CAP_REACHED = "FINDING_CAP_REACHED"
DISCOVERY_OVERFLOW = "DISCOVERY"
MINIMIZATION_OVERFLOW = "MINIMIZATION"
DEPENDENCY_ORDER = ("pyarrow", "pandas")


@dataclass(frozen=True, slots=True)
class GenerationEvidence:
    profile: str
    schema_case_id: str

    def __post_init__(self) -> None:
        if self.profile != "schema":
            raise codec.FindingValidationError("generation profile is not recognized")
        _validate_sha256(self.schema_case_id, "schema Case identity")

    def to_data(self) -> dict[str, object]:
        return {"profile": self.profile, "schema_case_id": self.schema_case_id}

    def binds(self, *cases: Case) -> bool:
        return all(Case(case.fields, ()).case_id == self.schema_case_id for case in cases)

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> GenerationEvidence:
        codec.require_exact_keys(data, {"profile", "schema_case_id"}, "generation evidence")
        return cls(
            codec.string(codec.required(data, "profile"), "generation profile"),
            codec.string(codec.required(data, "schema_case_id"), "schema_case_id"),
        )


@dataclass(frozen=True, slots=True)
class DiscoveryEvidence:
    examples: int | None
    seed: int | None
    max_findings: int | None
    stop_reason: str
    evaluated_cases: int | None = None
    evaluated_cells: int | None = None

    def __post_init__(self) -> None:
        if self.stop_reason == CHECK_COMPLETE:
            self._validate_check()
            return
        self._validate_fuzz()

    def _validate_check(self) -> None:
        if any(value is not None for value in (self.examples, self.seed, self.max_findings)):
            raise codec.FindingValidationError("check discovery evidence must not declare bounds")
        if self.evaluated_cases is not None or self.evaluated_cells is not None:
            raise codec.FindingValidationError("check discovery evidence declares counts")

    def _validate_fuzz(self) -> None:
        if self.stop_reason not in (EXAMPLE_BOUND_REACHED, FINDING_CAP_REACHED):
            raise codec.FindingValidationError("discovery stop reason is not recognized")
        if self.examples is None or self.examples < 1:
            raise codec.FindingValidationError("fuzz discovery requires a positive example bound")
        if self.seed is None or not 0 <= self.seed <= MAX_SEED:
            raise codec.FindingValidationError("fuzz discovery seed is outside the supported range")
        if self.max_findings is None or not 1 <= self.max_findings <= MAX_FINDINGS:
            raise codec.FindingValidationError("fuzz discovery finding cap is outside the range")
        if (self.evaluated_cases is None) != (self.evaluated_cells is None):
            raise codec.FindingValidationError("fuzz discovery counts must be recorded together")
        if any(isinstance(value, bool) for value in (self.evaluated_cases, self.evaluated_cells)):
            raise codec.FindingValidationError("fuzz discovery counts must be integers")
        if self.evaluated_cases is not None and not 1 <= self.evaluated_cases <= self.examples:
            raise codec.FindingValidationError("evaluated Case count is outside the example bound")
        if (
            self.evaluated_cases is not None
            and self.evaluated_cells is not None
            and self.evaluated_cells < self.evaluated_cases
        ):
            raise codec.FindingValidationError(
                "evaluated cell count is smaller than the Case count"
            )

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "examples": self.examples,
            "seed": self.seed,
            "max_findings": self.max_findings,
            "stop_reason": self.stop_reason,
        }
        if self.evaluated_cases is not None:
            data["evaluated_cases"] = self.evaluated_cases
            data["evaluated_cells"] = self.evaluated_cells
        return data

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> DiscoveryEvidence:
        keys = {"examples", "seed", "max_findings", "stop_reason"}
        has_counts = "evaluated_cases" in data or "evaluated_cells" in data
        if has_counts:
            keys.update(("evaluated_cases", "evaluated_cells"))
        codec.require_exact_keys(data, keys, "discovery evidence")
        return cls(
            codec.optional_integer(codec.required(data, "examples"), "examples"),
            codec.optional_integer(codec.required(data, "seed"), "seed"),
            codec.optional_integer(codec.required(data, "max_findings"), "max_findings"),
            codec.string(codec.required(data, "stop_reason"), "stop_reason"),
            (
                codec.integer(codec.required(data, "evaluated_cases"), "evaluated_cases")
                if has_counts
                else None
            ),
            (
                codec.integer(codec.required(data, "evaluated_cells"), "evaluated_cells")
                if has_counts
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class DependencyVersion:
    package: str
    version: str

    def __post_init__(self) -> None:
        if self.package not in DEPENDENCY_ORDER or not self.version:
            raise codec.FindingValidationError("dependency evidence is malformed")

    def to_data(self) -> dict[str, object]:
        return {"package": self.package, "version": self.version}

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> DependencyVersion:
        codec.require_exact_keys(data, {"package", "version"}, "dependency evidence")
        return cls(
            codec.string(codec.required(data, "package"), "dependency package"),
            codec.string(codec.required(data, "version"), "dependency version"),
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
            raise codec.FindingValidationError("environment evidence fields must not be empty")
        names = [provider.name for provider in self.providers]
        if not names or len(names) != len(set(names)):
            raise codec.FindingValidationError("environment providers must be unique")
        expected = ("pyarrow",) + (("pandas",) if "fastparquet" in names else ())
        dependency_names = tuple(item.package for item in self.dependencies)
        if dependency_names != expected:
            raise codec.FindingValidationError("environment dependencies are not canonical")
        provider_versions = {provider.name: provider.version for provider in self.providers}
        dependency_versions = {item.package: item.version for item in self.dependencies}
        if (
            "pyarrow" in provider_versions
            and provider_versions["pyarrow"] != dependency_versions["pyarrow"]
        ):
            raise codec.FindingValidationError("PyArrow provider and dependency versions differ")

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
        codec.require_exact_keys(data, keys, "environment evidence")
        return cls(
            codec.string(codec.required(data, "parquity_version"), "parquity_version"),
            codec.string(codec.required(data, "hypothesis_version"), "hypothesis_version"),
            codec.string(codec.required(data, "python_version"), "python_version"),
            codec.string(codec.required(data, "platform"), "platform"),
            tuple(
                engine_version_from_data(codec.mapping(value, "provider"))
                for value in codec.sequence(codec.required(data, "providers"), "providers")
            ),
            tuple(
                DependencyVersion.from_data(codec.mapping(value, "dependency"))
                for value in codec.sequence(codec.required(data, "dependencies"), "dependencies")
            ),
        )


@dataclass(frozen=True, slots=True)
class ReductionEvidence:
    discovered_case_id: str
    minimized_case_id: str
    hypothesis_reduced: bool
    fields: int
    rows: int
    nullability: int
    containers: int
    scalars: int

    def __post_init__(self) -> None:
        _validate_sha256(self.discovered_case_id, "discovered Case identity")
        _validate_sha256(self.minimized_case_id, "minimized Case identity")
        counts = (self.fields, self.rows, self.nullability, self.containers, self.scalars)
        if any(isinstance(value, bool) or value < 0 for value in counts):
            raise codec.FindingValidationError("reduction counts must not be negative")

    @property
    def total(self) -> int:
        return self.fields + self.rows + self.nullability + self.containers + self.scalars

    def to_data(self) -> dict[str, object]:
        return {
            "discovered_case_id": self.discovered_case_id,
            "minimized_case_id": self.minimized_case_id,
            "hypothesis_reduced": self.hypothesis_reduced,
            "successful_reductions": {
                "fields": self.fields,
                "rows": self.rows,
                "nullability": self.nullability,
                "containers": self.containers,
                "scalars": self.scalars,
                "total": self.total,
            },
        }

    @classmethod
    def from_data(cls, data: Mapping[str, object]) -> ReductionEvidence:
        keys = {
            "discovered_case_id",
            "minimized_case_id",
            "hypothesis_reduced",
            "successful_reductions",
        }
        codec.require_exact_keys(data, keys, "reduction evidence")
        counts = codec.mapping(codec.required(data, "successful_reductions"), "reductions")
        codec.require_exact_keys(
            counts, {"fields", "rows", "nullability", "containers", "scalars", "total"}, "counts"
        )
        result = cls(
            codec.string(codec.required(data, "discovered_case_id"), "discovered_case_id"),
            codec.string(codec.required(data, "minimized_case_id"), "minimized_case_id"),
            codec.boolean(codec.required(data, "hypothesis_reduced"), "hypothesis_reduced"),
            codec.integer(codec.required(counts, "fields"), "fields"),
            codec.integer(codec.required(counts, "rows"), "rows"),
            codec.integer(codec.required(counts, "nullability"), "nullability"),
            codec.integer(codec.required(counts, "containers"), "containers"),
            codec.integer(codec.required(counts, "scalars"), "scalars"),
        )
        if codec.integer(codec.required(counts, "total"), "total") != result.total:
            raise codec.FindingValidationError("reduction total does not match its categories")
        return result


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


def engine_version_from_data(data: Mapping[str, object]) -> EngineVersion:
    codec.require_exact_keys(data, {"name", "version"}, "engine version")
    try:
        return EngineVersion(
            codec.string(codec.required(data, "name"), "engine name"),
            codec.string(codec.required(data, "version"), "engine version"),
        )
    except ValueError as error:
        raise codec.FindingValidationError("engine version evidence is malformed") from error


def provider_inventory_matches(
    writers: tuple[EngineVersion, ...],
    readers: tuple[EngineVersion, ...],
    providers: tuple[EngineVersion, ...],
) -> bool:
    if not writers or not readers:
        return False
    selected: dict[str, str] = {}
    for engines in (writers, readers):
        role_names: set[str] = set()
        for engine in engines:
            if engine.name in role_names:
                return False
            role_names.add(engine.name)
            current = selected.get(engine.name)
            if current is not None and current != engine.version:
                return False
            selected[engine.name] = engine.version
    inventory = {provider.name: provider.version for provider in providers}
    return len(inventory) == len(providers) and inventory == selected


def _validate_sha256(value: str, label: str) -> None:
    malformed = len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
    if malformed:
        raise codec.FindingValidationError(f"{label} must be a lowercase SHA-256 value")
