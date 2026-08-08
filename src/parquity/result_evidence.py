from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


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


def normalize_detail(detail: str, transient_roots: tuple[Path, ...] = ()) -> str:
    normalized = detail
    roots = sorted({str(path) for path in transient_roots}, key=len, reverse=True)
    for root in roots:
        normalized = normalized.replace(root, "<parquity-temp>")
    return " ".join(normalized.split())


__all__ = ["DifferenceEvidence", "EngineVersion", "normalize_detail"]
