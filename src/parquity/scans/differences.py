from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_INDEX = r"(?:0|[1-9][0-9]*)"
_PERSISTED_PATHS = {
    "SCHEMA_DIFFERENCE": re.compile(rf"\$\.schema(?:\.fields\[{_INDEX}\])?"),
    "ROW_COUNT_DIFFERENCE": re.compile(r"\$\.rows"),
    "VALUE_DIFFERENCE": re.compile(rf"\$\.rows\[{_INDEX}\]\.columns\[{_INDEX}\]"),
}
_NORMALIZED_PATHS = {
    "SCHEMA_DIFFERENCE": _PERSISTED_PATHS["SCHEMA_DIFFERENCE"],
    "ROW_COUNT_DIFFERENCE": _PERSISTED_PATHS["ROW_COUNT_DIFFERENCE"],
    "VALUE_DIFFERENCE": re.compile(rf"\$\.rows\[\*\]\.columns\[{_INDEX}\]"),
}
_ROW_INDEX = re.compile(rf"(?<=\$\.rows)\[{_INDEX}\]")


class DifferenceKind(StrEnum):
    SCHEMA_DIFFERENCE = "SCHEMA_DIFFERENCE"
    ROW_COUNT_DIFFERENCE = "ROW_COUNT_DIFFERENCE"
    VALUE_DIFFERENCE = "VALUE_DIFFERENCE"


@dataclass(frozen=True, slots=True)
class ScanDifference:
    kind: DifferenceKind
    path: str

    @classmethod
    def from_persisted(cls, kind: object, path: object) -> ScanDifference:
        return cls._parse(kind, path, normalized=False)

    @classmethod
    def from_normalized(cls, kind: object, path: object) -> ScanDifference:
        return cls._parse(kind, path, normalized=True)

    @classmethod
    def _parse(cls, kind: object, path: object, *, normalized: bool) -> ScanDifference:
        try:
            typed_kind = DifferenceKind(kind)
        except (TypeError, ValueError) as error:
            raise ValueError("scan difference kind is malformed") from error
        if not isinstance(path, str):
            raise ValueError("scan difference path is malformed")
        patterns = _NORMALIZED_PATHS if normalized else _PERSISTED_PATHS
        if patterns[typed_kind.value].fullmatch(path) is None:
            raise ValueError("scan difference kind and path conflict")
        return cls(typed_kind, path)

    def normalized(self) -> ScanDifference:
        path = (
            _ROW_INDEX.sub("[*]", self.path, count=1)
            if self.kind is DifferenceKind.VALUE_DIFFERENCE
            else self.path
        )
        return self.from_normalized(self.kind, path)


__all__ = ["DifferenceKind", "ScanDifference"]
