from __future__ import annotations

import stat
from enum import Enum
from pathlib import Path


class EvidenceTarget(Enum):
    GENERATED_RUN = "generated_run"
    SCAN_RUN = "scan_run"
    FINDING = "finding"


class EvidenceTargetError(ValueError):
    def __init__(self, reason: str, error: OSError | None = None) -> None:
        self.reason = reason
        self.error = error
        super().__init__(reason)


def classify_evidence_target(path: Path) -> EvidenceTarget:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise EvidenceTargetError("missing", error) from error
    except OSError as error:
        raise EvidenceTargetError("unreadable", error) from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise EvidenceTargetError("not_directory")
    try:
        names = {item.name for item in path.iterdir()}
    except OSError as error:
        raise EvidenceTargetError("unreadable", error) from error
    if {"run.json", "scan.json"} <= names:
        raise EvidenceTargetError("conflicting_runs")
    if "run.json" in names:
        return EvidenceTarget.GENERATED_RUN
    if "scan.json" in names:
        return EvidenceTarget.SCAN_RUN
    if "finding.json" in names:
        return EvidenceTarget.FINDING
    raise EvidenceTargetError("unrecognized")


__all__ = ["EvidenceTarget", "EvidenceTargetError", "classify_evidence_target"]
