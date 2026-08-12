from __future__ import annotations

from typing import cast

import pytest

from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.scans import limits, records
from parquity.scans.discovery import MAX_VISITED_ENTRIES


def _run_record() -> dict[str, object]:
    finding_id = "f" * 64
    engines = (EngineVersion("pyarrow", "1"),)
    environment = EnvironmentEvidence(
        "0.1.0",
        "hypothesis",
        "3.12.0",
        "test-platform",
        engines,
        (DependencyVersion("pyarrow", "1"),),
    )
    data: dict[str, object] = {
        "format": records.SCAN_RUN_FORMAT,
        "scan_id": "",
        "parquity_version": "0.1.0",
        "environment": environment.to_data(),
        "status": "FINDINGS_FOUND",
        "input_kind": "directory",
        "discovery": {
            "files": [{"path": "a.parquet", "bytes": 1}, {"path": "b.parquet", "bytes": 1}],
            "skipped_symlinks": 0,
            "total_bytes": 2,
            "visited_entries": 3,
        },
        "limits": limits.SCAN_LIMITS,
        "engines": [item.to_data() for item in engines],
        "timeout_seconds": 30,
        "max_saved": 1,
        "stop_reason": "FINDINGS_FOUND",
        "findings": [
            {
                "finding_id": finding_id,
                "source_path": "b.parquet",
                "manifest": {
                    "path": f"findings/{finding_id}/finding.json",
                    "sha256": "a" * 64,
                    "bytes": 1,
                },
            }
        ],
        "overflow": [],
        "report": {"path": "REPORT.md", "sha256": "b" * 64, "bytes": 1},
    }
    data["scan_id"] = records.scan_id(data)
    assert records.ScanRunRecord.from_json(records.canonical_bytes(data)).data == data
    return data


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_path",
        "file_kind",
        "dot_path",
        "nul_path",
        "empty_version",
        "unmarked_overflow",
        "omitted_suffix",
        "visited_entries",
        "environment",
    ),
)
def test_run_record_rejects_resealed_impossible_run_relations(mutation: str) -> None:
    data = _run_record()
    discovery = cast(dict[str, object], data["discovery"])
    if mutation == "duplicate_path":
        files = cast(list[dict[str, object]], discovery["files"])
        files.append(dict(files[-1]))
        discovery["total_bytes"] = 3
    elif mutation == "file_kind":
        data["input_kind"] = "file"
    elif mutation == "empty_version":
        data["parquity_version"] = ""
    elif mutation == "unmarked_overflow":
        cast(list[dict[str, object]], data["findings"])[0]["source_path"] = "a.parquet"
        data["overflow"] = ["b.parquet"]
    elif mutation == "omitted_suffix":
        cast(list[dict[str, object]], data["findings"])[0]["source_path"] = "a.parquet"
    elif mutation == "visited_entries":
        discovery["visited_entries"] = MAX_VISITED_ENTRIES + 1
    elif mutation == "environment":
        environment = cast(dict[str, object], data["environment"])
        environment["parquity_version"] = "different"
    else:
        path = "." if mutation == "dot_path" else "a\0.parquet"
        cast(list[dict[str, object]], discovery["files"])[0]["path"] = path
        cast(list[dict[str, object]], data["findings"])[0]["source_path"] = path
    data["scan_id"] = ""
    data["scan_id"] = records.scan_id(data)

    with pytest.raises(records.ScanRecordError):
        records.ScanRunRecord.from_json(records.canonical_bytes(data))


def test_overflow_status_policy_produces_both_states_and_rejects_resealed_conflicts() -> None:
    assert records.status_for_overflow(()) is records.ScanRunStatus.FINDINGS_FOUND
    assert records.status_for_overflow(("b.parquet",)) is (
        records.ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED
    )
    assert (
        records.status_to_v1(records.ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED)
        == "FINDING_CAP_REACHED"
    )
    assert records.status_from_v1("FINDING_CAP_REACHED") is (
        records.ScanRunStatus.SAVED_EVIDENCE_LIMIT_REACHED
    )

    overflow = _run_record()
    cast(list[dict[str, object]], overflow["findings"])[0]["source_path"] = "a.parquet"
    overflow["overflow"] = ["b.parquet"]
    expected = records.status_for_overflow(("b.parquet",)).value
    overflow["status"] = overflow["stop_reason"] = expected
    overflow["scan_id"] = ""
    overflow["scan_id"] = records.scan_id(overflow)
    assert records.ScanRunRecord.from_json(records.canonical_bytes(overflow)).data == overflow

    overflow["status"] = overflow["stop_reason"] = records.ScanRunStatus.FINDINGS_FOUND.value
    overflow["scan_id"] = ""
    overflow["scan_id"] = records.scan_id(overflow)
    with pytest.raises(records.ScanRecordError):
        records.ScanRunRecord.from_json(records.canonical_bytes(overflow))
