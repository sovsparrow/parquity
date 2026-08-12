import hashlib
import json
from pathlib import Path
from shlex import split as _words
from typing import Any, cast

import pytest

from parquity.evidence import DependencyVersion, EngineVersion, EnvironmentEvidence
from parquity.evidence.normalization import detail_sha256_v1
from parquity.scans import records, symptoms
from parquity.scans.bundle import build_finding
from parquity.scans.differences import DifferenceKind
from parquity.scans.observations import ObservationDifference as Difference
from parquity.scans.observations import ObservationGroup as Group
from parquity.scans.records import ReaderOutcomeKind
from parquity.scans.records import ReaderOutcomeRecord as Outcome
from tests.support.scan_observation_values import named_value_difference as _named_value_difference

FindingRecord, RecordError = records.ScanFindingRecord, records.ScanRecordError
_DEFAULT = Difference(
    "group-1",
    "group-2",
    DifferenceKind.VALUE_DIFFERENCE,
    "$.rows[0].columns[0]",
    "1 != 2",
)
_RECORD_MUTATIONS = _words(
    "member_order group_order comparison_kind comparison_path source_dot source_nul "
    "version_empty diagnostic_empty success_diagnostic success_detail"
)


def _reject(error: type[BaseException], function: Any, *args: Any) -> None:
    with pytest.raises(error):
        function(*args)


def _record_outcome(engine: str, group: str, marker: str) -> Outcome:
    status = (ReaderOutcomeKind.SUCCESS, "SUCCESS", "", "", False, 1, 1)
    return Outcome(engine, "1", *status, marker * 64, marker * 64, 16, group)


def _finding_document(directory: Path, comparison: Difference | None = None) -> dict[str, object]:
    difference = comparison or _DEFAULT
    engines = tuple(EngineVersion(name, "1") for name in ("pyarrow", "duckdb", "polars"))
    environment = EnvironmentEvidence(
        "0.1.0",
        "hypothesis",
        "3.12.0",
        "test-platform",
        engines,
        (DependencyVersion("pyarrow", "1"),),
    )
    build_finding(
        directory,
        environment=environment,
        source_path="input.parquet",
        input_payload=b"PAR1controlled",
        engines=engines,
        timeout_seconds=30,
        outcomes=(
            _record_outcome("pyarrow", "group-1", "a"),
            _record_outcome("duckdb", "group-1", "a"),
            _record_outcome("polars", "group-2", "b"),
        ),
        groups=(Group("group-1", ("pyarrow", "duckdb")), Group("group-2", ("polars",))),
        comparisons=(difference,),
    )
    return cast(dict[str, object], json.loads((directory / "finding.json").read_bytes()))


def _reseal_finding(document: dict[str, object]) -> None:
    data, source = cast(dict[str, Any], document), cast(dict[str, Any], document["source"])
    source_identity = (source["path"], source["sha256"], source["bytes"])
    evidence = tuple(tuple(data[key]) for key in ("outcomes", "observation_groups", "comparisons"))
    identity = records.signature(
        *source_identity,
        tuple(item["name"] for item in data["engines"]),
        data["timeout_seconds"],
        *evidence,
    )
    document["signature_sha256"] = identity
    payload = records.canonical_bytes({"signature": identity})
    document["finding_id"] = hashlib.sha256(payload).hexdigest()


def test_empty_name_difference_validates_complete_finding(tmp_path: Path) -> None:
    document = _finding_document(tmp_path / "empty-name", _named_value_difference(""))
    _reseal_finding(document)
    record = FindingRecord.from_json(records.canonical_bytes(document))
    comparison = cast(list[dict[str, object]], record.data["comparisons"])[0]
    assert comparison["path"] == "$.rows[0].columns[0]"
    assert comparison["detail"] == "column '': 1 != 2"


@pytest.mark.parametrize("mutation", _RECORD_MUTATIONS)
def test_resealed_impossible_evidence_is_rejected(tmp_path: Path, mutation: str) -> None:
    document = _finding_document(tmp_path / mutation)
    outcomes = cast(list[dict[str, object]], document["outcomes"])
    groups = cast(list[dict[str, object]], document["observation_groups"])
    comparison = cast(list[dict[str, object]], document["comparisons"])[0]
    if mutation == "member_order":
        cast(list[str], groups[0]["engines"]).reverse()
    elif mutation == "group_order":
        outcomes[0]["observation_group"] = "group-2"
        outcomes[1]["observation_group"] = "group-1"
        groups[0]["engines"] = ["duckdb"]
        groups[1]["engines"] = ["pyarrow", "polars"]
    elif mutation == "comparison_kind":
        comparison["kind"] = "UNSUPPORTED"
    elif mutation == "comparison_path":
        comparison["path"] = "$.rows[0].value"
    elif mutation.startswith("source_"):
        source = cast(dict[str, object], document["source"])
        source["path"] = "." if mutation == "source_dot" else "input\0.parquet"
    else:
        target, key, value = {
            "version_empty": (document, "parquity_version", ""),
            "diagnostic_empty": (outcomes[0], "diagnostic_kind", ""),
            "success_diagnostic": (outcomes[0], "diagnostic_kind", "OTHER"),
            "success_detail": (outcomes[0], "detail", "unexpected"),
        }[mutation]
        target[key] = value
    _reseal_finding(document)
    _reject(RecordError, FindingRecord.from_json, records.canonical_bytes(document))


def test_scan_difference_grammar_preserves_value_and_row_count_meaning(
    tmp_path: Path,
) -> None:
    cases = (
        (
            DifferenceKind.VALUE_DIFFERENCE,
            "$.rows[7].columns[2]",
            "$.rows[*].columns[2]",
        ),
        (DifferenceKind.ROW_COUNT_DIFFERENCE, "$.rows", "$.rows"),
    )
    for kind, path, normalized in cases:
        difference = Difference("group-1", "group-2", kind, path, "controlled")
        document = _finding_document(tmp_path / kind.name, difference)
        record = FindingRecord.from_json(records.canonical_bytes(document))
        persisted = cast(list[dict[str, object]], record.data["comparisons"])[0]
        symptom = symptoms.extract(record, detail_sha256_v1)[0]
        assert (persisted["kind"], persisted["path"]) == (kind.value, path)
        assert (symptom.signal, symptom.normalized_location) == (kind.value, normalized)

    document = _finding_document(tmp_path / "bare-row-value")
    comparison = cast(list[dict[str, object]], document["comparisons"])[0]
    comparison["path"] = "$.rows"
    _reseal_finding(document)
    _reject(RecordError, FindingRecord.from_json, records.canonical_bytes(document))


def test_persisted_reader_outcome_contract_is_typed_and_coupled() -> None:
    success = _record_outcome("reader", "group-1", "a")
    valid = (
        success,
        Outcome(
            "reader",
            "1",
            ReaderOutcomeKind.PROVIDER_ERROR,
            "ArrowInvalid",
            "invalid input",
            "provider stderr",
            False,
        ),
        Outcome(
            "reader",
            "1",
            ReaderOutcomeKind.PROCESS_ERROR,
            "PROCESS_CRASH",
            "process stderr",
            "process stderr",
            True,
        ),
        Outcome(
            "reader",
            "1",
            ReaderOutcomeKind.TIMEOUT,
            "TIMEOUT",
            "timeout stderr",
            "timeout stderr",
            False,
        ),
    )
    decoded = tuple(Outcome.from_data(item.to_data()) for item in valid)
    assert decoded == valid
    assert tuple(item.kind.name for item in decoded) == (
        "SUCCESS",
        "PROVIDER_ERROR",
        "PROCESS_ERROR",
        "TIMEOUT",
    )
    assert tuple(item.to_data()["kind"] for item in decoded) == (
        "SUCCESS",
        "PROVIDER_ERROR",
        "PROCESS_CRASH",
        "TIMEOUT",
    )

    success_data = success.to_data()
    process_data = valid[2].to_data()
    timeout_data = valid[3].to_data()
    invalid = (
        {**success_data, "kind": "UNKNOWN"},
        {**success_data, "kind": "PROVIDER_ERROR", "diagnostic_kind": "ArrowInvalid"},
        {**process_data, "detail": "different"},
        {**timeout_data, "diagnostic_kind": "DeadlineExceeded"},
    )
    for data in invalid:
        _reject(RecordError, Outcome.from_data, data)
