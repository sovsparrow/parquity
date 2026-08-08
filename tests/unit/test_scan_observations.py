import hashlib
import json
from dataclasses import replace
from itertools import product
from pathlib import Path
from shlex import split as _words
from typing import Any, cast

import pyarrow as pa
import pyarrow.ipc as ipc
import pytest

from parquity.scans import records
from parquity.scans.bundle import build_finding
from parquity.scans.observations import (
    Observation,
    ObservationMetadata,
    encode_observation,
    group_observations,
    normalize_table,
)
from parquity.scans.observations import ObservationDifference as Difference
from parquity.scans.observations import ObservationError as Error
from parquity.scans.observations import ObservationGroup as Group
from parquity.scans.observations import decode_observation as decode
from parquity.scans.records import ReaderOutcomeRecord as Outcome
from parquity.verdicts import EngineVersion

FindingRecord, RecordError = records.ScanFindingRecord, records.ScanRecordError
_FAIL_FIELDS = _words("row_count column_count schema_sha256 ipc_sha256 ipc_bytes observation_group")
_FAILURE_CASES = tuple(product(("TIMEOUT", "PROCESS_CRASH"), ("diagnostic", "detail")))
_DEFAULT = Difference("group-1", "group-2", "VALUE_DIFFERENCE", "$.rows[0].columns[0]", "1 != 2")
_RECORD_MUTATIONS = _words(
    "member_order group_order comparison_kind comparison_path source_dot source_nul "
    "version_empty diagnostic_empty success_diagnostic success_detail"
)


def _field(container: object, index: int) -> "pa.Field[pa.DataType]":
    return cast(Any, container).field(index)


def _observation(engine: str, table: pa.Table) -> Observation:
    payload, metadata = encode_observation(table)
    return decode(engine, payload, metadata)


def _reject(error: type[BaseException], function: Any, *args: Any) -> None:
    with pytest.raises(error):
        function(*args)


def _float_shape(kind: str, value_type: pa.DataType, bits: int) -> "pa.Array[Any]":
    payload = bits.to_bytes(cast(int, cast(object, value_type.bit_width)) // 8, "little")
    values = pa.Array.from_buffers(value_type, 1, [None, pa.py_buffer(payload)])
    offsets = pa.array([0, 1], type=pa.int32())
    arrow = cast(Any, pa)
    shapes: dict[str, pa.Array[Any]] = {
        "scalar": values,
        "list": arrow.ListArray.from_arrays(offsets, values),
        "struct": arrow.StructArray.from_arrays([values], names=["leaf"]),
        "map": arrow.MapArray.from_arrays(offsets, pa.array(["key"]), values),
        "dictionary": arrow.DictionaryArray.from_arrays(pa.array([0], type=pa.int8()), values),
    }
    return shapes[kind]


def _assert_float_relation(case: tuple[str, pa.DataType, int, int, int, str]) -> None:
    kind, value_type, first_nan, second_nan, negative_zero, location = case

    def observe(engine: str, bits: int) -> Observation:
        array = _float_shape(kind, value_type, bits)
        return _observation(engine, pa.Table.from_arrays([array], names=["value"]))

    nans = group_observations((observe("first", first_nan), observe("second", second_nan)))
    assert nans.groups == (Group("group-1", ("first", "second")),)
    zeros = group_observations((observe("positive", 0), observe("negative", negative_zero)))
    difference = zeros.differences[0]
    assert len(zeros.groups) == 2 and difference.path == "$.rows[0].columns[0]"
    assert difference.detail.startswith("column 'value'")
    assert location == "$" or f" at {location}:" in difference.detail


def _legacy_map_table() -> pa.Table:
    item_field = pa.field("legacy_item", pa.string())
    map_type = pa.map_(pa.int64(), cast(pa.DataType, cast(object, item_field)))
    return pa.Table.from_arrays(
        [
            pa.array([[(1, "one")], None, []], type=map_type),
            pa.array([7, 8, 9], type=pa.int32()),
        ],
        names=["mapping", "ordinary"],
    )


def test_normalization_removes_only_top_level_metadata_and_chunking() -> None:
    field = pa.field("value", pa.int64(), metadata={b"field": b"preserved"})
    schema = pa.schema([field], metadata={b"top": b"removed"})
    chunks = pa.chunked_array([pa.array([1]), pa.array([2])])
    table = pa.Table.from_arrays([chunks], schema=schema)
    normalized = normalize_table(table)
    assert normalized.schema.metadata is None and normalized.column(0).num_chunks == 1
    assert _field(normalized.schema, 0).metadata == {b"field": b"preserved"}
    assert normalized.to_pylist() == [{"value": 1}, {"value": 2}]


def test_ipc_round_trip_binds_legacy_map_names_to_carrier_schema() -> None:
    normalized = normalize_table(_legacy_map_table())
    source_entries = _field(_field(normalized.schema, 0).type, 0)
    source_entry_fields = tuple(_field(source_entries.type, index) for index in range(2))
    payload, metadata = encode_observation(normalized)
    carrier_schema = ipc.open_file(pa.BufferReader(payload)).schema
    carrier_fields = tuple(_field(carrier_schema, index) for index in range(2))
    carrier_entries = _field(carrier_fields[0].type, 0)
    entry_fields = tuple(_field(carrier_entries.type, index) for index in range(2))
    assert tuple(field.name for field in source_entry_fields) == ("key", "legacy_item")
    assert tuple(field.name for field in entry_fields) == ("key", "value")
    assert not normalized.schema.equals(carrier_schema, check_metadata=True)
    observation = decode("pyarrow", payload, metadata)
    assert observation.table.schema.equals(carrier_schema, check_metadata=True)
    assert (observation.table.to_pylist(), observation.table.column_names) == (
        normalized.to_pylist(),
        ["mapping", "ordinary"],
    )
    assert (observation.table.num_rows, observation.table.num_columns) == (3, 2)
    assert (metadata.row_count, metadata.column_count, metadata.byte_count) == (3, 2, len(payload))
    assert metadata.sha256 == hashlib.sha256(payload).hexdigest()
    carrier_digest = hashlib.sha256(carrier_schema.serialize().to_pybytes()).hexdigest()
    source_digest = hashlib.sha256(normalized.schema.serialize().to_pybytes()).hexdigest()
    assert metadata.schema_sha256 == carrier_digest != source_digest
    assert tuple((field.type, field.nullable) for field in entry_fields) == (
        (pa.int64(), False),
        (pa.string(), True),
    )
    assert tuple(field.nullable for field in carrier_fields) == (True, True)
    assert carrier_fields[1] == _field(normalized.schema, 1)
    _reject(Error, decode, "pyarrow", payload + b"tamper", metadata)
    for mismatched in (
        replace(metadata, row_count=metadata.row_count + 1),
        replace(metadata, column_count=metadata.column_count + 1),
        replace(metadata, schema_sha256="0" * 64),
    ):
        _reject(Error, decode, "pyarrow", payload, mismatched)


def test_complete_equal_tables_share_one_stable_group() -> None:
    first = _observation("pyarrow", pa.table({"value": [1, 2]}))
    chunks = pa.chunked_array([pa.array([1]), pa.array([2])])
    second = _observation("duckdb", pa.Table.from_arrays([chunks], names=["value"]))
    grouped = group_observations((first, second))
    assert grouped.groups == (Group("group-1", ("pyarrow", "duckdb")),)
    assert grouped.differences == ()


def test_float_width_bits_define_grouping_and_first_difference() -> None:
    cases = (
        ("scalar", pa.float16(), 0x7E01, 0x7FFF, 0x8000, "$"),
        ("scalar", pa.float32(), 0x7FC00001, 0x7FC01234, 0x80000000, "$"),
        ("scalar", pa.float64(), 0x7FF8000000000001, 0x7FF8000000001234, 1 << 63, "$"),
        ("list", pa.float32(), 0x7FC00001, 0x7FC01234, 0x80000000, "$[0]"),
        ("struct", pa.float32(), 0x7FC00001, 0x7FC01234, 0x80000000, "$.fields[0]"),
        ("map", pa.float32(), 0x7FC00001, 0x7FC01234, 0x80000000, "$.entries[0].value"),
        ("dictionary", pa.float32(), 0x7FC00001, 0x7FC01234, 0x80000000, "$.dictionary"),
    )
    for case in cases:
        _assert_float_relation(case)


def test_schema_and_value_differences_create_complete_pair_evidence() -> None:
    left_raw, right_raw = 9223372036854775807, -4852191831933722624
    timestamp = pa.timestamp("ns")
    baseline = _observation("pyarrow", pa.table({"value": pa.array([left_raw], type=timestamp)}))
    schema = _observation("duckdb", pa.table({"value": pa.array([left_raw], type=pa.int64())}))
    value = _observation("polars", pa.table({"value": pa.array([right_raw], type=timestamp)}))
    grouped = group_observations((baseline, schema, value))
    assert [group.group_id for group in grouped.groups] == _words("group-1 group-2 group-3")
    kinds = tuple(item.kind for item in grouped.differences)
    assert kinds == tuple(_words("SCHEMA_DIFFERENCE VALUE_DIFFERENCE SCHEMA_DIFFERENCE"))
    value_difference = grouped.differences[1]
    expected = f"column 'value': timestamp[ns]({left_raw}) != timestamp[ns]({right_raw})"
    assert (value_difference.path, value_difference.detail) == ("$.rows[0].columns[0]", expected)


def test_grouping_does_not_accept_matching_hash_evidence_as_table_equality() -> None:
    first = _observation("first", pa.table({"value": [1]}))
    second = _observation("second", pa.table({"value": [2]}))
    forged = second._replace(metadata=first.metadata)
    grouped = group_observations((first, forged))
    assert (len(grouped.groups), grouped.differences[0].kind) == (2, "VALUE_DIFFERENCE")


def test_field_metadata_and_ordinary_struct_names_remain_semantic() -> None:
    left_field = pa.field("value", pa.int64(), metadata={b"side": b"left"})
    right_field = pa.field("value", pa.int64(), metadata={b"side": b"right"})
    observations = [
        _observation(
            side,
            pa.Table.from_arrays([pa.array([1])], schema=pa.schema([field])),
        )
        for side, field in (("left", left_field), ("right", right_field))
    ]

    def nested(engine: str, child_name: str, child_metadata: dict[bytes, bytes]) -> Observation:
        struct_type = pa.struct([pa.field(child_name, pa.int64(), metadata=child_metadata)])
        values = pa.array([{child_name: 1}], type=struct_type)
        return _observation(engine, pa.Table.from_arrays([values], names=["ordinary"]))

    observations += [
        nested("baseline", "child", {b"meaning": b"baseline"}),
        nested("renamed", "renamed", {b"meaning": b"baseline"}),
        nested("remetadata", "child", {b"meaning": b"changed"}),
    ]
    grouped = group_observations(tuple(observations))
    assert (len(grouped.groups), len(grouped.differences)) == (5, 10)
    assert {difference.kind for difference in grouped.differences} == {"SCHEMA_DIFFERENCE"}
    assert {difference.path for difference in grouped.differences} == {"$.schema.fields[0]"}


def test_invalid_metadata_and_well_digested_non_ipc_are_rejected() -> None:
    _reject(Error, ObservationMetadata, -1, "0" * 64, 0, 0, "0" * 64)
    _reject(Error, ObservationMetadata, 0, "invalid", 0, 0, "0" * 64)
    payload = b"not Arrow IPC"
    digest = hashlib.sha256(payload).hexdigest()
    metadata = ObservationMetadata(len(payload), digest, 0, 0, "0" * 64)
    _reject(Error, decode, "reader", payload, metadata)


def test_difference_walks_equal_columns_and_reports_field_count() -> None:
    left = _observation("left", pa.table({"same": [1], "changed": [2]}))
    right = _observation("right", pa.table({"same": [1], "changed": [3]}))
    values = group_observations((left, right)).differences[0]
    assert values.path == "$.rows[0].columns[1]"
    short = _observation("short", pa.table({"same": [1]}))
    schema = group_observations((short, left)).differences[0]
    assert (schema.kind, schema.detail) == ("SCHEMA_DIFFERENCE", "field count 1 != 2")
    longer = _observation("longer", pa.table({"same": [1, 2]}))
    rows = group_observations((short, longer)).differences[0]
    assert rows.kind == "ROW_COUNT_DIFFERENCE"
    assert rows.path == "$.rows" and rows.detail == "row count 1 != 2"


def _named_value_difference(name: str) -> Difference:
    left = _observation("left", pa.Table.from_arrays([pa.array([1])], names=[name]))
    right = _observation("right", pa.Table.from_arrays([pa.array([2])], names=[name]))
    return group_observations((left, right)).differences[0]


@pytest.mark.parametrize("name", ("", "a.b", "a[b]", "ünicode", "line\nbreak"))
def test_value_path_uses_column_index_and_keeps_field_name_in_detail(name: str) -> None:
    difference = _named_value_difference(name)
    assert difference.path == "$.rows[0].columns[0]"
    assert difference.detail == f"column {name!r}: 1 != 2"


def _record_outcome(engine: str, group: str, marker: str) -> Outcome:
    status = ("SUCCESS", "SUCCESS", "", "", False, 1, 1)
    return Outcome(engine, "1", *status, marker * 64, marker * 64, 16, group)


def _finding_document(directory: Path, comparison: Difference | None = None) -> dict[str, object]:
    difference = comparison or _DEFAULT
    build_finding(
        directory,
        parquity_version="0.1.0",
        source_path="input.parquet",
        input_payload=b"PAR1controlled",
        engines=tuple(EngineVersion(name, "1") for name in ("pyarrow", "duckdb", "polars")),
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


@pytest.mark.parametrize(("kind", "mutation"), _FAILURE_CASES)
def test_resealed_failure_conflicts_are_rejected(tmp_path: Path, kind: str, mutation: str) -> None:
    document = _finding_document(tmp_path / f"{kind}-{mutation}")
    outcomes = cast(list[dict[str, object]], document["outcomes"])
    failure = outcomes.pop()
    failure.update(kind=kind, diagnostic_kind=kind, detail="retained", stderr="retained")
    failure.update(dict.fromkeys(_FAIL_FIELDS))
    outcomes.append(failure)
    document["observation_groups"] = cast(list[object], document["observation_groups"])[:1]
    document["comparisons"] = []
    _reseal_finding(document)
    FindingRecord.from_json(records.canonical_bytes(document))
    failure["diagnostic_kind" if mutation == "diagnostic" else "detail"] = "conflict"
    _reseal_finding(document)
    _reject(RecordError, FindingRecord.from_json, records.canonical_bytes(document))
