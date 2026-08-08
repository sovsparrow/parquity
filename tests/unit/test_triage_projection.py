from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from parquity.findings import OPTIONAL_INPUT, REQUIRED_ARTIFACTS
from parquity.findings.bundle import ValidatedBundle
from parquity.findings.evidence import (
    EXAMPLE_BOUND_REACHED,
    DependencyVersion,
    DiscoveryEvidence,
    EnvironmentEvidence,
    ReductionEvidence,
    capture_environment,
)
from parquity.findings.matrix import MatrixRecord
from parquity.findings.model import ArtifactDigest, FindingRecord, ReplaySignature, finding_id_for
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.scans.bundle import ValidatedScanFinding
from parquity.scans.records import ScanFindingRecord
from parquity.triage.adapters import generated_child_occurrences, scan_child_occurrences
from parquity.triage.model import (
    FAMILY_FORMAT,
    Occurrence,
    Signal,
    group_occurrences,
)
from parquity.verdicts import CellResult, EngineVersion, Verdict

DepCase = tuple[tuple[EngineVersion, ...], tuple[DependencyVersion, ...]]


def _generated_child(
    case: Case,
    result: CellResult,
    directory: Path,
    *,
    input_bytes: int = 20,
) -> ValidatedBundle:
    fingerprint = result.fingerprint
    assert fingerprint is not None
    writers = (EngineVersion(result.writer, result.writer_version),)
    readers = (EngineVersion(result.reader, result.reader_version),)
    providers = (*writers, *readers)
    dependencies = (DependencyVersion("pyarrow", "1"),)
    reduction = ReductionEvidence(case.case_id, case.case_id, False, 0, 0, 0, 0, 0)
    names = tuple(sorted((*REQUIRED_ARTIFACTS, OPTIONAL_INPUT)))
    artifacts = tuple(
        ArtifactDigest(name, str(index) * 64, input_bytes if name == OPTIONAL_INPUT else index)
        for index, name in enumerate(names, start=1)
    )
    record = FindingRecord(
        finding_id_for(case.case_id, fingerprint),
        case.case_id,
        "fuzz",
        writers,
        readers,
        DiscoveryEvidence(10, 0, 8, EXAMPLE_BOUND_REACHED),
        EnvironmentEvidence("0.1.0", "6.165.1", "3", "x", providers, dependencies),
        reduction,
        fingerprint,
        ReplaySignature.from_fingerprint(fingerprint),
        result,
        True,
        artifacts,
    )
    matrix = MatrixRecord(case.case_id, writers, readers, fingerprint, (fingerprint,), (result,))
    return ValidatedBundle(record, case, case, matrix, directory)


def _scan_child(
    finding_id: str,
    source_path: str,
    outcomes: Sequence[Mapping[str, object]],
    groups: Sequence[Mapping[str, object]],
    comparisons: Sequence[Mapping[str, object]],
    engines: tuple[EngineVersion, ...],
    *,
    timeout: int = 30,
) -> ValidatedScanFinding:
    data: dict[str, object] = {
        "outcomes": list(outcomes),
        "observation_groups": list(groups),
        "comparisons": list(comparisons),
    }
    record = ScanFindingRecord(
        data, finding_id, source_path, "a" * 64, 100, engines, timeout, "b" * 64, "0.1.0"
    )
    return ValidatedScanFinding(record, Path("unused") / source_path)


def _success(engine: str, version: str, group: str) -> dict[str, object]:
    return {
        "engine": engine,
        "version": version,
        "kind": "SUCCESS",
        "diagnostic_kind": "SUCCESS",
        "detail": "",
    }


def _comparison(left: str, right: str, kind: str, path: str, detail: str) -> dict[str, object]:
    return {
        "left_group": left,
        "right_group": right,
        "kind": kind,
        "path": path,
        "detail": detail,
    }


def test_generated_projection_ignores_names_rows_locations_and_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {"parquity": "0.1.0", "hypothesis": "6", "pyarrow": "1", "pandas": "3"}
    monkeypatch.setattr("parquity.findings.evidence.metadata.version", versions.__getitem__)
    dependencies = (DependencyVersion("pyarrow", "1"), DependencyVersion("pandas", "3"))
    providers = (EngineVersion("pyarrow", "1"), EngineVersion("fastparquet", "2"))
    environment = capture_environment(providers)
    assert environment.dependencies == dependencies
    assert capture_environment(providers[:1]).dependencies == dependencies[:1]
    assert EnvironmentEvidence.from_data(environment.to_data()) == environment
    dependencies, inventory = environment.dependencies, environment.providers
    invalid: tuple[DepCase, ...] = ((inventory, ()), (inventory, dependencies * 2))
    invalid += ((providers[:1], dependencies), (inventory, dependencies[:1]))
    invalid += ((inventory, tuple(reversed(dependencies))),)
    invalid += ((providers[:1], (DependencyVersion("pyarrow", "9"),)),)
    for inventory, values in invalid:
        with pytest.raises(ValueError):
            replace(environment, providers=inventory, dependencies=values)
    with pytest.raises(ValueError):
        DependencyVersion("unknown", "1")
    first_case = Case((Field("alpha", TypeSpec(Kind.INT32)),), ((1,),))
    second_case = Case(
        (Field("beta", TypeSpec(Kind.INT32)),), tuple((index,) for index in range(8))
    )
    first_result = CellResult(
        "writer",
        "1",
        "reader",
        "2",
        "compare",
        Verdict.VALUE_MISMATCH,
        "$rows[0].alpha",
        "inside <parquity-temp>/evaluation value 7",
    )
    second_result = CellResult(
        "writer",
        "9",
        "reader",
        "8",
        "compare",
        Verdict.VALUE_MISMATCH,
        "$rows[7].beta",
        r"inside <parquity-temp>\evaluation value 7",
    )
    occurrences = generated_child_occurrences(
        (
            _generated_child(first_case, first_result, Path("one"), input_bytes=30),
            _generated_child(second_case, second_result, Path("elsewhere"), input_bytes=20),
        )
    )
    families = group_occurrences(occurrences)
    assert occurrences[0].projection == occurrences[1].projection
    assert len(families) == 1
    assert group_occurrences(tuple(reversed(occurrences))) == families
    family = families[0]
    assert family.signal is Signal.VALUE_DIFFERENCE
    assert {item.finding_id for item in family.occurrences} == {
        item.finding_id for item in occurrences
    }
    data = family.to_data()
    provider_data = cast(dict[str, object], data["observed_versions"])["providers"]
    observed_versions = {
        version
        for item in cast(list[dict[str, object]], provider_data)
        for version in cast(list[str], item["versions"])
    }
    assert observed_versions == {"1", "2", "8", "9"}
    assert data["projection_version"] == FAMILY_FORMAT
    assert data["signal"] == "VALUE_DIFFERENCE"
    assert all(item.occurrence_id != item.finding_id for item in occurrences)
    assert all(
        item.to_data()["occurrence_format"] == "parquity.triage-occurrence.v1"
        for item in occurrences
    )
    assert data["novelty_state"] == "UNAVAILABLE"
    assert occurrences[0].package_versions == (
        ("hypothesis", "6.165.1"),
        ("parquity", "0.1.0"),
        ("pyarrow", "1"),
    )


def test_generated_relevant_shape_and_diagnostic_changes_split() -> None:
    case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))
    result = CellResult(
        "writer",
        "1",
        "reader",
        "2",
        "compare",
        Verdict.VALUE_MISMATCH,
        "$rows[0].value",
        "expected 1, got 2",
    )
    original = generated_child_occurrences((_generated_child(case, result, Path("base")),))[0]
    changed_case = Case((Field("value", TypeSpec(Kind.STRING)),), (("1",),))
    changed_shape = generated_child_occurrences(
        (
            _generated_child(
                changed_case, replace(result, schema_path="$rows[0].value"), Path("shape")
            ),
        )
    )[0]
    diagnostics = cast(list[dict[str, object]], original.projection["diagnostics"])
    mutations: list[Occurrence] = []
    for key, value in (
        ("diagnostic_kind", "OtherError"),
        ("detail_sha256", "f" * 64),
        ("verdict", "SCHEMA_MISMATCH"),
    ):
        changed = {**diagnostics[0], key: value}
        mutations.append(
            replace(original, projection={**original.projection, "diagnostics": [changed]})
        )
    mutations.extend(
        (
            replace(original, projection={**original.projection, "operation": "read"}),
            replace(
                original,
                projection={
                    **original.projection,
                    "engine_roles": [{"engine": "other", "role": "reader"}],
                },
            ),
            replace(
                original,
                signal=Signal.SCHEMA_DIFFERENCE,
                projection={**original.projection, "signal": "SCHEMA_DIFFERENCE"},
            ),
            changed_shape,
        )
    )
    uniquely_identified = tuple(
        replace(
            occurrence,
            occurrence_id=f"{index:064x}",
            finding_id=f"{index:064x}",
        )
        for index, occurrence in enumerate((original, *mutations), start=1)
    )
    families = group_occurrences(uniquely_identified)
    assert len(families) == 8
    assert tuple(family.family_id for family in families) == tuple(
        sorted(family.family_id for family in families)
    )


def test_scan_projection_fans_out_and_is_order_version_and_group_invariant() -> None:
    first_outcomes: list[dict[str, object]] = [
        _success("a", "1", "group-1"),
        _success("b", "1", "group-2"),
        _success("c", "1", "group-3"),
        {
            "engine": "d",
            "version": "1",
            "kind": "PROVIDER_ERROR",
            "diagnostic_kind": "ControlledError",
            "detail": "retained 17",
        },
    ]
    first_groups: list[dict[str, object]] = [
        {"id": "group-1", "engines": ["a"]},
        {"id": "group-2", "engines": ["b"]},
        {"id": "group-3", "engines": ["c"]},
    ]
    first_comparisons: list[dict[str, object]] = [
        _comparison("group-1", "group-2", "VALUE_DIFFERENCE", "$.rows[0].columns[2]", "a-b"),
        _comparison("group-1", "group-3", "SCHEMA_DIFFERENCE", "$.schema.fields[4]", "a-c"),
        _comparison("group-2", "group-3", "SCHEMA_DIFFERENCE", "$.schema.fields[5]", "b-c"),
    ]
    remap = {"group-1": "group-3", "group-2": "group-1", "group-3": "group-2"}
    second_groups = [
        {"id": remap[cast(str, item["id"])], "engines": item["engines"]} for item in first_groups
    ]
    second_comparisons = [
        {
            **item,
            "left_group": remap[cast(str, item["left_group"])],
            "right_group": remap[cast(str, item["right_group"])],
        }
        for item in first_comparisons
    ]
    first = _scan_child(
        "1" * 64,
        "one.parquet",
        first_outcomes,
        second_groups,
        second_comparisons,
        tuple(EngineVersion(name, "1") for name in ("a", "b", "c", "d")),
    )
    second = _scan_child(
        "2" * 64,
        "nested/two.parquet",
        [{**item, "version": "9"} for item in first_outcomes],
        first_groups,
        first_comparisons,
        tuple(EngineVersion(name, "9") for name in ("d", "c", "b", "a")),
    )
    occurrences = scan_child_occurrences((first, second))
    assert len(occurrences) == 8
    assert {item.signal for item in occurrences} == {
        Signal.PROVIDER_ERROR,
        Signal.VALUE_DIFFERENCE,
        Signal.SCHEMA_DIFFERENCE,
    }
    by_finding = {
        finding_id: tuple(item for item in occurrences if item.finding_id == finding_id)
        for finding_id in ("1" * 64, "2" * 64)
    }
    assert all(len(items) == 4 for items in by_finding.values())
    first_projection = {
        item.signal.value + str(item.normalized_location): item.projection
        for item in by_finding["1" * 64]
    }
    second_projection = {
        item.signal.value + str(item.normalized_location): item.projection
        for item in by_finding["2" * 64]
    }
    assert first_projection == second_projection
    assert len(group_occurrences(occurrences)) == 4
    base = next(
        item
        for item in occurrences
        if item.finding_id == "1" * 64 and item.signal is Signal.PROVIDER_ERROR
    )
    changed_roster = replace(
        base,
        occurrence_id="0" * 64,
        projection={**base.projection, "reader_roster": ["a", "b", "c", "d", "x"]},
    )
    assert len(group_occurrences((base, changed_roster))) == 2
