from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pytest

import parquity.cli as cli
from parquity.engines import EngineSelection, EngineSelectionError
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, EngineAvailability, EngineVersion, MatrixRun, Verdict


class _WorkflowModule(Protocol):
    evaluate_selected_case: Callable[[Case, Path, EngineSelection], MatrixRun]


class _MainModule(Protocol):
    resolve_engine_selection: Callable[
        [str | Sequence[str] | None, str | Sequence[str] | None], EngineSelection
    ]


def _case() -> Case:
    return Case((Field("value", TypeSpec(Kind.INT32), nullable=False),), ((1,),))


def _write_case(path: Path) -> None:
    path.write_bytes(_case().canonical_bytes())


def _versions(
    selection: EngineSelection,
) -> tuple[tuple[EngineVersion, ...], tuple[EngineVersion, ...]]:
    return (
        tuple(
            EngineVersion(engine.identity.name, engine.identity.version)
            for engine in selection.writers
        ),
        tuple(
            EngineVersion(engine.identity.name, engine.identity.version)
            for engine in selection.readers
        ),
    )


def _cell(
    writer: EngineVersion, reader: EngineVersion, verdict: Verdict, detail: str
) -> CellResult:
    return CellResult(
        writer.name,
        writer.version,
        reader.name,
        reader.version,
        "compare",
        verdict,
        "$rows[0].value",
        detail,
    )


def _complete(
    selection: EngineSelection, failures: tuple[CellResult, ...] = ()
) -> tuple[CellResult, ...]:
    writers, readers = _versions(selection)
    cells = {(item.writer, item.reader): item for item in failures}
    return tuple(
        cells.get(
            (writer.name, reader.name),
            _cell(writer, reader, Verdict.PASS, "match"),
        )
        for writer in writers
        for reader in readers
    )


def _one_failure(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    directory.mkdir(parents=True)
    selected_writer = selection.writers[0].identity
    path = directory / f"{selected_writer.name}.parquet"
    path.write_bytes(b"PAR1selectedPAR1")
    writers, readers = _versions(selection)
    result = _cell(writers[0], readers[0], Verdict.VALUE_MISMATCH, "selected controlled mismatch")
    return MatrixRun(
        case.case_id,
        _complete(selection, (result,)),
        ((selected_writer.name, path),),
        writers,
        readers,
    )


def _pass(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    del directory
    writers, readers = _versions(selection)
    return MatrixRun(case.case_id, _complete(selection), (), writers, readers)


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    evaluator: Callable[[Case, Path, EngineSelection], MatrixRun],
) -> None:
    workflow = cast(_WorkflowModule, import_module("parquity.generation.workflow"))
    monkeypatch.setattr(workflow, "evaluate_selected_case", evaluator)


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert payload["format"] == "parquity.cli.v1"
    return payload


def _fuzz(destination: Path, max_findings: int, examples: int = 1) -> list[str]:
    base = ["fuzz", "--examples", str(examples), "--seed", "0"]
    return [*base, "--max-findings", str(max_findings), "--out", str(destination)]


def _unavailable() -> EngineAvailability:
    return EngineAvailability(
        "datafusion",
        "datafusion",
        "extended",
        True,
        False,
        False,
        None,
        "Install DataFusion",
        "controlled unavailable provider",
    )


def test_omitted_selection_uses_core_and_explicit_sets_are_canonicalized_and_bound(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    _patch(monkeypatch, _one_failure)

    default = tmp_path / "default"
    assert cli.main(["check", str(case_path), "--out", str(default)]) == 1
    _payload(capsys)
    default_run = cast(dict[str, object], json.loads((default / "run.json").read_bytes()))
    assert [item["name"] for item in cast(list[dict[str, object]], default_run["writers"])] == [
        "pyarrow",
        "duckdb",
        "polars",
    ]
    assert [item["name"] for item in cast(list[dict[str, object]], default_run["readers"])] == [
        "pyarrow",
        "duckdb",
        "polars",
    ]

    selected = tmp_path / "selected"
    arguments = [
        "check",
        str(case_path),
        "--readers",
        "datafusion,pyarrow",
        "--out",
        str(selected),
        "--writers",
        "duckdb,pyarrow",
    ]
    assert cli.main(arguments) == 1
    _payload(capsys)
    selected_run = cast(dict[str, object], json.loads((selected / "run.json").read_bytes()))
    assert [item["name"] for item in cast(list[dict[str, object]], selected_run["writers"])] == [
        "pyarrow",
        "duckdb",
    ]
    assert [item["name"] for item in cast(list[dict[str, object]], selected_run["readers"])] == [
        "pyarrow",
        "datafusion",
    ]
    providers = cast(dict[str, object], selected_run["environment"])["providers"]
    assert [item["name"] for item in cast(list[dict[str, object]], providers)] == [
        "pyarrow",
        "duckdb",
        "datafusion",
    ]


@pytest.mark.parametrize(
    ("option", "value", "kind"),
    (
        ("--writers", "", "INVALID_ENGINE_SET"),
        ("--writers", "pyarrow,pyarrow", "INVALID_ENGINE_SET"),
        ("--readers", "unknown", "UNKNOWN_ENGINE"),
        ("--writers", "datafusion", "ENGINE_CAPABILITY_ERROR"),
    ),
)
def test_invalid_engine_sets_exit_two_before_evaluation_without_contraction(
    option: str,
    value: str,
    kind: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    calls = 0

    def forbidden(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
        nonlocal calls
        calls += 1
        raise AssertionError((case, directory, selection))

    _patch(monkeypatch, forbidden)
    destination = tmp_path / kind
    assert cli.main(["check", str(case_path), "--out", str(destination), option, value]) == 2
    payload = _payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == kind
    assert calls == 0
    assert not destination.exists()


def test_unavailable_selected_engine_is_structured_and_not_silently_removed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    main_module = cast(_MainModule, import_module("parquity.cli.main"))
    unavailable = _unavailable()

    def reject(
        writers: str | Sequence[str] | None,
        readers: str | Sequence[str] | None,
    ) -> EngineSelection:
        del writers, readers
        raise EngineSelectionError("ENGINE_UNAVAILABLE", "datafusion unavailable", (unavailable,))

    monkeypatch.setattr(main_module, "resolve_engine_selection", reject)
    destination = tmp_path / "unavailable"
    assert cli.main(["check", str(case_path), "--out", str(destination)]) == 2
    payload = _payload(capsys)
    engines = cast(list[dict[str, object]], payload["engines"])
    assert [item["name"] for item in engines] == ["datafusion"]
    assert not destination.exists()


@pytest.mark.parametrize("max_findings", (1, 64))
def test_max_findings_accepts_both_public_boundaries(
    max_findings: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _patch(monkeypatch, _pass)
    destination = tmp_path / f"bound-{max_findings}"
    assert cli.main(_fuzz(destination, max_findings)) == 0
    payload = _payload(capsys)
    assert payload["max_findings"] == max_findings
    assert not destination.exists()


def test_fuzz_cap_materializes_one_child_and_records_every_overflow_from_the_case(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def two_failures(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
        run = _one_failure(case, directory, selection)
        other = run.results[1]
        second = _cell(
            EngineVersion(other.writer, other.writer_version),
            EngineVersion(other.reader, other.reader_version),
            Verdict.VALUE_MISMATCH,
            "second distinct detail",
        )
        return MatrixRun(
            run.case_id,
            (run.results[0], second, *run.results[2:]),
            run.files,
            run.writers,
            run.readers,
        )

    _patch(monkeypatch, two_failures)
    destination = tmp_path / "capped"
    assert cli.main(_fuzz(destination, 1, 3)) == 1
    payload = _payload(capsys)
    assert payload["run_status"] == "FINDING_CAP_REACHED"
    assert payload["finding_count"] == 1
    assert payload["overflow_count"] == 1
    run = cast(dict[str, object], json.loads((destination / "run.json").read_bytes()))
    assert len(cast(list[object], run["findings"])) == 1
    assert len(cast(list[object], run["overflow"])) == 1


def test_replay_requests_the_exact_recorded_sets_and_refuses_unavailability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    _write_case(case_path)
    _patch(monkeypatch, _one_failure)
    destination = tmp_path / "selected"
    assert (
        cli.main(
            [
                "check",
                str(case_path),
                "--out",
                str(destination),
                "--writers",
                "pyarrow,duckdb",
                "--readers",
                "pyarrow,datafusion",
            ]
        )
        == 1
    )
    _payload(capsys)
    main_module = cast(_MainModule, import_module("parquity.cli.main"))
    observed: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

    def resolve(
        writers: str | Sequence[str] | None,
        readers: str | Sequence[str] | None,
    ) -> EngineSelection:
        assert not isinstance(writers, str) and writers is not None
        assert not isinstance(readers, str) and readers is not None
        observed.append((tuple(writers), tuple(readers)))
        raise EngineSelectionError(
            "ENGINE_UNAVAILABLE",
            "recorded datafusion is unavailable",
            (_unavailable(),),
        )

    monkeypatch.setattr(main_module, "resolve_engine_selection", resolve)
    assert cli.main(["replay", str(destination)]) == 2
    _payload(capsys)
    assert observed == [(("pyarrow", "duckdb"), ("pyarrow", "datafusion"))]
