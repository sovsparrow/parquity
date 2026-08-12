from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from importlib import import_module
from pathlib import Path
from typing import Protocol, cast

import pytest

import parquity.cli as cli
from parquity.engines import EngineAvailability, EngineSelection, EngineSelectionError
from parquity.evidence import EngineVersion
from parquity.generation.search.identity import finding_key
from parquity.model import Case
from parquity.runs.bundle import ValidatedRunV2, validate_run
from parquity.verdicts import CellResult, MatrixRun, Verdict
from tests.support.cli_output import captured_payload
from tests.support.generated_cli import patch_evaluator, selection_versions, write_case


class _MainModule(Protocol):
    resolve_engine_selection: Callable[
        [str | Sequence[str] | None, str | Sequence[str] | None], EngineSelection
    ]


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
    writers, readers = selection_versions(selection)
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
    writers, readers = selection_versions(selection)
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
    writers, readers = selection_versions(selection)
    return MatrixRun(case.case_id, _complete(selection), (), writers, readers)


def _fuzz(destination: Path, max_saved: int, examples: int = 1) -> list[str]:
    base = ["fuzz", "--examples", str(examples), "--seed", "0"]
    return [*base, "--max-saved", str(max_saved), "--out", str(destination)]


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
    write_case(case_path)
    patch_evaluator(monkeypatch, _one_failure)

    default = tmp_path / "default"
    assert cli.main(["check", str(case_path), "--out", str(default)]) == 1
    captured_payload(capsys)
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
    captured_payload(capsys)
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
    write_case(case_path)
    calls = 0

    def forbidden(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
        nonlocal calls
        calls += 1
        raise AssertionError((case, directory, selection))

    patch_evaluator(monkeypatch, forbidden)
    destination = tmp_path / kind
    assert cli.main(["check", str(case_path), "--out", str(destination), option, value]) == 2
    payload, _ = captured_payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == kind
    assert calls == 0
    assert not destination.exists()


def test_unavailable_selected_engine_is_structured_and_not_silently_removed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    write_case(case_path)
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
    payload, _ = captured_payload(capsys)
    engines = cast(list[dict[str, object]], payload["engines"])
    assert [item["name"] for item in engines] == ["datafusion"]
    assert not destination.exists()


@pytest.mark.parametrize("max_saved", (1, 64))
def test_max_saved_accepts_both_public_boundaries_and_preserves_cli_v1_key(
    max_saved: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    patch_evaluator(monkeypatch, _pass)
    destination = tmp_path / f"bound-{max_saved}"
    assert cli.main(_fuzz(destination, max_saved)) == 0
    payload, _ = captured_payload(capsys)
    assert payload["max_findings"] == max_saved
    assert not destination.exists()


def test_fuzz_rejects_retired_max_findings_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = [
        "fuzz",
        "--examples",
        "1",
        "--seed",
        "0",
        "--max-findings",
        "1",
        "--out",
        "unused",
    ]
    assert cli.main(arguments) == 2
    payload, _ = captured_payload(capsys)
    assert cast(dict[str, object], payload["error"])["kind"] == "USAGE_ERROR"


def test_fuzz_saved_limit_materializes_one_child_and_records_overflow(
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

    patch_evaluator(monkeypatch, two_failures)
    destination = tmp_path / "capped"
    assert cli.main(_fuzz(destination, 1, 3)) == 1
    payload, _ = captured_payload(capsys)
    assert payload["run_status"] == "FINDING_CAP_REACHED"
    assert payload["finding_count"] == 1
    assert payload["overflow_count"] == 1
    run = cast(dict[str, object], json.loads((destination / "run.json").read_bytes()))
    assert run["format"] == "parquity.run.v2"
    assert run["status"] == "SAVED_EVIDENCE_LIMIT_REACHED"
    validated = validate_run(destination)
    assert isinstance(validated, ValidatedRunV2)
    assert len(validated.run.saved_evidence) == 1
    assert len(validated.run.manifest_only_evidence) == 1
    assert len(validated.run.occurrences) == 2
    saved = {finding_key(item.fingerprint) for item in validated.run.saved_evidence}
    manifest_only = {finding_key(item.fingerprint) for item in validated.run.manifest_only_evidence}
    assert saved.isdisjoint(manifest_only)
    assert saved | manifest_only == {item.key for item in validated.run.occurrences}


def test_replay_requests_the_exact_recorded_sets_and_refuses_unavailability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case.json"
    write_case(case_path)
    patch_evaluator(monkeypatch, _one_failure)
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
    captured_payload(capsys)
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
    captured_payload(capsys)
    assert observed == [(("pyarrow", "duckdb"), ("pyarrow", "datafusion"))]
