from __future__ import annotations

import contextlib
import io
import json
import multiprocessing
import sys
from pathlib import Path
from typing import cast

import pytest

import parquity.cli as cli
from parquity.engines import EngineSelection
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs.bundle import validate_run
from parquity.verdicts import CellResult, MatrixRun, Verdict
from tests.support.cli_import_contract import loaded_capability_modules
from tests.support.cli_output import captured_payload as _payload
from tests.support.generated_cli import patch_evaluator, selection_versions, write_case


def _template() -> Case:
    fields = (
        Field("value", TypeSpec(Kind.INT32), nullable=False),
        Field(
            "flags",
            TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), item_nullable=True, size=2),
        ),
    )
    return Case(fields, ())


def _write_template(path: Path) -> Case:
    case = _template()
    return write_case(path, case)


def _pass(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    del directory
    writers, readers = selection_versions(selection)
    result = CellResult(
        writers[0].name,
        writers[0].version,
        readers[0].name,
        readers[0].version,
        "compare",
        Verdict.PASS,
        "$",
        "",
    )
    return MatrixRun(case.case_id, (result,), (), writers, readers)


def _failure(case: Case, directory: Path, selection: EngineSelection) -> MatrixRun:
    del directory
    writers, readers = selection_versions(selection)
    result = CellResult(
        writers[0].name,
        writers[0].version,
        "*",
        "*",
        "write",
        Verdict.WRITE_ERROR,
        "$",
        "controlled schema failure",
        "Controlled",
    )
    return MatrixRun(case.case_id, (result,), (), writers, readers)


def _fuzz(
    schema: Path | None,
    destination: Path,
    *,
    examples: int = 2,
    writers: str = "pyarrow",
    readers: str = "pyarrow",
) -> list[str]:
    arguments = [
        "fuzz",
        "--examples",
        str(examples),
        "--seed",
        "7",
        "--max-saved",
        "1",
        "--writers",
        writers,
        "--readers",
        readers,
        "--out",
        str(destination),
    ]
    return arguments if schema is None else [*arguments, "--schema", str(schema)]


def _invalid_schema_probe(arguments: list[str], result_path: str) -> None:
    before = frozenset(sys.modules)
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = cli.main(arguments)
    loaded = loaded_capability_modules(set(sys.modules).difference(before))
    result = {
        "exit_code": exit_code,
        "payload": json.loads(stdout.getvalue()),
        "stderr": stderr.getvalue(),
        "loaded": loaded,
    }
    Path(result_path).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


@pytest.mark.parametrize("shape", ("missing", "malformed", "wrong", "unsupported", "rows", "limit"))
def test_invalid_schema_exits_two_before_engines_evaluation_or_output(
    shape: str,
    tmp_path: Path,
) -> None:
    path = tmp_path / f"{shape}.json"
    if shape == "malformed":
        path.write_text("{", encoding="utf-8")
    elif shape == "wrong":
        path.write_text('{"format":"other","schema":[],"rows":[]}', encoding="utf-8")
    elif shape == "unsupported":
        path.write_text(
            '{"format":"parquity.case.v1","schema":[{"name":"x","nullable":false,'
            '"type":{"kind":"decimal"}}],"rows":[]}',
            encoding="utf-8",
        )
    elif shape == "rows":
        path.write_bytes(Case(_template().fields, ((1, [True, False]),)).canonical_bytes())
    elif shape == "limit":
        fixed = TypeSpec(Kind.FIXED_LIST, item=TypeSpec(Kind.BOOL), size=257)
        path.write_bytes(Case((Field("values", fixed),), ()).canonical_bytes())
    destination = tmp_path / "output"
    result_path = tmp_path / "probe.json"
    arguments = _fuzz(path, destination, writers="unknown", readers="unknown")
    process = multiprocessing.get_context("spawn").Process(
        target=_invalid_schema_probe,
        args=(arguments, str(result_path)),
    )
    process.start()
    process.join()
    assert process.exitcode == 0
    result = cast(dict[str, object], json.loads(result_path.read_text(encoding="utf-8")))
    payload = cast(dict[str, object], result["payload"])
    assert result["exit_code"] == 2
    error = cast(dict[str, object], payload["error"])
    kind = error["kind"]
    expected_kind = (
        "SCHEMA_UNREADABLE"
        if shape == "missing"
        else "SCHEMA_LIMIT_EXCEEDED"
        if shape == "limit"
        else "INVALID_SCHEMA"
    )
    assert kind == expected_kind
    diagnostic_sentinels = {
        "missing": path.name,
        "malformed": "line 1",
        "wrong": "wrong format",
        "rows": "rows must be empty",
    }
    if sentinel := diagnostic_sentinels.get(shape):
        assert sentinel in cast(str, error["detail"])
        assert cast(str, error["detail"]) in cast(str, result["stderr"])
    assert result["loaded"] == []
    assert not destination.exists()


def test_schema_and_generic_no_finding_outputs_keep_distinct_additive_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    schema = _write_template(tmp_path / "schema.json")
    patch_evaluator(monkeypatch, _pass)
    schema_output = tmp_path / "schema-output"
    assert cli.main(_fuzz(tmp_path / "schema.json", schema_output)) == 0
    schema_payload, stderr = _payload(capsys)
    assert stderr == "" and schema_payload["status"] == "NO_FINDING"
    assert schema_payload["generation_profile"] == "schema"
    assert schema_payload["schema_case_id"] == schema.case_id
    assert not schema_output.exists()

    generic_output = tmp_path / "generic-output"
    assert cli.main(_fuzz(None, generic_output)) == 0
    generic, stderr = _payload(capsys)
    assert stderr == "" and generic["status"] == "NO_FINDING"
    assert "generation_profile" not in generic and "schema_case_id" not in generic
    assert not generic_output.exists()


def test_schema_run_passes_check_and_replay_with_bound_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    template_path = tmp_path / "schema.json"
    template = _write_template(template_path)
    patch_evaluator(monkeypatch, _failure)
    destination = tmp_path / "schema-run"
    assert cli.main(_fuzz(template_path, destination, examples=3)) == 1
    published, stderr = _payload(capsys)
    assert stderr == "" and published["status"] == "RUN_PUBLISHED"
    assert published["generation_profile"] == "schema"
    assert published["schema_case_id"] == template.case_id
    validated = validate_run(destination)
    assert len(validated.children) == 1
    child = validated.children[0]
    assert child.finding.generation is not None
    assert child.finding.generation.schema_case_id == template.case_id

    recheck = tmp_path / "recheck"
    assert (
        cli.main(
            [
                "check",
                str(child.directory / "case.json"),
                "--writers",
                "pyarrow",
                "--readers",
                "pyarrow",
                "--out",
                str(recheck),
            ]
        )
        == 1
    )
    checked, _ = _payload(capsys)
    assert "generation_profile" not in checked and "schema_case_id" not in checked

    assert cli.main(["replay", str(destination)]) == 1
    replayed, stderr = _payload(capsys)
    assert stderr == "" and replayed["status"] == "REPRODUCED"
