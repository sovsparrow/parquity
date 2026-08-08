from __future__ import annotations

import json
from collections.abc import Sequence
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from parquity import cli
from parquity.engines import EngineSelection, resolve_engine_selection
from parquity.engines.base import EngineIdentity, EngineWriter, ProviderOperationError
from parquity.engines.pyarrow import PyArrowEngine
from parquity.findings.bundle import ValidatedBundle
from parquity.findings.replay import replay_validated_bundle
from parquity.matrix import run_matrix
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.runs.bundle import ValidatedRun
from parquity.runs.replay import replay_validated_run
from parquity.verdicts import CellResult, EngineVersion, MatrixRun, Verdict
from parquity.writer_profile_contracts import admit_writer_profile_plan
from parquity.writer_profiles import (
    PROFILE_REGISTRY,
    CapabilityStatus,
    WriterExecutionIdentity,
    WriterProfileError,
    WriterProfileIdentity,
    WriterProfilePlan,
    build_writer_profile_plan,
)


def _fixed_case() -> Case:
    fields = (
        Field("value", TypeSpec(Kind.INT32), False),
        Field("label", TypeSpec(Kind.STRING), False),
    )
    return Case(fields, ((1, "a"), (2, "b"), (3, "c"), (4, "d")))


class _RejectingEngine(PyArrowEngine):
    def write_profiled(self, table: pa.Table, path: Path, profile: WriterProfileIdentity) -> None:
        del table, path, profile
        raise ProviderOperationError("pyarrow", "write", ValueError("option rejected"))

    def read(self, path: Path) -> pa.Table:
        raise AssertionError(f"unexpected reader execution for {path}")


def test_supported_profiles_produce_verified_artifacts_for_every_reader(
    tmp_path: Path,
) -> None:
    selection = resolve_engine_selection(
        "pyarrow,duckdb,polars,fastparquet",
        "pyarrow,duckdb,polars,datafusion,fastparquet",
    )
    declared = build_writer_profile_plan(PROFILE_REGISTRY, selection.writers)
    assert declared is not None
    plan = admit_writer_profile_plan(declared, selection.writers)
    assert plan is not None

    run = run_matrix(
        _fixed_case(),
        tmp_path / "portable-profiles",
        selection.writers,
        selection.readers,
        plan,
    )

    supported = tuple(
        item for item in plan.capabilities if item.status is CapabilityStatus.SUPPORTED
    )
    unsupported = tuple(
        item for item in plan.capabilities if item.status is CapabilityStatus.UNSUPPORTED
    )
    profiled_files = tuple(
        (identity, path)
        for identity, path in run.files
        if isinstance(identity, WriterExecutionIdentity) and identity.writer_profile is not None
    )
    profiled_results = tuple(result for result in run.results if result.writer_profile is not None)

    assert (run.status, len(plan.capabilities), len(supported)) == ("PASS", 16, 14)
    assert {(item.writer.name, item.profile_name) for item in unsupported} == {
        ("duckdb", "row-group-2"),
        ("duckdb", "min-max-statistics-off"),
    }
    assert (len(profiled_files), len(profiled_results)) == (14, 14 * 5)

    for capability in supported:
        cells = tuple(
            result
            for result in profiled_results
            if result.writer == capability.writer.name
            and result.writer_profile == capability.profile_identity
        )
        assert {result.reader for result in cells} == set(selection.reader_names)
        assert all(result.verdict is Verdict.PASS for result in cells)

    for execution, path in profiled_files:
        profile = execution.writer_profile
        assert profile is not None
        metadata = pq.ParquetFile(path).metadata
        chunks = tuple(
            metadata.row_group(group).column(column)
            for group in range(metadata.num_row_groups)
            for column in range(metadata.row_group(group).num_columns)
        )
        assert chunks
        if profile.name == "compression-gzip":
            assert all(column.compression == "GZIP" for column in chunks)
        elif profile.name == "compression-brotli":
            assert all(column.compression == "BROTLI" for column in chunks)
        elif profile.name == "row-group-2":
            assert tuple(
                metadata.row_group(index).num_rows for index in range(metadata.num_row_groups)
            ) == (2, 2)
            assert metadata.num_rows == 4
        else:
            assert profile.name == "min-max-statistics-off"
            assert all(
                column.statistics is None or not column.statistics.has_min_max for column in chunks
            )


def test_provider_rejection_is_unavailable_while_adapter_defects_are_internal(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _RejectingEngine(EngineIdentity("pyarrow", "controlled"))
    declared = build_writer_profile_plan(("compression-gzip",), (engine,))
    assert declared is not None
    with pytest.raises(WriterProfileError) as captured:
        admit_writer_profile_plan(declared, (engine,))
    assert captured.value.kind == "WRITER_PROFILE_UNSUPPORTED"

    selection = EngineSelection(("pyarrow",), ("pyarrow",), (engine,), (engine,))
    main_module = import_module("parquity.cli.main")

    def resolve(*unused: object) -> EngineSelection:
        del unused
        return selection

    monkeypatch.setattr(main_module, "resolve_engine_selection", resolve)
    source = tmp_path / "case.json"
    source.write_bytes(_fixed_case().canonical_bytes())
    destination = tmp_path / "unavailable"
    arguments = [
        "check",
        str(source),
        "--out",
        str(destination),
        "--writer-profiles",
        "compression-gzip",
    ]
    source.write_bytes(b"{}")
    assert cli.main(arguments) == 2
    invalid = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert cast(dict[str, object], invalid["error"])["kind"] == "INVALID_CASE"
    source.write_bytes(_fixed_case().canonical_bytes())
    assert cli.main(arguments) == 2
    payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert cast(dict[str, object], payload["error"])["kind"] == "WRITER_PROFILE_UNSUPPORTED"
    assert "finding_count" not in payload and not destination.exists()

    def wrong_contract(
        self: _RejectingEngine,
        table: pa.Table,
        path: Path,
        profile: WriterProfileIdentity,
    ) -> None:
        del profile
        PyArrowEngine.write(self, table, path)

    monkeypatch.setattr(_RejectingEngine, "write_profiled", wrong_contract)
    with pytest.raises(WriterProfileError):
        admit_writer_profile_plan(declared, (engine,))

    def malformed(self: _RejectingEngine, name: str) -> WriterProfileIdentity:
        del self, name
        raise ValueError("adapter translation is malformed")

    monkeypatch.setattr(_RejectingEngine, "writer_profile", malformed)
    arguments[3] = str(tmp_path / "malformed")
    assert cli.main(arguments) == 3
    malformed_payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert malformed_payload["status"] == "INTERNAL_ERROR"
    assert cast(dict[str, object], malformed_payload["error"])["kind"] == "ValueError"


def test_profile_plan_is_admitted_once_per_command_and_reused_within_fuzz(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = import_module("parquity.cli.generated")
    original_admit = admit_writer_profile_plan
    admissions: list[object] = []
    observed: list[object] = []

    def counted_admission(
        declared: WriterProfilePlan, writers: Sequence[EngineWriter]
    ) -> WriterProfilePlan | None:
        admissions.append(declared)
        return original_admit(declared, writers)

    def evaluate(
        case: Case,
        directory: Path,
        selection: EngineSelection,
        writer_profiles: WriterProfilePlan | None = None,
    ) -> MatrixRun:
        del directory
        observed.append(writer_profiles)
        writers = tuple(EngineVersion(*item) for item in selection.writer_versions)
        readers = tuple(EngineVersion(*item) for item in selection.reader_versions)
        executions = (
            tuple(WriterExecutionIdentity(writer) for writer in writers)
            if writer_profiles is None
            else writer_profiles.executions(writers)
        )
        results = tuple(
            CellResult(
                execution.writer.name,
                execution.writer.version,
                reader.name,
                reader.version,
                "compare",
                Verdict.PASS,
                "$",
                "match",
                writer_profile=execution.writer_profile,
            )
            for execution in executions
            for reader in readers
        )
        return MatrixRun(case.case_id, results, (), writers, readers, writer_profiles)

    monkeypatch.setattr(generated, "admit_writer_profile_plan", counted_admission)
    monkeypatch.setattr(
        import_module("parquity.generation.workflow"), "evaluate_selected_case", evaluate
    )
    profile_args = ["--writers", "pyarrow", "--readers", "pyarrow"]
    profile_args += ["--writer-profiles", "compression-gzip"]
    assert (
        cli.main(
            [
                "fuzz",
                "--examples",
                "3",
                "--seed",
                "17",
                "--out",
                str(tmp_path / "fuzz"),
                *profile_args,
            ]
        )
        == 0
    )
    capsys.readouterr()
    profiled = tuple(observed)
    assert len(profiled) > 1 and all(plan is profiled[0] for plan in profiled)
    assert len(admissions) == 1

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    assert cli.main(["fuzz", "--seed", "17", "--out", str(occupied), *profile_args]) == 2
    capsys.readouterr()
    assert len(admissions) == 1

    source = tmp_path / "case.json"
    source.write_bytes(_fixed_case().canonical_bytes())
    assert cli.main(["check", str(source), "--out", str(tmp_path / "plain")]) == 0
    capsys.readouterr()
    assert len(admissions) == 1 and observed[-1] is None
    assert cli.main(["check", str(source), "--out", str(tmp_path / "profiled"), *profile_args]) == 0
    capsys.readouterr()
    assert len(admissions) == 2


def test_direct_finding_and_run_replay_reject_conflicting_and_unexpected_profile_plans() -> None:
    writer = PyArrowEngine(EngineIdentity("pyarrow", "1"))
    recorded = build_writer_profile_plan(("compression-gzip", "row-group-2"), (writer,))
    assert recorded is not None
    reduced = WriterProfilePlan(
        ("row-group-2",),
        tuple(item for item in recorded.capabilities if item.profile_name == "row-group-2"),
    )
    foreign_data = cast(dict[str, object], json.loads(json.dumps(recorded.to_data())))
    capabilities = cast(list[dict[str, object]], foreign_data["capabilities"])
    cast(dict[str, object], capabilities[0]["effective_options"])["compression"] = "foreign"
    foreign = WriterProfilePlan.from_data(foreign_data)
    case = _fixed_case()
    finding = cast(
        ValidatedBundle,
        SimpleNamespace(case=case, finding=SimpleNamespace(writer_profiles=recorded)),
    )
    aggregate = cast(
        ValidatedRun,
        SimpleNamespace(run=SimpleNamespace(writer_profiles=recorded), children=(finding,)),
    )

    def evaluator_for(current: WriterProfilePlan | None):
        def evaluator(
            evaluated_case: Case,
            directory: Path,
        ) -> MatrixRun:
            del evaluated_case, directory
            run: MatrixRun

            def normalized(transient_roots: object) -> MatrixRun:
                del transient_roots
                return run

            run = cast(
                MatrixRun,
                SimpleNamespace(
                    case_id=case.case_id,
                    writer_profiles=current,
                    normalized=normalized,
                ),
            )
            return run

        return evaluator

    for current in (None, reduced, foreign):
        evaluator = evaluator_for(current)
        with pytest.raises(RuntimeError, match="writer profile plan"):
            replay_validated_bundle(finding, evaluator)
        with pytest.raises(RuntimeError, match="writer profile plan"):
            replay_validated_run(aggregate, evaluator)
    plain_finding = cast(
        ValidatedBundle,
        SimpleNamespace(case=case, finding=SimpleNamespace(writer_profiles=None)),
    )
    plain_run = cast(
        ValidatedRun,
        SimpleNamespace(run=SimpleNamespace(writer_profiles=None), children=(plain_finding,)),
    )
    profiled = evaluator_for(recorded)
    with pytest.raises(RuntimeError, match="unprofiled replay"):
        replay_validated_bundle(plain_finding, profiled)
    with pytest.raises(RuntimeError, match="unprofiled replay"):
        replay_validated_run(plain_run, profiled)
