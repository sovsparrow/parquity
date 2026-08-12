from __future__ import annotations

from pathlib import Path

from parquity.evidence import EngineVersion
from parquity.generation.search.evaluation import CampaignEvaluator
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.verdicts import CellResult, MatrixRun, Verdict


def test_campaign_evaluation_cache_reuses_normalized_results_but_not_fresh_evidence(
    tmp_path: Path,
) -> None:
    case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))
    writer = EngineVersion("pyarrow", "1")
    reader = EngineVersion("duckdb", "2")
    result = CellResult(
        writer.name,
        writer.version,
        reader.name,
        reader.version,
        "compare",
        Verdict.VALUE_MISMATCH,
        "$rows[0].value",
        "controlled mismatch",
        "ControlledMismatch",
    )
    calls = 0

    def evaluate(value: Case, directory: Path) -> MatrixRun:
        nonlocal calls
        calls += 1
        directory.mkdir(parents=True)
        artifact = directory / "pyarrow.parquet"
        artifact.write_bytes(b"PAR1cache-proofPAR1")
        return MatrixRun(
            value.case_id,
            (result,),
            ((writer.name, artifact),),
            (writer,),
            (reader,),
        )

    cached = CampaignEvaluator(evaluate)
    first = cached(case)
    second = cached(case)

    assert first == second
    assert first.files == ()
    assert (cached.hits, cached.misses, calls) == (1, 1, 1)

    fresh = evaluate(case, tmp_path / "fresh-publication")

    assert fresh.results == first.results
    assert fresh.files[0][1].is_file()
    assert calls == 2


def test_campaign_evaluation_cache_evicts_the_least_recent_case_at_its_bound() -> None:
    first = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))
    second = Case((Field("value", TypeSpec(Kind.INT32)),), ((2,),))
    writer = EngineVersion("pyarrow", "1")
    reader = EngineVersion("duckdb", "2")
    calls: list[str] = []

    def evaluate(case: Case, directory: Path) -> MatrixRun:
        calls.append(case.case_id)
        directory.mkdir(parents=True)
        artifact = directory / "pyarrow.parquet"
        artifact.write_bytes(b"PAR1cache-bound-proofPAR1")
        return MatrixRun(
            case.case_id,
            (
                CellResult(
                    writer.name,
                    writer.version,
                    reader.name,
                    reader.version,
                    "compare",
                    Verdict.VALUE_MISMATCH,
                    "$rows[0].value",
                    "controlled mismatch",
                    "ControlledMismatch",
                ),
            ),
            ((writer.name, artifact),),
            (writer,),
            (reader,),
        )

    cached = CampaignEvaluator(evaluate, max_entries=1)
    cached(first)
    cached(second)
    cached(first)

    assert calls == [first.case_id, second.case_id, first.case_id]
    assert (cached.hits, cached.misses) == (0, 3)
