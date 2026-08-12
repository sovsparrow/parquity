from __future__ import annotations

import sys

import pytest

from parquity.cli.output import emit
from parquity.reporting import (
    ArtifactRef,
    DetailView,
    EvidenceKind,
    EvidenceReportView,
    FindingEvidenceView,
    FindingView,
    InputView,
    ReplayState,
    ReplayStateCount,
    ReproductionStep,
    RunReportView,
    TableView,
)
from tests.support.cli_output import Output, plain


def _engine(name: str, tier: str, *, available: bool, writer: bool) -> dict[str, object]:
    return {
        "name": name,
        "distribution": name,
        "tier": tier,
        "reader": True,
        "writer": writer,
        "available": available,
        "version": "20.0.0" if available else None,
        "installation_hint": None if available else f"Install parquity[{name}]",
        "detail": "installed" if available else "not installed",
    }


_DOCUMENTS: tuple[tuple[str, dict[str, object], tuple[str, ...]], ...] = (
    (
        "engines",
        {
            "command": "engines",
            "status": "OK",
            "engines": [
                _engine("pyarrow", "core", available=True, writer=True),
                _engine("datafusion", "extended", available=False, writer=False),
            ],
            "python_support": {
                name: ["3.11", "3.12", "3.13", "3.14"] for name in ("pyarrow", "datafusion")
            },
        },
        (
            "Engine Tier Available Reader Writer Version",
            "pyarrow core yes yes yes 20.0.0",
            "datafusion extended no yes — —",
            "1/2 providers available · Python 3.11-3.14",
        ),
    ),
    (
        "smoke",
        {
            "command": "smoke",
            "status": "FAIL",
            "case_id": "smoke-case",
            "writers": [],
            "readers": [],
            "results": [
                {"writer": writer, "reader": reader, "verdict": verdict}
                for writer, reader, verdict in (
                    ("pyarrow", "pyarrow", "PASS"),
                    ("pyarrow", "duckdb", "PASS"),
                    ("duckdb", "pyarrow", "READ_ERROR"),
                    ("duckdb", "duckdb", "PASS"),
                )
            ],
        },
        (
            "Writer \\ Reader pyarrow duckdb",
            "pyarrow PASS PASS",
            "duckdb READ_ERROR PASS",
            "FAIL · 3/4 cells passed",
        ),
    ),
)

_CAPTURE_VIEW = RunReportView(
    command="check",
    evidence_kind=EvidenceKind.GENERATED,
    summary=(
        "3 of 3 engine paths failed on the supplied table. "
        "A reproducer was saved for 1; the other remains in run.json."
    ),
    writers=("pyarrow 1",),
    readers=("duckdb 1",),
    evaluated_input_count=1,
    executed_check_count=3,
    affected_input_count=1,
    findings=(
        FindingView(
            label="F1",
            participants="pyarrow → duckdb",
            stage="compare",
            outcome_kind="VALUE_MISMATCH",
            summary="controlled mismatch",
            evidence_input="1 row · 1 column · int32",
            exact_location="$.rows[0].value",
            occurrence_count=2,
            distinct_input_count=1,
            saved_replay_target_count=1,
            evidence_refs=(ArtifactRef("saved report", "findings/finding-id/REPORT.md"),),
            replay_state_counts=(ReplayStateCount(ReplayState.NOT_RUN, 1),),
        ),
        FindingView(
            label="F2",
            participants="duckdb (write)",
            stage="write",
            outcome_kind="WRITE_ERROR · ControlledError",
            summary="controlled write failure",
            evidence_input="1 row · int32",
            exact_location="$",
            occurrence_count=1,
            distinct_input_count=1,
            saved_replay_target_count=0,
            evidence_refs=(ArtifactRef("run.json", "run.json"),),
            replay_state_counts=(),
        ),
    ),
    saved_evidence_count=1,
    evidence_bundle_count=1,
    unevaluated_input_count=0,
    stop="Supplied Input evaluated",
    bounds=(),
    environment=(DetailView("Parquity", "0.2.0"),),
    machine_record=ArtifactRef("run.json", "run.json"),
)

_REPLAY_VIEW = EvidenceReportView(
    evidence_kind=EvidenceKind.SCAN,
    title="Parquity scan evidence",
    summary="The reader failed to open the file.",
    facts=(DetailView("Replay", "Reproduced: 1"),),
    reproduce=(
        ReproductionStep(
            "Parquity replay",
            "python reproduce.py",
            "Replays this saved target.",
        ),
    ),
    input=InputView(
        identity="input-id",
        facts=(DetailView("Bytes", "12"),),
        artifacts=(ArtifactRef("retained Parquet bytes", "input.parquet"),),
    ),
    finding_evidence=(
        FindingEvidenceView(
            "occurrence-a",
            "pyarrow recorded a provider error",
            (DetailView("Replay", "REPRODUCED"),),
        ),
    ),
    outcomes=TableView(
        ("Reader", "Version", "Result", "Rows", "Columns", "Diagnostic"),
        (("pyarrow", "1", "PROVIDER_ERROR", "—", "—", "controlled error"),),
    ),
    environment=(DetailView("Parquity", "0.2.0"),),
    machine_record=ArtifactRef("finding.json", "finding.json"),
    replay_observations=(DetailView("new-observation", "duckdb recorded a new error"),),
)


def _terminal_bytes(
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    report: RunReportView | EvidenceReportView | None = None,
    *,
    term: str = "xterm-256color",
    no_color: bool = False,
) -> bytes:
    monkeypatch.setenv("TERM", term)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)
    output = Output(tty=True)
    monkeypatch.setattr(sys, "stdout", output)
    emit(document, report)
    return output.bytes()


def _content_lines(payload: bytes) -> tuple[str, ...]:
    return tuple(" ".join(line.split()) for line in plain(payload).splitlines())


def _assert_ordered(payload: bytes, values: tuple[str, ...]) -> None:
    text = plain(payload)
    positions = tuple(text.index(value) for value in values)
    assert positions == tuple(sorted(positions))


@pytest.mark.parametrize(
    ("name", "document", "required"),
    _DOCUMENTS,
    ids=tuple(name for name, _, _ in _DOCUMENTS),
)
def test_public_terminal_documents_have_one_ordered_human_projection(
    name: str,
    document: dict[str, object],
    required: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del name
    rendered = _terminal_bytes(monkeypatch, document, term="dumb")
    assert not rendered.lstrip().startswith(b"{")
    assert _content_lines(rendered) == required


def test_typed_capture_uses_the_shared_finding_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = _terminal_bytes(
        monkeypatch,
        {"command": "check", "status": "RUN_PUBLISHED", "output": "/evidence/check"},
        _CAPTURE_VIEW,
        term="dumb",
    )
    assert not rendered.lstrip().startswith(b"{")
    _assert_ordered(
        rendered,
        (
            "Check run saved",
            "3 of 3 engine paths failed on the supplied table. A reproducer was saved for 1; "
            "the other remains in run.json.",
            "Writer → reader",
            "compare · VALUE_MISMATCH controlled mismatch",
            "Seen 2 times on this supplied table",
            "open",
            "duckdb (write)",
            "not saved",
            "Output: /evidence/check",
        ),
    )
    for hidden in ("Finding", "Occurrence", "affected Input", "bundle", "saved target"):
        assert hidden not in plain(rendered)


def test_typed_replay_uses_authoritative_status_and_lists_new_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered = _terminal_bytes(
        monkeypatch,
        {"command": "replay", "status": "RELATED_FAILURE"},
        _REPLAY_VIEW,
        term="dumb",
    )
    assert not rendered.lstrip().startswith(b"{")
    _assert_ordered(
        rendered,
        (
            "Reproduction found related failures",
            "Parquity scan evidence",
            "Replay  Reproduced: 1",
            "New replay observations",
            "duckdb recorded a new error",
        ),
    )
    for status, title in (
        ("REPRODUCED", "Recorded failures reproduced"),
        ("RELATED_FAILURE", "Reproduction found related failures"),
        ("NOT_REPRODUCED", "Recorded failures not reproduced"),
    ):
        title_only = plain(
            _terminal_bytes(
                monkeypatch,
                {"command": "replay", "status": status},
                term="dumb",
            )
        )
        assert title in title_only
        assert "Recorded behavior" not in title_only


def test_terminal_style_and_repeatability_policy_is_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document: dict[str, object] = {"command": "check", "status": "RUN_PUBLISHED"}
    styled = _terminal_bytes(monkeypatch, document, _CAPTURE_VIEW)
    assert styled == _terminal_bytes(monkeypatch, document, _CAPTURE_VIEW)
    assert b"\x1b" in styled
    plain_bytes = _terminal_bytes(monkeypatch, document, _CAPTURE_VIEW, no_color=True)
    assert plain_bytes == _terminal_bytes(monkeypatch, document, _CAPTURE_VIEW, term="dumb")
    assert b"\x1b" not in plain_bytes
    assert plain(styled) == plain_bytes.decode()
