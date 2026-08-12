from __future__ import annotations

import io
import threading
from collections.abc import Callable
from typing import Protocol, cast

import pytest

from parquity.cli import progress
from parquity.generation.progress import FuzzPhase, FuzzProgress


class _IndicatorView(Protocol):
    stopped: threading.Event


class _FrameStream(io.StringIO):
    def __init__(self, rendered: threading.Event) -> None:
        super().__init__()
        self.rendered = rendered

    def write(self, value: str) -> int:
        written = super().write(value)
        if "Lifecycle" in value:
            self.rendered.set()
        return written


def test_fuzz_progress_uses_finding_counts_for_every_phase() -> None:
    discovery = FuzzProgress(FuzzPhase.DISCOVERY, 2, 3, 1, 1)
    minimizing = FuzzProgress(FuzzPhase.MINIMIZATION, 2, 3, 1, 1, 0, 1)
    writing = FuzzProgress(FuzzPhase.EVIDENCE_WRITING, 2, 3, 1, 1, 0, 1)
    finalizing = FuzzProgress(FuzzPhase.FINALIZATION, 2, 3, 1, 1, 1, 1)

    assert progress.fuzz_label(discovery).endswith("1 retained finding · 1 additional finding")
    assert progress.fuzz_label(minimizing) == "Minimizing · 0/1 finding"
    assert progress.fuzz_label(writing) == "Writing evidence · 0/1 finding"
    assert progress.fuzz_label(finalizing) == "Finalizing evidence · 1 finding"


def test_real_indicator_worker_renders_and_is_fully_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduled = threading.Event()
    rendered = threading.Event()
    created: list[threading.Thread] = []

    def thread_factory(target: Callable[[], None]) -> threading.Thread:
        def synchronized_target() -> None:
            scheduled.set()
            target()

        thread = threading.Thread(
            target=synchronized_target,
            daemon=True,
            name="parquity-progress-lifecycle-test",
        )
        created.append(thread)
        return thread

    monkeypatch.setattr(progress, "_animation_thread", thread_factory)
    monkeypatch.setattr(progress.sys, "stderr", stream := _FrameStream(rendered))
    active_slot = cast(list[object | None], vars(progress)["_active"])

    with progress.indicator("Lifecycle", enabled=True):
        assert scheduled.wait(timeout=1), "progress worker did not start"
        assert rendered.wait(timeout=1), "progress worker did not render"
        active = cast(_IndicatorView | None, active_slot[0])
        assert active is not None

    assert len(created) == 1
    worker = created[0]
    worker.join(timeout=1)
    assert active_slot[0] is None
    assert active.stopped.is_set()
    assert not worker.is_alive()
    assert worker not in threading.enumerate()
    assert "Lifecycle" in stream.getvalue()
