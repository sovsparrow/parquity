from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from parquity.evidence.storage import DestinationExistsError
from parquity.generation import evidence
from parquity.generation.search.records import OverflowObservation
from parquity.runs import bundle
from parquity.verdicts import FailureFingerprint
from tests.support.generated_run import CASE, FAILURES, evaluate, published_run, source


def test_direct_publication_maps_destination_race_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "run"

    def race(_: Path, target: Path) -> None:
        raise DestinationExistsError(target)

    monkeypatch.setattr(bundle, "atomic_publish_directory", race)
    with pytest.raises(bundle.RunPublicationError) as raised:
        bundle.publish_run(source(), destination, evaluate)

    assert (raised.value.kind, raised.value.detail) == (
        "OUTPUT_EXISTS",
        "output path already exists",
    )
    assert not destination.exists() and tuple(tmp_path.iterdir()) == ()


def test_direct_publication_maps_rename_failure_and_cleans_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "run"

    def fail_rename(_: Path, __: Path) -> None:
        raise OSError("controlled rename failure")

    monkeypatch.setattr(bundle, "atomic_publish_directory", fail_rename)
    with pytest.raises(bundle.RunPublicationError) as raised:
        bundle.publish_run(source(), destination, evaluate)

    assert (raised.value.kind, raised.value.detail) == (
        "OUTPUT_ERROR",
        "output path could not be published",
    )
    assert not destination.exists() and tuple(tmp_path.iterdir()) == ()


def test_v1_publication_keeps_exact_wire_order_and_identity(tmp_path: Path) -> None:
    saved = source().findings
    overflow = tuple(
        OverflowObservation(
            CASE,
            replace(result, detail=f"overflow {index}"),
            evidence.DISCOVERY_OVERFLOW,
        )
        for index, result in enumerate(FAILURES[:2])
    )
    first_source = source(
        command="fuzz",
        stops=overflow,
        items=tuple(reversed(saved)),
    )
    second_source = source(
        command="fuzz",
        stops=tuple(reversed(overflow)),
        items=saved,
    )

    first, _ = published_run(tmp_path, "first-wire-order", first_source)
    second, _ = published_run(tmp_path, "second-wire-order", second_source)

    finding_fingerprints = tuple(item.fingerprint for item in first.findings)
    overflow_fingerprints = tuple(item.fingerprint for item in first.overflow)
    assert finding_fingerprints == tuple(
        sorted(finding_fingerprints, key=FailureFingerprint.canonical_bytes)
    )
    assert overflow_fingerprints == tuple(
        sorted(overflow_fingerprints, key=FailureFingerprint.canonical_bytes)
    )
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.run_id == second.run_id
    assert tuple(item.finding_id for item in first.findings) == tuple(
        item.finding_id for item in second.findings
    )
