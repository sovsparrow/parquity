from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from parquity.evidence import (
    DependencyVersion,
    DifferenceEvidence,
    EngineVersion,
    EnvironmentEvidence,
    FingerprintSelectionIssue,
    digest_matches,
    engine_selection_is_valid,
    engine_versions_from_data,
    fingerprint_selection_issue,
    normalize_detail,
    provider_inventory_matches,
    sha256_hex,
)
from parquity.evidence import json_codec as codec
from parquity.evidence.storage import (
    DestinationExistsError,
    atomic_publish_directory,
    require_destination_absent,
    staging_directory,
)
from parquity.findings import OPTIONAL_INPUT, REQUIRED_ARTIFACTS
from parquity.findings.model import (
    ArtifactDigest,
    FindingRecord,
    ReductionEvidence,
    ReplaySignature,
    finding_id_for,
)
from parquity.generation.evidence import EXAMPLE_BOUND_REACHED, DiscoveryEvidence
from parquity.model import Case, Field, Kind, TypeSpec
from parquity.profiles import (
    CapabilityStatus,
    WriterProfileCapability,
    WriterProfileIdentity,
    WriterProfilePlan,
)
from parquity.verdicts import CellResult, Verdict


def _finding() -> FindingRecord:
    case = Case((Field("value", TypeSpec(Kind.INT32)),), ((1,),))
    result = CellResult(
        "pyarrow", "1", "duckdb", "2", "compare", Verdict.VALUE_MISMATCH, "$", "mismatch"
    )
    fingerprint = result.fingerprint
    assert fingerprint is not None
    providers = (EngineVersion("pyarrow", "1"), EngineVersion("duckdb", "2"))
    artifacts = tuple(
        ArtifactDigest(name, "0" * 64, index)
        for index, name in enumerate(sorted((*REQUIRED_ARTIFACTS, OPTIONAL_INPUT)))
    )
    return FindingRecord(
        finding_id_for(case.case_id, fingerprint),
        case.case_id,
        "fuzz",
        providers[:1],
        providers[1:],
        DiscoveryEvidence(25, 7, 8, EXAMPLE_BOUND_REACHED),
        EnvironmentEvidence(
            "0.1.0",
            "6.165.1",
            "3.12.0",
            "controlled-platform",
            providers,
            (DependencyVersion("pyarrow", "1"),),
        ),
        ReductionEvidence(case.case_id, case.case_id, False, 0, 0, 0, 0, 0),
        fingerprint,
        ReplaySignature.from_fingerprint(fingerprint),
        result,
        True,
        artifacts,
    )


def test_strict_json_preserves_canonical_finite_bytes_and_digest_primitives() -> None:
    value = {"z": "café", "a": [1, 1.25, True]}
    expected = b'{"a":[1,1.25,true],"z":"caf\xc3\xa9"}'

    assert codec.canonical_bytes(value) == expected
    assert codec.decode(expected) == value
    assert codec.is_canonical_json(expected)
    assert codec.canonical_bytes_match(expected, value)
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert digest_matches(b"abc", sha256_hex(b"abc"), 3)
    assert not digest_matches(b"abc", sha256_hex(b"abd"), 3)
    assert not digest_matches(b"abc", sha256_hex(b"abc"), 2)
    with pytest.raises(ValueError):
        codec.canonical_bytes({"value": float("nan")})


@pytest.mark.parametrize(
    ("payload", "neutral_message"),
    (
        (b'{"format":"x","format":"x"}', "duplicate JSON field: format"),
        (b'{"format":NaN}', "raw JSON non-finite token is invalid: NaN"),
        (b'{"format":1e999}', "JSON numeric token exceeds the finite float range"),
    ),
)
def test_strict_json_rejects_duplicate_and_nonfinite_tokens(
    payload: bytes,
    neutral_message: str,
) -> None:
    with pytest.raises(codec.EvidenceValidationError, match=neutral_message):
        codec.decode(payload)


def test_engine_selection_primitives_preserve_boundary_policy() -> None:
    pyarrow = EngineVersion.from_data({"name": "pyarrow", "version": "1"})
    duckdb = EngineVersion.from_data({"name": "duckdb", "version": "2"})
    assert engine_selection_is_valid((pyarrow, duckdb))
    assert not engine_selection_is_valid(())
    assert not engine_selection_is_valid((pyarrow, pyarrow))
    assert provider_inventory_matches((pyarrow,), (duckdb,), (pyarrow, duckdb))


@pytest.mark.parametrize(
    ("decoder", "payload", "message"),
    (
        (
            EngineVersion.from_data,
            {"name": 7, "version": "1"},
            "engine name must be a string",
        ),
        (
            EngineVersion.from_data,
            {"name": "engine", "version": ""},
            "engine version evidence is malformed",
        ),
        (
            DifferenceEvidence.from_data,
            {"expected": 1, "observed": "after"},
            "difference evidence values must be strings",
        ),
        (
            DifferenceEvidence.from_data,
            {"expected": "before", "observed": ""},
            "difference evidence values must not be empty",
        ),
    ),
)
def test_evidence_values_reject_malformed_public_data(
    decoder: Callable[[dict[str, object]], object],
    payload: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        decoder(payload)


@pytest.mark.parametrize(
    ("value", "message"),
    (
        (None, "writers must be an array"),
        (({"name": "engine"},), "engine version fields are malformed"),
    ),
)
def test_engine_version_collections_reject_invalid_shapes(value: object, message: str) -> None:
    with pytest.raises(codec.EvidenceValidationError, match=message):
        engine_versions_from_data(value, "writers")


def test_fingerprint_selection_reports_each_issue_reachable_from_valid_evidence() -> None:
    fingerprint = _finding().fingerprint
    writer = EngineVersion(fingerprint.writer, fingerprint.writer_version)
    reader = EngineVersion(fingerprint.reader, fingerprint.reader_version)
    profile = WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    other_profile = WriterProfileIdentity("row-group-2", {"row_group_size": 3})
    profiled = replace(fingerprint, writer_profile=profile)
    capability = WriterProfileCapability(
        writer, "row-group-2", CapabilityStatus.SUPPORTED, other_profile
    )
    plan = WriterProfilePlan(("row-group-2",), (capability,))

    assert fingerprint_selection_issue(fingerprint, (writer,), (reader,), None) is None
    scenarios = (
        (fingerprint, (), (reader,), None, FingerprintSelectionIssue.WRITER),
        (fingerprint, (writer,), (), None, FingerprintSelectionIssue.READER),
        (profiled, (writer,), (reader,), None, FingerprintSelectionIssue.PROFILE_PLAN),
        (profiled, (writer,), (reader,), plan, FingerprintSelectionIssue.PROFILE),
    )
    for candidate, writers, readers, profiles, expected in scenarios:
        assert fingerprint_selection_issue(candidate, writers, readers, profiles) is expected


def test_direct_results_and_fingerprints_enforce_one_shape_contract() -> None:
    finding = _finding()
    fingerprint = finding.fingerprint
    assert fingerprint.canonical_bytes() == (
        b'{"diagnostic_kind":"VALUE_MISMATCH","normalized_detail_sha256":'
        b'"5acbfff1b086e0f920c5857527976199018afe0cbf16e28d42c7eb9c683508e5",'
        b'"operation":"compare","reader":"duckdb","reader_version":"2",'
        b'"schema_path":"$","verdict":"VALUE_MISMATCH","writer":"pyarrow",'
        b'"writer_version":"1"}'
    )

    invalid_shapes = (
        {"operation": "write", "verdict": Verdict.WRITE_ERROR},
        {
            "operation": "read",
            "verdict": Verdict.READ_ERROR,
            "reader": "*",
            "reader_version": "*",
        },
        {"operation": "compare", "verdict": Verdict.READ_ERROR},
    )
    for changes in invalid_shapes:
        with pytest.raises(ValueError, match="result fields conflict"):
            replace(finding.result, **changes)
        with pytest.raises(ValueError, match="fingerprint fields conflict"):
            replace(fingerprint, **changes)


def test_neutral_publication_staging_owns_creation_cleanup_and_atomic_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(DestinationExistsError):
        require_destination_absent(existing)

    destination = tmp_path / "published"
    with staging_directory(destination, publication_name="payload") as staging:
        staging.mkdir()
        (staging / "evidence").write_bytes(b"bound")
        atomic_publish_directory(staging, destination)
    assert (destination / "evidence").read_bytes() == b"bound"
    assert {path.name for path in tmp_path.iterdir()} == {"existing", "published"}

    before = {path.name for path in tmp_path.iterdir()}
    with (
        pytest.raises(RuntimeError, match="body failed"),
        staging_directory(tmp_path / "body-error") as staging,
    ):
        (staging / "partial").write_bytes(b"partial")
        raise RuntimeError("body failed")
    assert {path.name for path in tmp_path.iterdir()} == before

    rename_error = OSError("controlled rename failure")
    for race in (True, False):
        target = tmp_path / f"rename-{'race' if race else 'error'}"

        def fail_rename(source: Path, destination: Path, destination_race: bool = race) -> None:
            del source
            if destination_race:
                destination.mkdir()
            raise rename_error

        expected = DestinationExistsError if race else OSError
        with monkeypatch.context() as faults, pytest.raises(expected) as raised:
            faults.setattr(Path, "rename", fail_rename)
            with staging_directory(target) as staging:
                atomic_publish_directory(staging, target)
        assert raised.value.__cause__ is rename_error if race else raised.value is rename_error
        assert target.exists() is race
        assert not tuple(tmp_path.glob(f".{target.name}.parquity*"))


def test_normalized_detail_is_independent_of_the_recording_platform() -> None:
    # The normalized detail is what FailureFingerprint hashes into normalized_detail_sha256, which
    # in turn feeds finding_id_for and ReplaySignature. Substituting the transient root leaves the
    # rest of the path behind it, so a native separator there gives one failure two identities and
    # evidence recorded on one platform cannot replay against another. A backslash is an ordinary
    # character in a POSIX path, so this pins the behaviour wherever the suite runs.
    windows = normalize_detail(
        r"write failed at C:\parquity\run\pyarrow.parquet", (Path(r"C:\parquity\run"),)
    )
    posix = normalize_detail(
        "write failed at /parquity/run/pyarrow.parquet", (PurePosixPath("/parquity/run"),)
    )

    assert windows == "write failed at <parquity-temp>/pyarrow.parquet"
    assert posix == "write failed at <parquity-temp>/pyarrow.parquet"
    assert sha256_hex(windows.encode()) == sha256_hex(posix.encode())
