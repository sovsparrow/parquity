from __future__ import annotations

from dataclasses import fields, replace
from itertools import permutations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from parquity.generation.search.identity import FindingKey, finding_key
from parquity.profiles import WriterProfileIdentity
from parquity.verdicts import FailureFingerprint, Verdict

_ENGINES = st.sampled_from(("duckdb", "polars", "pyarrow"))
_VERSIONS = st.text(
    alphabet=st.characters(min_codepoint=48, max_codepoint=122),
    min_size=1,
    max_size=8,
)
_DIGESTS = st.binary(min_size=32, max_size=32).map(bytes.hex)
_PATHS = st.sampled_from(
    ("$", "$schema", "$schema.value", "$rows", "$rows[0].value", "$data[7].value")
)
_FINGERPRINTS: st.SearchStrategy[FailureFingerprint] = st.one_of(
    st.builds(
        FailureFingerprint,
        writer=_ENGINES,
        writer_version=_VERSIONS,
        reader=st.just("*"),
        reader_version=st.just("*"),
        operation=st.just("write"),
        verdict=st.just(Verdict.WRITE_ERROR),
        schema_path=_PATHS,
        diagnostic_kind=st.sampled_from(("ArrowInvalid", "ControlledError")),
        normalized_detail_sha256=_DIGESTS,
    ),
    st.builds(
        FailureFingerprint,
        writer=_ENGINES,
        writer_version=_VERSIONS,
        reader=_ENGINES,
        reader_version=_VERSIONS,
        operation=st.just("read"),
        verdict=st.just(Verdict.READ_ERROR),
        schema_path=_PATHS,
        diagnostic_kind=st.sampled_from(("ArrowInvalid", "ControlledError")),
        normalized_detail_sha256=_DIGESTS,
    ),
    st.builds(
        FailureFingerprint,
        writer=_ENGINES,
        writer_version=_VERSIONS,
        reader=_ENGINES,
        reader_version=_VERSIONS,
        operation=st.just("compare"),
        verdict=st.sampled_from(
            (Verdict.ROW_COUNT_MISMATCH, Verdict.SCHEMA_MISMATCH, Verdict.VALUE_MISMATCH)
        ),
        schema_path=_PATHS,
        diagnostic_kind=st.sampled_from(("Mismatch", "ValueError")),
        normalized_detail_sha256=_DIGESTS,
    ),
)


def _fingerprint(
    *,
    writer: str = "alpha",
    reader: str = "beta",
    operation: str = "compare",
    verdict: Verdict = Verdict.VALUE_MISMATCH,
    path: str = "$schema.value",
    diagnostic_kind: str = "Mismatch",
    digest: str = "0" * 64,
    writer_version: str = "1",
    reader_version: str = "2",
    profile: WriterProfileIdentity | None = None,
) -> FailureFingerprint:
    return FailureFingerprint(
        writer,
        writer_version,
        reader,
        reader_version,
        operation,
        verdict,
        path,
        diagnostic_kind,
        digest,
        profile,
    )


@settings(max_examples=80, derandomize=True, database=None, deadline=None)
@given(fingerprint=_FINGERPRINTS)
def test_factory_is_total_deterministic_and_preserves_fingerprint_equality(
    fingerprint: FailureFingerprint,
) -> None:
    first = finding_key(fingerprint)
    second = finding_key(replace(fingerprint))

    assert first == second
    assert hash(first) == hash(second)


def test_direct_construction_is_refused() -> None:
    with pytest.raises(TypeError, match=r"derived with finding_key\(\)"):
        FindingKey()


def test_factory_retains_only_the_contract_fields_and_exact_profile() -> None:
    profile = WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
    fingerprint = _fingerprint(profile=profile)
    key = finding_key(fingerprint)

    assert tuple(field.name for field in fields(FindingKey)) == (
        "writer",
        "reader",
        "operation",
        "verdict",
        "diagnostic_kind",
        "normalized_detail_sha256",
        "location_class",
        "writer_profile",
    )
    assert key.writer == "alpha"
    assert key.reader == "beta"
    assert key.operation == "compare"
    assert key.verdict is Verdict.VALUE_MISMATCH
    assert key.diagnostic_kind == "Mismatch"
    assert key.normalized_detail_sha256 == "0" * 64
    assert key.location_class == "opaque:$schema.value"
    assert key.writer_profile == profile
    assert not hasattr(key, "writer_version")
    assert not hasattr(key, "reader_version")
    assert not hasattr(key, "schema_path")
    assert finding_key(replace(fingerprint, writer_version="9", reader_version="8")) == key
    generated = replace(fingerprint, schema_path="$schema.field_0")
    assert finding_key(replace(generated, schema_path="$schema.field_9")) == finding_key(generated)
    assert finding_key(replace(fingerprint, writer_profile=None)) != key
    different = WriterProfileIdentity("row-group-2", {"row_group_size": 2})
    assert finding_key(replace(fingerprint, writer_profile=different)) != key


@pytest.mark.parametrize(
    ("path", "expected"),
    (
        ("$", "root"),
        ("$schema", "schema"),
        ("$schema.field_0", "schema/field"),
        ("$schema.field_17[]", "schema/field/item"),
        ("$schema.field_2.key", "schema/field/key"),
        ("$schema.field_2.value", "schema/field/value"),
        ("$schema.field_2.child_4", "schema/field/field"),
        ("$rows", "rows"),
        ("$rows[0].field_0", "rows/field"),
        ("$rows[17].field_8[3]", "rows/field/item"),
        (
            "$rows[2].field_1.entries[sha256=" + "a" * 64 + "].value",
            "rows/field/entry/value",
        ),
        ("$schema_value", "opaque:$schema_value"),
        ("$rows.value", "opaque:$rows.value"),
        ("$data[0].value", "opaque:$data[0].value"),
    ),
)
def test_location_classes_are_anchored_and_unknown_paths_remain_exact(
    path: str, expected: str
) -> None:
    assert finding_key(_fingerprint(path=path)).location_class == expected


def test_unknown_location_fallback_does_not_coarsen_opaque_paths() -> None:
    first = finding_key(_fingerprint(path="$data[0].value"))
    second = finding_key(_fingerprint(path="$data[1].value"))

    assert first != second


def test_generated_location_coarsens_ordinals_but_preserves_role_and_depth() -> None:
    first_field = finding_key(_fingerprint(path="$schema.field_0"))
    later_field = finding_key(_fingerprint(path="$schema.field_9"))
    first_item = finding_key(_fingerprint(path="$schema.field_0[]"))
    later_item = finding_key(_fingerprint(path="$schema.field_9[]"))

    assert first_field == later_field
    assert first_item == later_item
    assert (
        len(
            {
                first_field,
                first_item,
                finding_key(_fingerprint(path="$schema.field_0.key")),
                finding_key(_fingerprint(path="$schema.field_0.value")),
                finding_key(_fingerprint(path="$schema.field_0[].value")),
            }
        )
        == 5
    )


def test_total_order_uses_the_contract_tuple_for_every_fixed_permutation() -> None:
    self_route = finding_key(_fingerprint(writer="zeta", reader="zeta"))
    row_mismatch = finding_key(
        _fingerprint(verdict=Verdict.ROW_COUNT_MISMATCH, diagnostic_kind="Zulu")
    )
    schema_mismatch = finding_key(
        _fingerprint(verdict=Verdict.SCHEMA_MISMATCH, diagnostic_kind="Alpha")
    )
    value_mismatch = finding_key(_fingerprint(diagnostic_kind="Alpha"))
    expected = (self_route, row_mismatch, schema_mismatch, value_mismatch)

    for values in permutations(reversed(expected)):
        assert tuple(sorted(values)) == expected


@pytest.mark.parametrize(
    ("left", "right"),
    (
        (
            _fingerprint(operation="compare", verdict=Verdict.VALUE_MISMATCH),
            _fingerprint(operation="read", verdict=Verdict.READ_ERROR),
        ),
        (
            _fingerprint(writer="alpha", reader="zeta"),
            _fingerprint(writer="beta", reader="zeta"),
        ),
        (
            _fingerprint(writer="alpha", reader="beta"),
            _fingerprint(writer="alpha", reader="gamma"),
        ),
        (
            _fingerprint(diagnostic_kind="Alpha"),
            _fingerprint(diagnostic_kind="Beta"),
        ),
        (
            _fingerprint(path="$data[0]"),
            _fingerprint(path="$data[1]"),
        ),
        (
            _fingerprint(profile=None),
            _fingerprint(
                profile=WriterProfileIdentity("compression-gzip", {"compression": "gzip"})
            ),
        ),
        (
            _fingerprint(digest="0" * 64),
            _fingerprint(digest="1" * 64),
        ),
    ),
)
def test_later_order_dimensions_break_ties_lexically(
    left: FailureFingerprint, right: FailureFingerprint
) -> None:
    assert finding_key(left) < finding_key(right)
