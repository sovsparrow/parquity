from __future__ import annotations

from collections.abc import Mapping

from ..result_evidence import DifferenceEvidence
from ..verdicts import CellResult, FailureFingerprint, Verdict
from ..writer_profiles import WriterProfileIdentity
from . import json_codec as codec


def fingerprint_from_data(
    data: Mapping[str, object], *, allow_profile: bool = False
) -> FailureFingerprint:
    keys = {
        "writer",
        "writer_version",
        "reader",
        "reader_version",
        "operation",
        "verdict",
        "schema_path",
        "diagnostic_kind",
        "normalized_detail_sha256",
    }
    profile = _profile_from_data(data, keys, allow_profile, "failure fingerprint")
    try:
        fingerprint = FailureFingerprint(
            writer=codec.string(codec.required(data, "writer"), "writer"),
            writer_version=codec.string(codec.required(data, "writer_version"), "writer_version"),
            reader=codec.string(codec.required(data, "reader"), "reader"),
            reader_version=codec.string(codec.required(data, "reader_version"), "reader_version"),
            operation=codec.string(codec.required(data, "operation"), "operation"),
            verdict=_verdict(codec.required(data, "verdict")),
            schema_path=codec.string(codec.required(data, "schema_path"), "schema_path"),
            diagnostic_kind=codec.string(
                codec.required(data, "diagnostic_kind"), "diagnostic_kind"
            ),
            normalized_detail_sha256=codec.string(
                codec.required(data, "normalized_detail_sha256"), "normalized detail SHA-256"
            ),
            writer_profile=profile,
        )
    except ValueError as error:
        raise codec.FindingValidationError("failure fingerprint is malformed") from error
    if not fingerprint_shape_is_valid(fingerprint):
        raise codec.FindingValidationError("failure fingerprint fields conflict")
    return fingerprint


def cell_result_from_data(data: Mapping[str, object], *, allow_profile: bool = False) -> CellResult:
    keys = {
        "writer",
        "writer_version",
        "reader",
        "reader_version",
        "operation",
        "verdict",
        "schema_path",
        "detail",
        "diagnostic_kind",
    }
    difference = None
    if "difference" in data:
        keys.add("difference")
        try:
            difference = DifferenceEvidence.from_data(
                codec.mapping(codec.required(data, "difference"), "difference")
            )
        except ValueError as error:
            raise codec.FindingValidationError("difference evidence is malformed") from error
    profile = _profile_from_data(data, keys, allow_profile, "matrix result")
    writer = codec.string(codec.required(data, "writer"), "writer")
    writer_version = codec.string(codec.required(data, "writer_version"), "writer_version")
    reader = codec.string(codec.required(data, "reader"), "reader")
    reader_version = codec.string(codec.required(data, "reader_version"), "reader_version")
    operation = codec.string(codec.required(data, "operation"), "operation")
    verdict = _verdict(codec.required(data, "verdict"))
    schema_path = codec.string(codec.required(data, "schema_path"), "schema_path")
    detail = codec.string(codec.required(data, "detail"), "detail")
    diagnostic_kind = codec.string(codec.required(data, "diagnostic_kind"), "diagnostic_kind")
    try:
        return CellResult(
            writer=writer,
            writer_version=writer_version,
            reader=reader,
            reader_version=reader_version,
            operation=operation,
            verdict=verdict,
            schema_path=schema_path,
            detail=detail,
            diagnostic_kind=diagnostic_kind,
            writer_profile=profile,
            difference=difference,
        )
    except ValueError as error:
        raise codec.FindingValidationError("matrix result is malformed") from error


def _profile_from_data(
    data: Mapping[str, object],
    base_keys: set[str],
    allow_profile: bool,
    label: str,
) -> WriterProfileIdentity | None:
    has_profile = "writer_profile" in data
    if has_profile and not allow_profile:
        codec.require_exact_keys(data, base_keys, label)
    expected = set(base_keys)
    if has_profile:
        expected.add("writer_profile")
    codec.require_exact_keys(data, expected, label)
    if not has_profile:
        return None
    return WriterProfileIdentity.from_data(
        codec.mapping(codec.required(data, "writer_profile"), "writer_profile")
    )


def fingerprint_shape_is_valid(fingerprint: FailureFingerprint) -> bool:
    if fingerprint.operation == "write":
        return (
            fingerprint.verdict is Verdict.WRITE_ERROR
            and fingerprint.reader == "*"
            and fingerprint.reader_version == "*"
        )
    if fingerprint.operation == "read":
        return fingerprint.verdict is Verdict.READ_ERROR and fingerprint.reader != "*"
    if fingerprint.operation == "compare":
        return (
            fingerprint.verdict
            in (
                Verdict.SCHEMA_MISMATCH,
                Verdict.ROW_COUNT_MISMATCH,
                Verdict.VALUE_MISMATCH,
            )
            and fingerprint.reader != "*"
        )
    return False


def _verdict(value: object) -> Verdict:
    try:
        return Verdict(codec.string(value, "verdict"))
    except ValueError as error:
        raise codec.FindingValidationError("verdict is not recognized") from error


__all__ = ["cell_result_from_data", "fingerprint_from_data", "fingerprint_shape_is_valid"]
