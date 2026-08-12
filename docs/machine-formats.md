# Machine format overview

This reference is for tools that read Parquity JSON. People reviewing a run
should start with `REPORT.md`; command syntax and replay behavior are documented
in [Using Parquity](usage.md) and [Evidence and replay](evidence.md).

The installed Parquity decoders are the supported interface for consuming these
formats. This overview is not a standalone, language-neutral specification.
Parquity does not publish separate JSON Schema files. The versioned decoders
linked below are the executable definitions: they validate types, required
fields, ordering, identities, bounds, and cross-field invariants.

## JSON encoding

Canonical documents are UTF-8 JSON with:

- object keys sorted lexicographically;
- no insignificant whitespace;
- non-ASCII text preserved as UTF-8;
- no duplicate object keys; and
- finite JSON floating-point values only; non-finite tokens and values outside
  Python's finite float range are rejected.

Identity and artifact digests use lowercase SHA-256 over the documented
canonical bytes. The shared implementation is
[`evidence/json_codec.py`](../src/parquity/evidence/json_codec.py).

## Format registry

| Identity | Purpose | Executable definition |
|---|---|---|
| `parquity.case.v1` | Logical schema and rows | [`model.py`](../src/parquity/model.py), [`case/`](../src/parquity/case/) |
| `parquity.finding.v1` | Standalone generated reproducer | [`findings/model.py`](../src/parquity/findings/model.py) |
| `parquity.run.v1` | Legacy generated aggregate, accepted for replay | [`runs/formats/v1.py`](../src/parquity/runs/formats/v1.py) |
| `parquity.run.v2` | Current check and fuzz aggregate | [`runs/formats/v2.py`](../src/parquity/runs/formats/v2.py) |
| `parquity.scan-finding.v1` | Legacy standalone scan evidence | [`scans/records/finding.py`](../src/parquity/scans/records/finding.py) |
| `parquity.scan-finding.v2` | Current standalone scan evidence | [`scans/records/finding.py`](../src/parquity/scans/records/finding.py) |
| `parquity.scan-run.v1` | Legacy scan aggregate, accepted for replay | [`scans/records/run.py`](../src/parquity/scans/records/run.py) |
| `parquity.scan-run.v2` | Current scan aggregate | [`scans/records/run.py`](../src/parquity/scans/records/run.py) |
| `parquity.cli.v1` | Redirected or `--json` command result | [`cli/output.py`](../src/parquity/cli/output.py) and command projections under [`cli/`](../src/parquity/cli/) |

`parquity.finding-key.v1` and `parquity.generated-occurrence.v1` are subordinate
identities used inside `parquity.run.v2`. `parquity.scan-symptom.v1` identifies
the occurrence projection derived from validated scan records. They are not
standalone files.

## Case

A `parquity.case.v1` object has exactly:

```text
format, schema, rows
```

`schema` is a non-empty ordered array of unique top-level fields. `rows` is an
ordered array whose width must equal the schema width. Nested type and value
rules, including canonical binary encoding, are defined in
[Writing Cases](cases.md).

`case_id` is the lowercase SHA-256 digest of the complete canonical Case. It is
therefore an identity for schema and rows, not for schema alone.

## Generated evidence

### Standalone reproducer

`parquity.finding.v1` uses these required fields:

```text
format, finding_id, case_id, command, writers, readers, discovery,
environment, reduction, fingerprint, replay_signature, result,
input_parquet, artifacts
```

`generation` and `writer_profiles` are present only when applicable. The
artifact inventory is exact and every retained file is bound by path, byte
count, and SHA-256 digest.

`finding_id` is SHA-256 over canonical JSON containing the final `case_id` and
the exact failure fingerprint. A fingerprint includes the writer and reader
versions, operation, result kind, exact structural path, diagnostic kind,
normalized-detail digest, and optional exact writer-profile identity.

### Current aggregate

`parquity.run.v2` has these required top-level fields:

```text
format, finding_key_format, run_id, command, status, writers, readers,
discovery, evaluated_inputs, executed_checks, environment, saved_evidence,
manifest_only_evidence, occurrences, report
```

`writer_profiles` is optional. The arrays are canonical and validated as one
partition:

- `saved_evidence` indexes standalone reproducer directories;
- `manifest_only_evidence` retains a bounded exact representative when no
  standalone directory was saved; and
- `occurrences` records each distinct exact `(case_id, fingerprint)` target
  observed during discovery or admitted minimization.

Each occurrence has exactly:

```text
occurrence_format, occurrence_id, case_id, fingerprint, origin
```

`occurrence_id` is SHA-256 over its format identity, `case_id`, and exact
fingerprint. Occurrences must be unique and canonically ordered.

`finding_key_format` is `parquity.finding-key.v1`. The key is derived only from
an exact fingerprint and contains:

```text
writer, reader, operation, verdict, diagnostic_kind,
normalized_detail_sha256, structural location class, writer_profile
```

Provider versions are omitted because one run binds a single immutable
provider roster. Exact field indexes and row indexes are normalized into a
structural location class; map key/value, list item, entry, and structural
depth remain distinct. Unrecognized paths remain exact opaque values.

The key controls retention and minimization. It is not an estimate of upstream
bug count. The exact fingerprint remains in persisted evidence and replay.

`run_id` is SHA-256 over the canonical v2 identity fields. It omits itself and
the rendered-report digest; saved child indexes already bind their manifest
digests.

### Legacy aggregate

`parquity.run.v1` remains accepted for validation and replay. Its top-level
shape is:

```text
format, run_id, command, status, writers, readers, discovery, environment,
findings, overflow, report
```

`writer_profiles` is optional. New check and fuzz runs use v2; v1 documents are
not rewritten. V1 retains the historical `max_findings` field and
`FINDING_CAP_REACHED` token where those appear in its nested discovery data.
V2 uses `max_saved` and `SAVED_EVIDENCE_LIMIT_REACHED`.

Standalone generated children remain `parquity.finding.v1` under both run
generations.

## Scan evidence

### Standalone scan evidence

Both scan-finding generations use:

```text
format, finding_id, parquity_version, source, engines, timeout_seconds,
scan_status, outcomes, observation_groups, comparisons, signature_sha256,
artifacts
```

V2 additionally requires `environment`. `source` contains the portable path,
byte count, and source SHA-256. Reader outcomes are in engine order. Successful
readers belong to canonical observation groups; comparisons contain every
pair of distinct groups. The artifact inventory is exact.

### Scan aggregate

Both scan-run generations use:

```text
format, scan_id, parquity_version, status, input_kind, discovery, limits,
engines, timeout_seconds, stop_reason, findings, overflow, report
```

V1 adds `max_findings`. V2 replaces it with `max_saved` and also requires
`environment`. V1 spells the saved-evidence stop as `FINDING_CAP_REACHED`; v2
uses `SAVED_EVIDENCE_LIMIT_REACHED`. Findings follow discovered-file order;
overflow is the exact unevaluated suffix when the limit stops the run.

For standalone scan evidence, `signature_sha256` binds the source path, source
digest and size, reader names, timeout, outcomes without provider-version
fields, observation groups, and comparisons. `finding_id` is SHA-256 over
canonical JSON containing that signature. `scan_id` is SHA-256 over the
canonical aggregate with `scan_id` replaced by an empty string.

The scan occurrence and grouping projection is defined by
[`scans/symptoms.py`](../src/parquity/scans/symptoms.py). It retains failed
reader evidence and complete semantic-comparison edges; it does not reinterpret
one source-file bundle as one failure.

## CLI output

Redirected stdout and `--json` add:

```json
{"format":"parquity.cli.v1"}
```

to the command-specific result. The remaining keys depend on the command and
status. Human terminal output is a projection of that result and is not a
machine format.

The CLI may translate a durable format token for compatibility. In particular,
finite-strategy exhaustion is stored as `STRATEGY_EXHAUSTED` in run v2 and is
projected as the established CLI-v1 status `EXAMPLE_BOUND_REACHED`. Do not
derive artifact grammar from CLI spelling.

## Decoder and compatibility rules

- Select a decoder from the explicit `format` value; do not infer a format
  from filenames or fields.
- Preserve unknown format generations rather than coercing them to a known
  generation.
- Validate the complete bundle before provider execution.
- Treat IDs, digests, byte counts, array order, and artifact inventories as
  bound evidence, not display metadata.
- Do not edit a bound file in place. Publish a new bundle instead.

Format evolution policy is defined in [Versioning](../VERSIONING.md).
