# Evidence and replay

When `check`, `fuzz`, or `scan` publishes an output directory, open its
`REPORT.md` first. The report points to retained findings and summarizes the
selected providers, inputs, results, and any bounded overflow.

The JSON manifests are the authoritative record. Parquity preserves provider
versions, directions, options, outcomes, hashes, and reproduction material so
a result does not depend on terminal text.

Evidence remains neutral. A majority of readers is not an oracle, and one
finding is not by itself an upstream defect.

## What a finding looks like

A Parquity 0.1.0 fuzz run recorded this finding:

```text
Parquity observed READ_ERROR for duckdb -> pyarrow during read.
Writer: duckdb 1.5.5
Reader: pyarrow 25.0.0
Diagnostic kind: ArrowInvalid
Normalized detail: Length spanned by list offsets (1) larger than values
  array (length 0)
input.parquet: present
```

The excerpt records one environment. It is not a claim that other provider
versions must produce the same result.

## Generated and scan evidence

Generated evidence starts from a `parquity.case.v1` Case. The Case declares the
expected schema and values, so each writer-reader cell can be compared with the
declared input.

Scan evidence starts from existing Parquet bytes. Each selected reader produces
an independent observation. Parquity compares those observations with each
other; it does not select a reference reader.

The two sources have separate durable formats and identities. They can be
viewed together through triage, but their manifests are not interchangeable.

## Report vocabulary

- A **published run** is an output directory created only after its complete
  bundle is ready. Agreement or no finding creates no run directory.
- An **accepted scan input** is a file that passed the documented discovery,
  file-size, and total-byte limits.
- A **normalized location** is a structural value path used for grouping, such
  as `$.rows[*].columns[0]`; data-dependent row numbers do not split one
  structural symptom into several families.
- **Comparison endpoints** are the exact reader groups on the two sides of a
  semantic difference. Family identity records them so a different reader
  partition cannot merge silently.

## Generated run layout

`check` and `fuzz` publish a `parquity.run.v1` aggregate:

```text
run-directory/
├── run.json
├── REPORT.md
└── findings/
    └── <finding-id>/
        ├── finding.json
        ├── REPORT.md
        ├── case.json
        ├── matrix.json
        ├── reproduce.py
        ├── upstream_repro.py
        ├── discovered_case.json  # when reduction changed the Case
        └── input.parquet         # when the target writer produced bytes
```

Each child is a standalone `parquity.finding.v1` bundle. Copying the child out
of its aggregate does not remove information required for validation or
replay. The aggregate indexes every child and records discovery bounds,
retained findings, and bounded overflow.

`matrix.json` contains the complete final selected matrix for that reduced
Case, not only the target cell. `upstream_repro.py` collects direct provider
evidence for the selected path; it is not a second semantic oracle.

## Scan run layout

`scan` publishes a `parquity.scan-run.v1` aggregate:

```text
scan-run/
├── scan.json
├── REPORT.md
└── findings/
    └── <finding-id>/
        ├── finding.json
        ├── input.parquet
        ├── REPORT.md
        ├── reproduce.py
        └── upstream_repro.py
```

Each `parquity.scan-finding.v1` child is standalone. It binds the exact accepted
input bytes, normalized relative source path, reader order and versions,
timeout, every reader outcome, every comparison, and its reports and scripts.

The parent records bounded discovery, limits, skipped symlinks, stop reason,
overflow, report identity, and every child reference. One source file may
produce several findings when it contains distinct observed symptoms.

## Identities and hashes

Canonical JSON and SHA-256 digests make artifact changes detectable:

- a Case identity hashes its canonical `case.json` bytes;
- a finding identity binds its target and all required child artifacts;
- a run identity binds discovery evidence and its complete child index;
- scan identities additionally bind the accepted source bytes and reader
  observation evidence.

Validation rejects missing, extra, malformed, non-canonical, or digest-mismatched
artifacts before replay starts providers.

These hashes establish internal byte consistency only. They are not digital
signatures, do not identify an author, do not prove provenance, and do not make
retained data anonymous.

## Durable format identities

Saved formats are versioned independently of the Parquity package. Generated
Cases, findings, and runs use `parquity.case.v1`, `parquity.finding.v1`, and
`parquity.run.v1`. Scan findings and aggregates use
`parquity.scan-finding.v1` and `parquity.scan-run.v1`.

Machine-readable command results use `parquity.cli.v1`. Compatible updates may
add fields; consumers must ignore fields they do not recognize.

These identities have exact manifest shapes and inventories. A decoder does
not guess a newer branch. An incompatible change to grammar, inventory,
identity, extraction, or projection requires a new format identity. Derived
triage occurrences and families carry their own format identities because
their grouping rules can evolve without rewriting stored bundles.

Generated and scan manifests are not interchangeable. A standalone finding
cannot be decoded as an aggregate, and a scan finding cannot be decoded as a
generated finding.

## Finding, occurrence, family, and defect

The terms describe different layers:

| Layer | Meaning |
|---|---|
| Matrix cell or reader observation | One engine operation and its result. |
| Finding bundle | One retained non-passing target plus enough context to inspect and replay it. |
| Symptom occurrence | One derived signal inside one validated finding. |
| Symptom family | A deterministic grouping of occurrences with the same signal and canonical evidence shape. |
| Root cause | The implementation condition that produces one or more symptoms; Parquity does not infer it. |
| Upstream defect | A root cause accepted as a defect in an upstream project; a maintainer or investigation establishes it. |

A generated finding has one occurrence. A scan finding has one occurrence for
each failed reader and one for each distinct semantic signal at a normalized
location. Comparisons at the same location remain attached to that occurrence.

Family identity has one signal. Scan families also bind the complete reader
roster and comparison endpoints, so results from different reader matrices do
not merge silently. Row ordinals and package versions remain visible evidence
but do not become family identity.

Triage may therefore report more occurrences than finding bundles, and more or
fewer families than source files. None of those counts is a count of upstream
defects.

Aggregate `REPORT.md` files include these families automatically. The optional
`parquity triage` command exposes the grouping, applies focus filters, and can
attach states from a complete replay document; it does not perform a second
discovery campaign. Pass `--json` for the canonical structured view.

## Replay classifications

Replay validates a bundle, resolves its recorded provider set, and performs a
fresh evaluation. It reports package and provider version drift separately
from reproduction state.

| State | Meaning |
|---|---|
| `REPRODUCED` | The recorded target or occurrence was observed exactly. |
| `RELATED_FAILURE` | The same evidence shape remained but normalized detail changed, or a mixed/new scan symptom prevents an exact aggregate classification. |
| `NOT_REPRODUCED` | The recorded target or occurrence was absent in this evaluation. |
| `NOT_CHECKED` | Triage has no bound replay evidence for the family. |

Scan replay also reports `new_observations` that were not in the original
occurrence inventory. A related or absent state does not mean an upstream fix
was confirmed; provider versions, environment, or behavior may have changed.

Replay exits 1 when at least one recorded target reproduces exactly. It exits 0
when none reproduces exactly, including a related-only result. Missing required
providers, invalid evidence, or an exact writer profile that can no longer be
evaluated exit 2.

## Reports and scripts

`REPORT.md` is a human-readable projection of bound evidence. The canonical
JSON manifests remain authoritative. Reports escape untrusted text. Long
diagnostics are truncated in the report; their complete text remains bound by
the digest in the manifest.

`reproduce.py` invokes authoritative Parquity replay. `upstream_repro.py`
invokes the selected provider path and emits direct evidence. Bundle validation
does not execute either script and does not certify a script from an untrusted
bundle as safe. Inspect scripts before running them.

## Before sharing a bundle

Generated findings may retain the canonical and discovered Case, complete
matrix results, a writer-produced `input.parquet`, provider versions,
diagnostics, platform data, and executable scripts. Scan findings retain the
exact accepted source bytes as `input.parquet`, plus normalized source paths,
schemas, observations, diagnostics, versions, and scripts.

Removing an absolute path does not anonymize this material. Field names,
values, relative filenames, schemas, and provider messages may reveal
personal, commercial, or environment information.

Before sharing:

1. Inspect every retained Parquet, JSON, Markdown, and Python file.
2. Treat source values, schema, filenames, versions, and diagnostics as
   potentially sensitive.
3. Do not redact a bound file in place; changing it invalidates the manifest.
4. Prefer reproducing a non-sensitive minimal Case and sharing that new bundle
   instead of production bytes.
5. Use a channel appropriate for the data and recipient.

See [Using Parquity](usage.md) for commands, [Writing Cases](cases.md) for the
Case format, and [Versioning](../VERSIONING.md) for package compatibility.
