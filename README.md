<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/sovsparrow/parquity/v0.1.0/assets/parquity-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/sovsparrow/parquity/v0.1.0/assets/parquity-wordmark-light.svg">
    <img alt="Parquity" src="https://raw.githubusercontent.com/sovsparrow/parquity/v0.1.0/assets/parquity-wordmark-light.svg" width="420">
  </picture>
</p>

<p align="center">
  Find and reproduce semantic disagreements between Parquet engines.
</p>

<p align="center">
  <a href="https://github.com/sovsparrow/parquity/actions/workflows/ci.yml"><img alt="Continuous integration" src="https://github.com/sovsparrow/parquity/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/parquity/"><img alt="PyPI" src="https://img.shields.io/pypi/v/parquity.svg"></a>
  <a href="https://pypi.org/project/parquity/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/parquity.svg"></a>
  <a href="https://github.com/sovsparrow/parquity/blob/v0.1.0/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-282320.svg"></a>
</p>

Parquity finds semantic disagreements and provider failures that appear when
Parquet data crosses engine boundaries.

Give it either the table you meant to write or the `.parquet` bytes you need to
investigate. Parquity runs the relevant engine matrix, compares the logical
result, and saves replayable evidence when schemas, row counts, values, or
provider outcomes diverge. Generated failures are reduced to small Cases;
scans retain the exact input bytes.

A result records behavior, not blame. It does not choose a reference engine or
prove that an upstream project has a defect.

## Two ways to test

Parquity starts from either a logical table you describe or Parquet bytes you
already have.

```text
case.json  -> writer -> Parquet bytes -> reader -> compare with case.json

file.parquet -> reader A ┐
             -> reader B ├-> compare reader observations
             -> reader C ┘
```

A **Case** is not a Parquet file. It is the ordered schema and rows that should
survive a writer-reader path. `check` evaluates one Case you provide; `fuzz`
generates and reduces Cases. `scan` instead compares how readers interpret an
existing `.parquet` file, without choosing a reference reader.

## Choose a command

| You have or want | Command |
|---|---|
| A known schema and exact rows | `parquity check` |
| Small generated interoperability cases | `parquity fuzz` |
| Generated values under a fixed schema | `parquity fuzz --schema` |
| One existing Parquet file or a directory of them | `parquity scan` |
| A saved finding or run to reproduce | `parquity replay` |
| A focused view of the symptom families already in a run | `parquity triage` |
| A quick installation check | `parquity smoke` |

## Install

Parquity requires Python 3.11 or newer.
Parquity 0.1.0 supports Linux and macOS. Windows is not supported in this
release; `scan` and replay of scan evidence require POSIX process-group
supervision.

```console
python -m pip install parquity
```

The base installation includes PyArrow, DuckDB, and Polars. DataFusion and
fastparquet are optional providers; see
[Providers](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/providers.md).

Check the installed core matrix:

```console
parquity smoke
```

Exit 0 and `PASS` mean that all nine core writer-reader cells matched the
built-in Case.

On a terminal, `smoke` prints a compact writer-reader matrix. When stdout is
redirected or piped, commands emit canonical JSON instead; pass `--json` to
request the same machine output on a terminal. `smoke` is ephemeral and never
creates a bundle. A failing cell exits 1 with status `FAIL`.

## Scan an existing file

```console
parquity scan example.parquet --out scan-run
```

Each selected reader observes the file independently. Agreement exits 0 and
creates no output directory. A disagreement, reader error, timeout, or crash
exits 1 and writes `scan-run/`; start with `scan-run/REPORT.md`.

## Check a known table

Save this as `case.json`:

```json
{
  "format": "parquity.case.v1",
  "schema": [
    {"name": "id", "nullable": false, "type": {"kind": "int64"}},
    {"name": "active", "nullable": false, "type": {"kind": "bool"}}
  ],
  "rows": [
    [101, true],
    [102, false]
  ]
}
```

The first value in each row belongs to `id`; the second belongs to `active`.
Run every selected writer-reader path and compare the result with those two
rows:

```console
parquity check case.json --out check-run
```

Matching cells exit 0 with `NO_FINDING` and create no output directory. Any
non-passing cell exits 1 and writes a validated run with a report, canonical
Case, matrix, provider versions, and reproduction material.

## Documentation

- [Using Parquity](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/usage.md):
  exact commands, outputs, and exit codes for each task.
- [Writing Cases](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/cases.md):
  the `case.json` model, copyable schemas, supported types, and values.
- [Evidence and replay](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/evidence.md):
  reports, bundles, identities, replay states, and safe sharing.
- [Providers](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/providers.md):
  install and select engines and directions.
- [Writer profiles](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/writer-profiles.md):
  add compression, row-group, and statistics variants.
- [Versioning](https://github.com/sovsparrow/parquity/blob/v0.1.0/VERSIONING.md):
  package releases and public compatibility.

## Reading a result

Successful no-finding tokens differ by command: `smoke` reports `PASS`,
`check` and `fuzz` report `NO_FINDING`, and `scan` reports `AGREEMENT`. Each
result applies only to the recorded inputs, providers, versions, directions,
and options.

A finding preserves an observation and the material needed to inspect or
replay it. A finding is not a defect count or a verdict about which engine is
correct. See [Evidence and replay](https://github.com/sovsparrow/parquity/blob/v0.1.0/docs/evidence.md)
before filing an upstream issue or sharing a bundle.

Aggregate `REPORT.md` files already include symptom families. The optional
`triage` command exposes the same grouping with focus filters and bound replay
states; use `--json` for its canonical machine-readable form.

## Prior art

The writer-by-reader direction follows Alkis Evlogimenos's `carpenter`
proposal in
[apache/parquet-format#441](https://github.com/apache/parquet-format/issues/441#issuecomment-2192228561).
Parquity does not claim to originate cross-engine Parquet testing.

## Project

See
[CONTRIBUTING.md](https://github.com/sovsparrow/parquity/blob/v0.1.0/CONTRIBUTING.md)
to work on Parquity. Report suspected vulnerabilities through
[SECURITY.md](https://github.com/sovsparrow/parquity/blob/v0.1.0/SECURITY.md),
not a public issue.

Parquity is available under the
[MIT License](https://github.com/sovsparrow/parquity/blob/v0.1.0/LICENSE).
