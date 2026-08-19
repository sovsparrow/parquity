<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/sovsparrow/parquity/v0.2.0/assets/parquity-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/sovsparrow/parquity/v0.2.0/assets/parquity-wordmark-light.svg">
    <img alt="Parquity" src="https://raw.githubusercontent.com/sovsparrow/parquity/v0.2.0/assets/parquity-wordmark-light.svg" width="420">
  </picture>
</p>

<p align="center">
  Find and reproduce Parquet interoperability failures.
</p>

<p align="center">
  <a href="https://github.com/sovsparrow/parquity/actions/workflows/ci.yml"><img alt="Continuous integration" src="https://github.com/sovsparrow/parquity/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/parquity/"><img alt="PyPI" src="https://img.shields.io/pypi/v/parquity.svg"></a>
  <a href="https://pypi.org/project/parquity/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/parquity.svg"></a>
  <a href="https://github.com/sovsparrow/parquity/blob/v0.2.0/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-282320.svg"></a>
</p>

Parquity checks whether a logical table survives a Parquet round trip and
whether independent readers agree on existing Parquet bytes. It records schema
and value differences, provider errors, timeouts, and crashes.

Give it either the table you meant to write or the `.parquet` bytes you need to
investigate. Generated failures are reduced to small Cases and saved as
standalone reproducers. Scan retains each affected source file once with all
recorded reader outcomes.

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

A **Case** is the ordered schema and rows that should survive a writer-reader
path. `check` evaluates one Case you provide; `fuzz` generates and reduces
Cases. `scan` compares how readers interpret an existing `.parquet` file,
without choosing a reference reader.

## Choose a command

| You have or want | Command |
|---|---|
| A known schema and exact rows | `parquity check` |
| Small generated interoperability cases | `parquity fuzz` |
| Generated values under a fixed schema | `parquity fuzz --schema` |
| One existing Parquet file or a directory of them | `parquity scan` |
| A saved reproducer or run to evaluate again | `parquity replay` |
| A quick installation check | `parquity smoke` |

## Install

Parquity requires Python 3.11 and currently supports Python 3.11 through 3.14.
It supports Linux, macOS, and Windows.

```console
python -m pip install parquity
```

The base installation includes PyArrow, DuckDB, and Polars. DataFusion and
fastparquet are optional; see
[Providers](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/providers.md).

Check the installed core matrix:

```console
parquity smoke
```

Exit 0 and `PASS` mean that all nine core writer-reader paths matched the
built-in Case. On a terminal, `smoke` prints a compact matrix. When stdout is
redirected or piped, commands emit canonical JSON instead; pass `--json` to
request the same machine output on a terminal.

## Find a generated failure

```console
parquity fuzz --examples 100 --seed 42 --max-saved 8 --out fuzz-run
```

Parquity generates small tables, minimizes failing Cases, and saves up to eight
reproducers. Additional distinct failures remain recorded in
`fuzz-run/run.json`.

The report leads with the result rather than the storage model:

```text
Parquity tested 4 generated tables and found 5 distinct failures.
It stopped after saving 3 reproducers; the other 2 remain in run.json.

Writer → reader   Failure                                      Example table / location                         Reproduce
polars → polars   compare · SCHEMA_MISMATCH                    0 rows · 1 column · map<float32, float32>         open
                  expected map, got large_list<item: ...>       $schema.field_2
polars → duckdb   compare · SCHEMA_MISMATCH                    1 row · 4 columns · map<float32, float32>?        not saved
                  expected map, got list<l: struct<...>>        $schema.field_2
```

Open `fuzz-run/REPORT.md` for the full table and links.

## Scan an existing file

```console
parquity scan example.parquet --out scan-run
```

Each selected reader observes the file independently. Agreement exits 0 and
creates no output directory. A disagreement, reader error, timeout, or crash
exits 1 and writes `scan-run/`. Start with `scan-run/REPORT.md`; use
`scan-run/scan.json` for automation and complete machine evidence.

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

Run every selected writer-reader path and compare the result with the Case:

```console
parquity check case.json --out check-run
```

Matching paths exit 0 with `NO_FINDING` and create no output directory. If any
path fails, `check` exits 1 and writes a report with links to the saved
reproducers. Parquity may reduce the supplied Case while preserving the same
failure; when it changes the input, the reproducer keeps the supplied Case as
`discovered_case.json`.

## Documentation

- [Using Parquity](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/usage.md):
  commands, outputs, limits, exits, and operational warnings.
- [Writing Cases](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/cases.md):
  the `case.json` grammar, supported types, and values.
- [Evidence and replay](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/evidence.md):
  reports, reproducers, replay states, and safe sharing.
- [Machine format overview](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/machine-formats.md):
  manifests, identities, canonicalization, and compatibility fields.
- [Providers](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/providers.md):
  install and select engines and directions.
- [Writer profiles](https://github.com/sovsparrow/parquity/blob/v0.2.0/docs/writer-profiles.md):
  add compression, row-group, and statistics variants.
- [Versioning](https://github.com/sovsparrow/parquity/blob/v0.2.0/VERSIONING.md):
  package releases and public compatibility.

## Reading a result

Start with `REPORT.md`. It says what failed and links to each saved reproducer.
Run `python reproduce.py` inside a reproducer or pass the directory to
`parquity replay` for a fresh evaluation.

The digest-bound JSON manifests are authoritative for automation, validation,
and exact identities. Replay validates them before starting providers and
never rewrites the captured evidence.

## Prior art

The writer-by-reader direction follows Alkis Evlogimenos's `carpenter`
proposal in
[apache/parquet-format#441](https://github.com/apache/parquet-format/issues/441#issuecomment-2192228561).
Parquity does not claim to originate cross-engine Parquet testing.

## Project

See
[CONTRIBUTING.md](https://github.com/sovsparrow/parquity/blob/v0.2.0/CONTRIBUTING.md)
to work on Parquity. Report suspected vulnerabilities through
[SECURITY.md](https://github.com/sovsparrow/parquity/blob/v0.2.0/SECURITY.md),
not a public issue.

Parquity is available under the
[MIT License](https://github.com/sovsparrow/parquity/blob/v0.2.0/LICENSE).
