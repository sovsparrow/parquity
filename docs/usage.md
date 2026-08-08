# Using Parquity

Choose a command from the input you already have:

| Starting point | Command | Comparison |
|---|---|---|
| Exact schema and rows | `check` | Every writer-reader result against your Case |
| No Case yet | `fuzz` | Generated Cases against their writer-reader results |
| Exact schema, unknown troublesome values | `fuzz --schema` | Generated rows under your fixed schema |
| Existing Parquet bytes | `scan` | Independent reader observations against each other |
| Saved evidence | `replay` | A fresh evaluation against the recorded target |
| Symptom families from a saved run | `triage` | Filtered families or replay-bound states |

`check` and `fuzz` use a [Case](cases.md): the logical schema and rows that
should survive serialization. `scan` has no Case and no reference reader; it
starts from existing Parquet bytes.

## Inspect the installation

```console
parquity --help
parquity --version
parquity engines
parquity smoke
```

`engines` reports installed providers, versions, supported directions, tiers,
and declared Python support. `smoke` runs the three core writers against the
three core readers using a built-in Case. On a terminal these commands print
compact tables; `smoke` does not create a bundle.

Run `parquity <command> --help` for command-specific arguments, options,
defaults, and exit behavior. Interactive terminals receive a human-readable
summary. Redirected or piped stdout receives compact `parquity.cli.v1` JSON.
Pass `--json` to force that canonical machine output on a terminal.

## Execution model

`check`, `fuzz`, `smoke`, and replay of generated findings load providers in
Parquity's main process. A native provider crash can therefore terminate the
command before Parquity can publish a result.

`scan` and replay of scan evidence evaluate each reader-file cell in a fresh,
sequential child process. This lets a campaign record ordinary provider errors,
timeouts, and child crashes without losing earlier observations. It is a
supervision boundary, not a security sandbox; the exact limits are described
below.

## Check a known table

Use `check` when you know both the schema and the values that should survive a
writer-reader path:

```console
parquity check case.json --out check-run
```

For each selected writer, Parquity writes the Case to Parquet. Every selected
reader then reads those bytes, and the observed schema and rows are compared
with the original Case.

PyArrow, DuckDB, and Polars are selected as writers and readers by default.
Narrow the matrix when investigating one path:

```console
parquity check case.json --out duckdb-to-pyarrow \
  --writers duckdb --readers pyarrow
```

If every selected cell matches the Case, `check` exits 0 with `NO_FINDING` and
does not create `check-run`. Any non-passing cell exits 1 and publishes an
aggregate run containing one standalone finding for each retained
observation.

See [Writing Cases](cases.md) for the JSON model and supported values.

## Search generated Cases

Generic fuzz searches small schemas, rows, nested values, nullability, and
boundary values:

```console
parquity fuzz --examples 100 --seed 42 --max-findings 8 --out fuzz-run
```

Generic fuzz is useful when you maintain or integrate a Parquet engine and do
not want to predict the failing schema first. The generated Cases are small on
purpose: they isolate an interoperability boundary and make a failure cheap to
inspect and reproduce.

`--examples` is the maximum discovery budget. `--seed` must be an integer from 0 through
2^64 - 1. A seed is repeatable only with the same Parquity, Hypothesis, Python,
and provider environment. The reduced `case.json` saved with a finding is the
durable reproducer.

The example limit and finding cap are competing bounds. Fuzz retains up to
`--max-findings` distinct fingerprints as complete finding bundles. If it sees
another distinct fingerprint after reaching that cap, it records bounded
overflow and stops discovery early. Overflow fingerprints are not complete
findings, and their count is only a known lower bound: the campaign did not
evaluate the rest of its search space. The default finding cap is 8; the
maximum is 64.

## Search values under a fixed schema

Use schema-aware fuzz when your pipeline schema is known but troublesome rows
are not. Supply an ordinary Case with the exact schema and an empty `rows`
array:

```console
parquity fuzz --schema schema.json --examples 100 --seed 42 \
  --max-findings 8 --out schema-run
```

Parquity generates and reduces only rows and values. Field order, names,
types, parameters, and nullability remain fixed. A non-empty template or a
schema outside the documented generation budgets is rejected before any
provider runs.

Schema-aware findings contain the same canonical `case.json` accepted by
`check`. See the copyable template in [Writing Cases](cases.md).

## Scan existing Parquet files

Use `scan` when the Parquet bytes already exist:

```console
parquity scan input.parquet --out scan-run
```

An explicitly named file may use any filename. A directory scan recursively
selects regular `.parquet` files without following symlinks:

```console
parquity scan parquet-directory --out scan-run \
  --engines pyarrow,duckdb,polars,datafusion \
  --timeout 30 --max-findings 32
```

Each reader observes a private snapshot in a fresh, sequential child process.
Parquity compares row count, semantic schema, and values without choosing a
reference reader. Agreement exits 0 and creates no output path. A disagreement,
provider error, timeout, or child crash exits 1 and publishes a scan run.

Directory discovery and retained evidence are bounded:

- at most 4,096 visited entries and 256 accepted files;
- at most 64 MiB per file and 512 MiB of accepted source bytes in total;
- a 1–300 second timeout per reader-file cell; and
- at most 64 retained findings.

Reaching the finding cap before every accepted file is evaluated is recorded
as a non-exhaustive stop with bounded overflow.

These are discovery and retained-evidence bounds, not hard memory limits. They
do not bound every allocation or decompression step performed inside a
provider.

The child-process boundary records ordinary provider exceptions, hangs, and
crashes; it is not a sandbox. It does not restrict filesystem, network,
credentials, environment variables, OS identity or privileges, memory, CPU,
disk, or decompression work. On POSIX systems, Parquity supervises the child
process group. The package's pure-Python wheel tag does not establish
equivalent containment on an otherwise unverified platform. Run files of
uncertain provenance in an operating-system or container boundary with least
privilege and appropriate resource limits.

## Replay recorded evidence

Replay accepts a standalone generated finding, a generated aggregate, a
standalone scan finding, or a scan aggregate:

```console
parquity replay run-directory
```

Replay validates the complete inventory and hash chain before resolving the
recorded providers and options. It does not execute either reproduction script
stored in the bundle.

Replay exits 1 when at least one recorded target reproduces exactly. This is a
finding result, not a command failure. Save canonical replay output before
binding it into triage:

```console
parquity replay run-directory --json > replay.json
parquity triage run-directory --replay-evidence replay.json
```

The states `REPRODUCED`, `RELATED_FAILURE`, `NOT_REPRODUCED`, and `NOT_CHECKED`
are defined in [Evidence and replay](evidence.md).

## Inspect automatic symptom families

Generated and scan aggregate reports already contain deterministic symptom
families. The `triage` command is an optional read-only view for filtering those
families or attaching replay states:

```console
parquity triage run-directory
parquity triage run-directory --focus execution
parquity triage run-directory --focus data
parquity triage run-directory --focus schema
```

`triage` validates the bundle and derives the same grouping by signal and
evidence shape. It starts no providers or child processes and does not modify
the bundle. `--focus` changes only the displayed family list; the complete
finding, occurrence, and family counts remain unchanged. Add `--json` when the
result will be consumed by a script or saved as structured evidence.

A symptom family is not a root-cause or defect count. See
[Evidence and replay](evidence.md) before turning a family into an upstream
issue.

## Add writer profiles

`check` and both fuzz modes can request bounded writer-option variants:

```console
parquity check case.json --out profiled-run \
  --writers pyarrow,duckdb \
  --readers pyarrow,duckdb,polars \
  --writer-profiles compression-gzip,row-group-2
```

Default writing still runs. Each supported profile adds one writer execution
per selected reader. Exact names and provider support are in
[Writer profiles](writer-profiles.md).

## Output and exit codes

`--help` always prints plain-text usage. Other commands choose their stdout
format from the destination:

- an interactive terminal receives a concise table or summary;
- a pipe or redirected file receives one compact canonical JSON document; and
- `--json` forces that JSON document even on a terminal.

Color and terminal hyperlinks are omitted when stdout is not a terminal, when
`NO_COLOR` is set, or when `TERM=dumb`. Published `check`, `fuzz`, and `scan`
summaries link to `REPORT.md` on capable terminals and show the same path as
plain text otherwise.

The canonical JSON document carries a command-specific successful status:

| Command | Exit-0 status |
|---|---|
| `--version`, `engines` | `OK` |
| `smoke` | `PASS` |
| `check`, `fuzz` | `NO_FINDING` |
| `scan` | `AGREEMENT` |
| `triage` | `TRIAGED` |

| Exit | Meaning |
|---:|---|
| 0 | The command completed without a finding; replay had no exact reproduction; or triage completed. |
| 1 | A disagreement was observed, or replay reproduced at least one recorded target. |
| 2 | Usage, input, provider, resource, output, bundle, or replay-evidence validation failed. |
| 3 | An unexpected internal, worker-protocol, publication, or artifact-validation failure prevented a valid result. |

`check`, `fuzz`, and `scan` publish the requested directory only when they have
a complete run to report. Every command writes its immediate result to stdout;
human terminal output is only a projection of the same result represented by
canonical JSON. See [Evidence and replay](evidence.md) for bundle layouts and
what to inspect before sharing them.
