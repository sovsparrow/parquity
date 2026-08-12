# Using Parquity

Choose a command from the input you already have:

| Starting point | Command | Comparison |
|---|---|---|
| Exact schema and rows | `check` | Every writer-reader result against your Case |
| No Case yet | `fuzz` | Generated Cases against their writer-reader results |
| Exact schema, unknown troublesome values | `fuzz --schema` | Generated rows under your fixed schema |
| Existing Parquet bytes | `scan` | Independent reader observations against each other |
| Saved evidence | `replay` | A fresh evaluation against the recorded target |

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
compact tables; `smoke` does not save evidence.

Run `parquity <command> --help` for command-specific arguments, options,
defaults, and exit behavior. Interactive terminals receive a human-readable
summary. Redirected or piped stdout receives compact `parquity.cli.v1` JSON.
Pass `--json` to force that canonical machine output on a terminal.

## Platform support

Parquity supports Linux and macOS. Windows is not currently supported.

`scan` and replay of scan evidence require POSIX process-group supervision for
timeouts and descendant cleanup. The pure-Python wheel may install on another
platform; installation alone does not establish support for its commands.

## Execution model

`check`, `fuzz`, `smoke`, and replay of generated evidence load providers in
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
run directory with a report and a standalone reproducer for each retained
failure.

Parquity may reduce a failing supplied Case to a smaller table that preserves
the same exact failure. The saved `case.json` is the reduced reproducer. When
reduction changes the input, `discovered_case.json` preserves the supplied
Case that exposed the failure.

`check` has no additional table-size limit beyond Case validation and available
process resources. Its writers and readers run in the main process, so a large
Case can consume substantial memory or terminate the command through provider
failure.

See [Writing Cases](cases.md) for the JSON model and supported values.

## Search generated Cases

Generic fuzz searches small schemas, rows, nested values, nullability, and
boundary values:

```console
parquity fuzz --examples 100 --seed 42 --max-saved 8 --out fuzz-run
```

Generic fuzz is useful when you maintain or integrate a Parquet engine and do
not want to predict the failing schema first. The generated Cases are small on
purpose: they isolate an interoperability boundary and make a failure cheap to
inspect and reproduce.

`--examples` is the maximum discovery budget. `--seed` must be an integer from
0 through 2^64 - 1. A seed is repeatable only with the same Parquity,
Hypothesis, Python, and provider environment. The reduced `case.json` in a
saved reproducer is the durable input.

Parquity deduplicates equivalent failures. `--max-saved N` saves at most N
minimized reproducers; additional distinct failures remain in `run.json` but
do not receive standalone reproducer directories. Replay evaluates saved
reproducers only. The default limit is 8; the maximum is 64.

`--examples` is an upper bound. A finite schema strategy may run out of
distinct tables first; the run then records `STRATEGY_EXHAUSTED` rather than
claiming that the example bound was reached.

## Search values under a fixed schema

Use schema-aware fuzz when your pipeline schema is known but troublesome rows
are not. Supply a `parquity.case.v1` document using Case grammar, the exact
schema, and `rows: []`:

```console
parquity fuzz --schema schema.json --examples 100 --seed 42 \
  --max-saved 8 --out schema-run
```

Parquity generates and reduces only rows and values. Field order, names,
types, parameters, and nullability remain fixed. A non-empty template or a
schema outside the documented generation budgets is rejected before any
provider runs.

Schema-aware reproducers contain the same canonical `case.json` accepted by
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
  --timeout 30 --max-saved 32
```

Each reader observes a private snapshot in a fresh, sequential child process.
Parquity compares row count, semantic schema, and values without choosing a
reference reader. Agreement exits 0 and creates no output path. A disagreement,
provider error, timeout, or child crash exits 1 and publishes a scan run.

Directory discovery and retained evidence are bounded:

- at most 4,096 visited entries and 256 accepted files;
- at most 64 MiB per file and 512 MiB of accepted source bytes in total;
- a 1–300 second timeout per reader-file cell; and
- saved evidence for at most 64 source files.

Reaching the saved-evidence limit before every accepted file is evaluated is
recorded as a non-exhaustive stop. The remaining accepted files are listed as
not evaluated.

Scan supervision currently requires a POSIX platform. Windows support is
demand-driven; open an issue if you need it.

These are discovery and retained-evidence bounds, not hard memory limits. They
do not bound every allocation or decompression step performed inside a
provider.

The child-process boundary records ordinary provider exceptions, hangs, and
crashes; it is not a sandbox. It does not restrict filesystem, network,
credentials, environment variables, OS identity or privileges, memory, CPU,
disk, or decompression work. Run files of uncertain provenance in an
operating-system or container boundary with least privilege and appropriate
resource limits.

## Replay saved evidence

Replay accepts a standalone generated reproducer, a generated run directory,
a standalone scan evidence directory, or a scan run directory:

```console
parquity replay run-directory
```

Replay validates the complete artifact inventory and all recorded digests
before resolving the recorded providers and options. Run replay evaluates
saved reproducers only. It does not execute either reproduction script stored
with the evidence.

Save canonical replay output when another tool needs the result:

```console
parquity replay run-directory --json > replay.json
```

Exit 1 means at least one recorded target reproduced exactly; it is a replay
result, not a command failure. With `--json`, a completed replay writes only
canonical JSON to stdout and leaves stderr empty.

The states `REPRODUCED`, `RELATED_FAILURE`, and `NOT_REPRODUCED` are defined in
[Evidence and replay](evidence.md).

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
summaries show the published output directory.

The canonical JSON document carries a command-specific successful status:

| Command | Exit-0 status |
|---|---|
| `--version`, `engines` | `OK` |
| `smoke` | `PASS` |
| `check`, `fuzz` | `NO_FINDING` |
| `scan` | `AGREEMENT` |

| Exit | Meaning |
|---:|---|
| 0 | The command completed without a failure, or replay had no exact reproduction. |
| 1 | A failure or semantic disagreement was recorded, or replay reproduced at least one saved target. |
| 2 | Usage, input, provider, resource, output, or saved-evidence validation failed. |
| 3 | An unexpected internal, worker-protocol, publication, or artifact-validation failure prevented a valid result. |

`check`, `fuzz`, and `scan` publish the requested directory only when they have
a complete run to report. Every command writes its immediate result to stdout;
human terminal output is only a projection of the same result represented by
canonical JSON. See [Evidence and replay](evidence.md) for saved layouts and
what to inspect before sharing them.

## After finding a failure

1. Open `REPORT.md`.
2. Follow `open` for the relevant failure.
3. Run `python reproduce.py` for authoritative Parquity replay.
4. Inspect `matrix.json` or the recorded reader outcomes for complete evidence.
5. Run `python upstream_repro.py` for a direct provider-level reproduction.
6. Check the recorded Parquity, Python, platform, provider, and dependency
   versions.
7. Review every retained file before sharing the reproducer.
