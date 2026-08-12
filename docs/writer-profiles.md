# Writer profiles

Use writer profiles when the default write path is not enough. A profile asks
a selected writer to serialize the same Case with one bounded Parquet option
changed, then runs the resulting bytes through every selected reader.

The profile name is provider-neutral. Parquity translates it to the public
option exposed by each writer and records the exact effective option in the
run. Unsupported writer-profile pairs are reported explicitly; they do not
produce substitute default cells.

Default writing always runs first. Requested profiles run afterward in the
registry order shown below for each selected writer that supports them.

```console
parquity check case.json --out profiled-run \
  --writers pyarrow,duckdb \
  --readers pyarrow,duckdb,polars \
  --writer-profiles compression-gzip,row-group-2
```

`--writer-profiles` is also available on generic and schema-aware `fuzz`.

## Profile registry

The option accepts a comma-separated set chosen from:

1. `compression-gzip`
2. `compression-brotli`
3. `row-group-2`
4. `min-max-statistics-off`

`default`, empty tokens, duplicates, unknown names, and more than four entries
are rejected. User order is normalized to registry order.

## Provider translation

| Writer | `compression-gzip` | `compression-brotli` | `row-group-2` | `min-max-statistics-off` |
|---|---|---|---|---|
| PyArrow | `compression="gzip"` | `compression="brotli"` | `row_group_size=2` | `write_statistics=False` |
| Polars | `compression="gzip"` | `compression="brotli"` | `row_group_size=2` | `statistics=False` |
| fastparquet | `compression="GZIP"` | `compression="BROTLI"` | `row_group_offsets=2` | `stats=False` |
| DuckDB | `compression="gzip"` | `compression="brotli"` | unsupported | unsupported |

PyArrow, Polars, and fastparquet support all four profiles. DuckDB supports
gzip and brotli compression only. DataFusion remains reader-only.

These names describe Parquity execution profiles, not a claim that different
providers expose identical writer internals. A supported endpoint means that
Parquity passes the exact public option above and that a fresh provider
write/read interoperability control succeeds. It does not mean Parquity
independently inspected the resulting physical row groups, pages, encodings,
or statistics.

## Capability evidence

Each profiled run records whether every requested profile is supported by each
selected writer. A supported record contains exact effective options. An
unsupported record contains `OPTION_UNAVAILABLE` and no options:

```json
{
  "requested": ["row-group-2"],
  "capabilities": [
    {
      "effective_options": {"row_group_size": 2},
      "profile": "row-group-2",
      "status": "SUPPORTED",
      "writer": {"name": "pyarrow", "version": "25.0.0"}
    },
    {
      "profile": "row-group-2",
      "reason_code": "OPTION_UNAVAILABLE",
      "status": "UNSUPPORTED",
      "writer": {"name": "duckdb", "version": "1.5.5"}
    }
  ]
}
```

The enclosing key is `writer_profiles`. Every requested profile must be
supported by at least one selected writer. An unsupported writer/profile
pair performs no write and creates no reader checks.

## Matrix cost

Default cells are always evaluated. Each supported profiled writer execution
adds one cell per selected reader.

For the command above:

- default: 2 writers × 3 readers = 6 cells;
- `compression-gzip`: 2 supported writers × 3 readers = 6 cells;
- `row-group-2`: 1 supported writer × 3 readers = 3 cells;
- total: 15 cells.

Provider writes and reads are sequential. Add profiles deliberately when a
larger matrix is worth the extra provider work.

## Identity and replay

Parquity records the selected profile, writer version, and exact effective
options with the result. Default and profiled writes are kept separate. When
`--writer-profiles` is omitted, provider calls receive no added keyword
arguments and profile fields are absent.

Replay requires the same writer profile and effective options. If that exact
execution is no longer available, replay exits 2 with
`WRITER_PROFILE_NOT_EVALUABLE`; it does not substitute a default write or
return a partial aggregate result.

Installed provider behavior can change. `parquity engines` reports the live
provider versions; each run records the versions it used. See
[Providers](providers.md) for installation and selection, [Evidence](evidence.md)
for saved-evidence interpretation, and [Using Parquity](usage.md#add-writer-profiles)
for the command in context.
