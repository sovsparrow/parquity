# Providers and engine selection

Parquity compares independent Parquet implementations through provider
adapters. A provider has a reader direction, a writer direction, or both.

The base package installs three core providers. Two additional providers use
named extras so users do not acquire their dependency trees unless they select
them.

## Installation and directions

| Provider | Python distribution | Tier | Install | Reader | Writer | In the default matrix |
|---|---|---|---|---:|---:|---:|
| PyArrow | `pyarrow` | Core | `parquity` | Yes | Yes | Yes |
| DuckDB | `duckdb` | Core | `parquity` | Yes | Yes | Yes |
| Polars | `polars` | Core | `parquity` | Yes | Yes | Yes |
| DataFusion | `datafusion` | Optional | `parquity[datafusion]` | Yes | No | No |
| fastparquet | `fastparquet` | Optional | `parquity[fastparquet]` | Yes | Yes | No |

Install one or both optional providers:

```console
python -m pip install 'parquity[datafusion]'
python -m pip install 'parquity[fastparquet]'
python -m pip install 'parquity[datafusion,fastparquet]'
```

The declared minimum versions are DataFusion 54.0.0 and fastparquet 2026.5.0.
Parquity supports all five providers on Python 3.11 through 3.14.
`parquity engines` reports what is installed in the current environment and
records each discovered version.

## Why DataFusion and fastparquet are optional

DataFusion is reader-only in Parquity and brings a separate execution stack.
fastparquet is included as a legacy-interoperability provider and brings NumPy,
pandas, and its compression dependencies. Neither is required to use the core
writer-by-reader matrix.

Optional means separately installed and explicitly selected. Evidence from an
optional provider is handled the same way as evidence from a core provider.

## Default and explicit selection

These commands use PyArrow, DuckDB, and Polars by default:

- `smoke` uses all three as writers and readers;
- `check` and `fuzz` use all three as writers and readers;
- `scan` uses all three as readers.

Installed optional providers are not added silently. Select them by name:

```console
parquity check case.json --out selected-run \
  --writers duckdb,fastparquet \
  --readers pyarrow,datafusion

parquity fuzz --examples 100 --seed 42 --out selected-fuzz \
  --writers pyarrow \
  --readers pyarrow,duckdb,polars,datafusion,fastparquet

parquity scan parquet-directory --out selected-scan \
  --engines pyarrow,duckdb,polars,datafusion,fastparquet
```

Names are validated and normalized to provider-registry order. A requested
provider is never dropped silently. A missing provider or unsupported
direction is a configuration error and exits 2 before a partial matrix is
reported.

Replay does not use the current default. It resolves the exact writer and
reader sets recorded with the evidence and refuses to evaluate a smaller
matrix.
See [Evidence](evidence.md) for replay states and exits.

## Implementations without a Python provider

An implementation that ships no Python distribution can still take part, by
answering a small subprocess contract instead of being imported. Those engines
are declared explicitly, never join the default matrix, and produce evidence
handled the same way as any other provider. See
[External engines](external-engines.md).

## Writer options

Writer directions can also be evaluated under the bounded profiles in
[Writer profiles](writer-profiles.md). Profile support is recorded per writer;
it is separate from the reader/writer direction table above.

## Interpreting provider evidence

Parquity records provider name and version with every result. Dependency lower
bounds in package metadata are installation constraints, not a claim that all
future combinations behave identically. Preserve the saved evidence when a
result matters; replay reports version drift separately from reproduction
state.

Provider code executes with the current user's authority. `scan` contains each
reader-file operation in a child process, but that boundary is not a sandbox.
See [Using Parquity](usage.md#scan-existing-parquet-files) before processing
files of uncertain provenance.
