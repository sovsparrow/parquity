# Parquity scan finding

## Summary

For "nested/released.parquet", **2** readers failed and **0** pairwise observation differences were recorded.

Parquity compared independent reader observations.
No reader is treated as the reference answer, and this evidence does not assign
provider fault.

## Source file

- Original path: "nested/released.parquet"
- Size: `21` bytes
- SHA-256: `1d59e28d35ef1ee9591ad9df0d3ae9bb5f3b3404f7f98f4c41550a76663e7228`
- Retained input: [`input.parquet`](input.parquet)

## Reader outcomes

| Reader | Outcome | Shape | Observation group | Diagnostic |
|---|---|---|---|---|
| `pyarrow 25.0.0` | `PROVIDER_ERROR` | no table returned | — | "ArrowInvalid": "released provider failure" |
| `duckdb 1.5.5` | `PROCESS_CRASH` | no table returned | — | "PROCESS\_CRASH": "released worker crash" |

## Observed differences

The left and right columns name reader groups, not expected and observed truth.

No pairwise semantic difference was recorded; the finding comes from a reader failure.

## Reproduce

Run `python reproduce.py` in this directory to validate the bundle and repeat the
full reader comparison.

- `python upstream_repro.py pyarrow` runs the direct `pyarrow` reader.
- `python upstream_repro.py duckdb` runs the direct `duckdb` reader.

Inspect both scripts before running them. Direct scripts emit provider evidence and
do not apply Parquity's semantic comparison.

## What this evidence establishes

- Established: the recorded readers produced these outcomes for these exact bytes in
  the recorded environment.
- Not established: which observation is correct, root cause, provider fault, or
  behavior on untested versions.

## Occurrence index

| Signal | Reader | Location | Occurrence identity |
|---|---|---|---|
| `PROCESS_CRASH` | `duckdb` | no table returned | `be2b54ba19c0765174e44ca5527a2516a616729c0131c7f906fcf8bfc5de91ce` |
| `PROVIDER_ERROR` | `pyarrow` | no table returned | `c610f90e7d9749a81651eec532575c22863d8f4456150fa044b13121dc5db54f` |

## Technical evidence

- Finding identity: `15b1baa9209f13415b4f2b2d74ce3147aa9da6caa90f75617218a73d7fec9d33`
- Signature SHA-256: `295dc1c1ecb79cdecf52d50596cfd8faf5f41fc4ee1cafc5f99991d211b14a33`
- Timeout per reader: `30` seconds
- Occurrences extracted: `2`
- Canonical manifest: [`finding.json`](finding.json)

This bundle contains source bytes and diagnostics that may reveal sensitive data.
Inspect every file before sharing it.
