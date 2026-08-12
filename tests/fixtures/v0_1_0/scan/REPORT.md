# Parquity scan run

## Summary

Parquity retained **1** file findings. Run status: `FINDINGS_FOUND`.

A scan finding is one source file with at least one reader failure or disagreement.
It is not a count of upstream defects.

## Run scope

| Measure | Value |
|---|---:|
| Parquet files discovered | 1 |
| Files evaluated | 1 |
| Files with retained findings | 1 |
| Files not evaluated after cap | 0 |
| Symlinks skipped | 0 |
| Filesystem entries visited | 2 |
| Finding limit | 4 |
| Stop reason | `FINDINGS_FOUND` |

## Files with observed problems

| Source file | Reader failures | Semantic differences | Signals | Report |
|---|---:|---:|---|---|
| "nested/released.parquet" | 2 | 0 | PROCESS_CRASH: 1, PROVIDER_ERROR: 1 | [open finding](findings/15b1baa9209f13415b4f2b2d74ce3147aa9da6caa90f75617218a73d7fec9d33/REPORT.md) |

## Symptom families

Parquity grouped **2** occurrences into **2** conservative
families. Families help navigate repetition; they do not claim root-cause identity.

| Signal | Occurrences | Representative file | Representative report |
|---|---:|---|---|
| `PROCESS_CRASH` | 1 | "nested/released.parquet" | [open finding](findings/15b1baa9209f13415b4f2b2d74ce3147aa9da6caa90f75617218a73d7fec9d33/REPORT.md) |
| `PROVIDER_ERROR` | 1 | "nested/released.parquet" | [open finding](findings/15b1baa9209f13415b4f2b2d74ce3147aa9da6caa90f75617218a73d7fec9d33/REPORT.md) |

## Replay and triage

- `parquity replay .` validates and replays every retained file finding.
- `parquity replay --json . > replay.json` writes canonical replay evidence.
- `parquity triage .` groups repeated symptom shapes across files.

## Coverage and limits

- Results cover only discovered files that were evaluated before the finding cap.
- Symlinks are skipped; discovery and retained-byte limits remain bounded.
- Reader agreement does not prove that an observation is specification-correct.

## Environment and exact evidence

- Parquity: `0.1.0`
- Readers: `pyarrow 25.0.0, duckdb 1.5.5`
- Timeout per reader: `30` seconds
- Canonical manifest: [`scan.json`](scan.json)

Each finding contains source bytes and diagnostics that may reveal sensitive data.
Inspect every child before sharing it.
