# Parquity check run

Parquity saved **1** reproducible finding.

## Run scope

| Measure | Value |
|---|---:|
| Supplied Case | 1 |
| Cases actually checked | 1 |
| Writer-reader cells actually checked | 1 |
| Findings with individual reports | 1 |
| Other observations without individual reports | 0 |
| Why the run stopped | the supplied Case was checked |

A finding is one reproducible symptom, not a count of upstream defects.
One generated Case can produce several findings or other observations.

## Inputs with observed problems

### C1 · 1 row · 1 column

Case identity: `fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3` · [open canonical Case](findings/4301899bdcf5dde01d90c0e2c01c9d634167cd0c0413b8505cbd82d01f1facbe/case.json)

#### Schema

| # | Column | Type | Nullable | Shape |
|---:|---|---|---|---|
| 1 | <code>value</code> | <code>int32</code> | no | — |

#### Data

| Row | Column | Value |
|---:|---|---|
| 1 | <code>value</code> | <code>1</code> |

#### Findings from this Case

| # | Route | Result | Where | Detail | Evidence |
|---:|---|---|---|---|---|
| 1 | `pyarrow` → `duckdb` | `VALUE_MISMATCH` | row 1, column 1, <code>value</code> (<code>$rows[0].value</code>) | "expected 1, got 2" | [open finding](findings/4301899bdcf5dde01d90c0e2c01c9d634167cd0c0413b8505cbd82d01f1facbe/REPORT.md) |


## Symptom families

Parquity grouped **1** occurrence into **1**
conservative family. A family is a navigation aid, not a confirmed root cause
or bug count.

| Signal | Source cell result | Route | Diagnostic kind | Detail | Occurrences | Replay state | Evidence |
|---|---|---|---|---|---:|---|---|
| `VALUE_DIFFERENCE` | `VALUE_MISMATCH` | `pyarrow → duckdb` | "VALUE\_MISMATCH" | "expected 1, got 2" | 1 | `NOT_CHECKED` | [open finding](findings/4301899bdcf5dde01d90c0e2c01c9d634167cd0c0413b8505cbd82d01f1facbe/REPORT.md) |

## Replay and triage

- `parquity replay .` validates the run and re-executes every exact target.
- `parquity replay --json . > replay.json` writes canonical replay evidence.
- `parquity triage .` groups repeated symptom shapes without treating families as
  confirmed upstream bugs.

Replay exits 1 when at least one exact target reproduces. Exit 0 means no exact
target reproduced; related or unevaluable outcomes remain separately classified.

## Coverage and limits

- The run stopped because: the supplied Case was checked.
- Results cover only the selected providers, versions, profiles, seed, and bounds.
- A finding proves recorded behavior; it does not assign provider fault.

## Environment and exact evidence

- Command: `parquity check CASE.json --out RUN_DIR --writers pyarrow --readers duckdb`
- Run identity: `dacc978fd02146092a69dacd6385f113e32a43bc0d4e2bc1a5d384242d51ee6f`
- Writers: `pyarrow 25.0.0`
- Readers: `duckdb 1.5.5`
- Parquity: `0.1.0`
- Hypothesis: `6.165.1`
- Python: `3.12.13`
- Platform: `released-fixture`
- Canonical run manifest: [`run.json`](run.json)
