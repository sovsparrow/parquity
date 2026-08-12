# Parquity finding · value disagreement

`pyarrow` wrote the file and `duckdb` read it, but the result disagreed with the Case.

This is reproducible interoperability evidence. It does not by itself identify which
provider is at fault.

## What happened

| Step | Stage | Outcome |
|---:|---|---|
| 1 | Build input | Case is the expected table |
| 2 | Write with pyarrow [default] | completed |
| 3 | Read with duckdb | completed |
| 4 | Compare with the Case | value disagreed |

- Location: row 1, column 1, <code>value</code> (<code>$rows[0].value</code>)
- Structured expected/observed evidence is unavailable for this record.
- Detail: "expected 1, got 2"

## Input Case

The Case is the table Parquity asked the writer to encode. It is also the expected
schema and data for semantic comparison.

### Schema

| # | Column | Type | Nullable | Shape |
|---:|---|---|---|---|
| 1 | <code>value</code> | <code>int32</code> | no | — |

### Data

| Row | Column | Value |
|---:|---|---|
| 1 | <code>value</code> | <code>1</code> |

Open [`case.json`](case.json) for the complete canonical input.

## Reproduce

Run `python reproduce.py` in this directory. Exit 1 means this exact target
reproduced; exit 0 means it did not. Exit 2 means required evidence or providers are
unavailable; exit 3 means Parquity itself failed.

Run `python upstream_repro.py` for direct provider output without Parquity's semantic
comparison. Inspect the script before running it.

## Complete writer-reader matrix

Every requested cell is shown. `PASS` means that cell matched the Case; another cell
may still disagree.

| Writer output | Reader | Stage | Result | Location |
|---|---|---|---|---|
| <code>pyarrow</code> | <code>duckdb</code> | <code>compare</code> | <code>VALUE_MISMATCH</code> | row 1, column 1, <code>value</code> (<code>$rows[0].value</code>) |

Open [`matrix.json`](matrix.json) for complete diagnostics for every cell.

## What this evidence establishes

- Established: the writer and reader completed, then semantic comparison found this difference in the recorded environment.
- Not established: root cause, provider fault, behavior on untested versions, or
  exhaustiveness beyond the recorded bounds.

## Discovery and minimization

- Stop reason: `CHECK_COMPLETE`
- Discovered Case identity: `fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3`
- Minimized Case identity: `fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3`
- Successful deterministic reductions: `0`
- Reduction breakdown: fields `0`, rows `0`, nullability `0`, containers `0`, scalars `0`.

## Technical evidence

- Finding identity: `4301899bdcf5dde01d90c0e2c01c9d634167cd0c0413b8505cbd82d01f1facbe`
- Final Case identity: `fd9209bc1a6fa5addbc53f967198e4dabc5f7526de0a1706f3ded4e5b5580ec3`
- Target location: row 1, column 1, <code>value</code> (<code>$rows[0].value</code>)
- Diagnostic kind: "VALUE\_MISMATCH"
- Normalized detail SHA-256: `c2e29a081ddb63535089a7d9d66d77875b324ded3c66729095562fb8383cfeba`
- Input Parquet artifact: [`input.parquet`](input.parquet)
- Canonical manifest: [`finding.json`](finding.json)

### Environment

- Parquity: `0.1.0`
- Hypothesis: `6.165.1`
- Python: `3.12.13`
- Platform: `released-fixture`
- Dependencies: `pyarrow` `25.0.0`
- Selected writers: `pyarrow` `25.0.0`
- Selected readers: `duckdb` `1.5.5`
