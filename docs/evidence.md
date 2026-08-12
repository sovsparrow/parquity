# Evidence and replay

Start with `REPORT.md`. It summarizes the observed failures and links to saved
reproducers. Use `run.json`, `scan.json`, or `finding.json` for automation,
validation, exact identities, and complete machine evidence.

Parquity records observed behavior. It does not determine specification
conformance, root cause, or provider fault.

## Two kinds of evidence

Generated evidence starts from a `parquity.case.v1` Case. The Case declares the
expected schema and values, so each writer-reader result can be compared with
the supplied or generated table.

Scan evidence starts from existing Parquet bytes. Each selected reader produces
an independent observation. Parquity compares those observations with each
other; it does not select a reference reader.

Scan comparison treats these representation-only Arrow aliases as equivalent:

- `string`, `large_string`, and `string_view`;
- `binary`, `large_binary`, and `binary_view`; and
- `list` and `large_list`.

Container child labels are ignored for variable and fixed lists, as are the
conventional key and value labels in maps. Fixed-list width, map-versus-list
structure, child types and nullability, `keys_sorted`, ordinary field names,
metadata, and other semantic parameters remain significant. The original
reader schemas remain in the machine evidence even when their comparison views
agree.

## Generated run layout

`check` and `fuzz` use the same output layout:

```text
run-directory/
├── run.json
├── REPORT.md
└── findings/
    └── <id>/
        ├── finding.json
        ├── REPORT.md
        ├── case.json
        ├── matrix.json
        ├── reproduce.py
        ├── upstream_repro.py
        ├── discovered_case.json  # when reduction changed the Case
        └── input.parquet         # when the writer produced bytes
```

The `findings/` and `finding.json` names are retained machine-format names. In
human reports, each row is a **failure** and each saved child is a
**reproducer**.

Parquity deduplicates equivalent failures and saves one minimized reproducer
for each retained failure, up to `--max-saved`. Additional distinct failures
remain in `run.json` without receiving a child directory. They are visible in
the aggregate report as `not saved` and are not replay targets.

`matrix.json` contains the complete selected matrix for the reduced Case, not
only the failing path. `upstream_repro.py` exercises the selected provider path
directly; it is supporting provider evidence, not a second semantic oracle.

For `check` as well as `fuzz`, reduction may make the failing table smaller.
`case.json` is the reduced reproducer. When it differs from the table that
exposed the failure, `discovered_case.json` preserves that original Case.

## Scan run layout

`scan` writes this layout when at least one reader failure or semantic
difference is recorded:

```text
scan-run/
├── scan.json
├── REPORT.md
└── findings/
    └── <id>/
        ├── finding.json
        ├── input.parquet
        ├── REPORT.md
        ├── reproduce.py
        └── upstream_repro.py
```

Each child contains the exact accepted source bytes and all recorded reader
outcomes for that file. The parent records bounded discovery, selected readers,
limits, files left unevaluated after an early stop, and links to each source
reproducer.

Agreement creates no output directory. With zero or one successful reader,
cross-reader semantic comparison is unavailable; reader failures are not
reported as agreement.

## Integrity and authority

Every saved artifact is covered by canonical JSON and SHA-256 digests.
Validation rejects missing, extra, malformed, non-canonical, or
digest-mismatched files before replay starts provider execution. `REPORT.md`
is also bound by path, byte count, and digest.

The JSON manifest is authoritative when a report and machine evidence differ.
The hashes establish internal byte consistency only. They are not digital
signatures, do not identify an author, do not prove provenance, and do not make
retained data anonymous.

See [Machine format overview](machine-formats.md) for format identities, exact
top-level fields, grouping keys, compatibility projections, and canonical
ordering.

## Replay saved evidence

Replay accepts a standalone reproducer or a generated or scan run directory:

```console
parquity replay run-directory
```

Replay validates the saved inventory, resolves the recorded providers and
writer options, and performs a fresh evaluation. It never rewrites the captured
report or manifests. A run replay evaluates saved reproducers only; failures
recorded only in `run.json` are not replay targets.

Replay reports package and provider version drift separately from the result:

| State | Meaning |
|---|---|
| `REPRODUCED` | The exact recorded failure was observed again. |
| `RELATED_FAILURE` | The saved input still failed, but not with the exact recorded identity. For example, the exception kind may match while its normalized detail differs, or scan replay may contain a mixture of reproduced, missing, and new reader observations. |
| `NOT_REPRODUCED` | The recorded failure was absent in this evaluation. |

Scan replay also reports `new_observations` that were absent from the original
capture. A related or absent result does not prove that an upstream issue was
fixed; provider versions, environment, or behavior may have changed.

Replay exit meanings are:

| Exit | Meaning |
|---:|---|
| 0 | No saved target reproduced exactly. |
| 1 | At least one saved target reproduced exactly. |
| 2 | Required evidence, provider, or writer profile was unavailable or invalid. |
| 3 | Parquity failed before producing a valid replay result. |

Exit 1 is a replay result, not a command failure.

## Reports and scripts

Aggregate reports use the same four-column model:

```text
Writer -> reader or Reader(s) | Failure | Table/File and location | Reproduce
```

Generated reports show the reduced table shape and exact structural location.
Scan reports show the source file and either a structural location or the whole
file for reader failures. Aggregate tables shorten long diagnostics; open the
linked reproducer for the complete text and evidence.

`reproduce.py` invokes authoritative Parquity replay and forwards the exit
meanings above. `upstream_repro.py` invokes provider calls directly and emits
JSON evidence. Generated scripts run the selected writer-reader path; scan
scripts require one recorded reader name as an argument. A provider error exits
1, while a successful direct provider call exits 0 even when its printed schema
or values expose a semantic difference.

Validation does not execute either script and does not certify a script from an
untrusted directory as safe. Inspect scripts before running them.

## From failure to upstream report

1. Open `REPORT.md`.
2. Open the reproducer for the relevant failure.
3. Run `python reproduce.py`.
4. Inspect the complete matrix or reader outcomes.
5. Run `python upstream_repro.py` for direct provider behavior.
6. Check the recorded Parquity, Python, platform, provider, and dependency
   versions.
7. Review every retained file before sharing it or filing an upstream issue.

## Before sharing evidence

Generated reproducers may retain the reduced and original Case, matrix results,
a writer-produced `input.parquet`, provider versions, diagnostics, platform
data, and executable scripts. Scan reproducers retain the exact accepted source
bytes, normalized source path, schemas, observations, diagnostics, versions,
and scripts.

Removing an absolute path does not anonymize this material. Field names,
values, relative filenames, schemas, and provider messages may reveal personal,
commercial, or environment information.

Before sharing:

1. Inspect every retained Parquet, JSON, report, and Python file.
2. Treat values, schemas, filenames, versions, and diagnostics as potentially
   sensitive.
3. Do not redact a bound file in place; changing it invalidates the manifest.
4. Prefer reproducing a non-sensitive minimal Case and sharing that new
   reproducer instead of production bytes.
5. Use a channel appropriate for the data and recipient.

See [Using Parquity](usage.md) for commands, [Writing Cases](cases.md) for the
Case grammar, [Machine format overview](machine-formats.md) for machine
contracts, and [Versioning](../VERSIONING.md) for compatibility policy.
