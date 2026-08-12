# Parquity v0.1.0 fixture provenance

These immutable compatibility fixtures were emitted by the annotated Parquity
v0.1.0 release. No writer, serializer, report renderer, or bundle builder from
the current checkout was used.

- Annotated tag object: `c6c0b311bf41a498fe528f41d7ca9e8b6782a3bc`
- Peeled release commit: `dee99842f081af041e21293067a2b662c60b54e7`
- Released `uv.lock` SHA-256:
  `965ec34ba88038d16a1dcac6f40f14f6714e6884481d6a040d7041c1af441ddb`
- Python: `3.12.13`
- Dependency resolution: released lock, offline

The release tree and environment were isolated under a fresh temporary
directory. The commands were:

```console
repo="$(git rev-parse --show-toplevel)"
work="$(mktemp -d)"
mkdir -p "$work/release"
git archive c6c0b311bf41a498fe528f41d7ca9e8b6782a3bc | tar -x -C "$work/release"
uv sync --project "$work/release" --frozen --offline
uv run --project "$work/release" --frozen --offline python "$work/generate.py" "$repo/tests/fixtures/v0_1_0"
```

`generate.py` used only released public bundle builders and deterministic
in-memory records. The generated fixture contains one released
`parquity.run.v1` check run and one released `parquity.finding.v1` child. Its
evaluator wrote the fixed payload `PAR1released-pyarrowPAR1`; it did not invoke
a Parquet writer. The scan fixture contains one released
`parquity.scan-run.v1` run and one released `parquity.scan-finding.v1` child
over the fixed payload `PAR1released-scanPAR1`, with deterministic provider
error and process-crash observations.

Tests must treat every byte under `generated/` and `scan/` as sealed evidence.
They may copy and tamper with a fixture to test rejection, but must never
rebuild, rewrite, or reseal the checked-in fixture.
