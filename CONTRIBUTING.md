# Contributing to Parquity

Parquity welcomes focused fixes, provider support, reproducible
interoperability cases, and documentation corrections.

Search existing issues before starting. For a new command, format change,
provider direction, or broad refactor, open an issue first so the behavior and
compatibility cost can be agreed before implementation.

When reporting engine behavior, describe the observation and reproduction
evidence. Leave fault attribution to the upstream investigation.

## Set up the repository

The development baseline is Python 3.12 with [`uv`](https://docs.astral.sh/uv/).
Install the locked development environment and both optional providers:

```console
uv sync --locked --group dev --extra datafusion --extra fastparquet
uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
```

Run `uv lock` only when dependencies intentionally change, and review the
resulting `uv.lock` diff. Do not edit the lock file by hand.

## Work in a short feedback loop

Run the narrowest relevant test while editing:

```console
uv run pytest tests/unit/test_case_type_extensions.py -q
```

Then run the source checks:

```console
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run python scripts/check_structure.py
git diff --check
```

Use `uv run ruff format .` to apply formatting.

## Before opening a pull request

Run the complete source suite:

```console
uv lock --check
uv run pre-commit run --all-files
uv run pytest --cov=parquity --cov-branch --cov-report=term-missing
```

If the change affects dependencies, packaging, installed files, entry points,
templates, or the README, also run:

```console
uv pip check
uv run pip-audit --local
uv build
uv run twine check dist/*
uv run check-wheel-contents dist/*.whl
```

Install the new wheel into a clean environment and exercise the affected CLI
path from outside the repository. Provider changes should be checked with the
real provider, not a replacement module.

## Test standard

Tests should name a plausible behavioral regression and use an independent
oracle. Prefer public outcomes: canonical bytes, schemas, values, exit codes,
validated artifacts, and typed errors.

Do not add sleeps, network access, snapshots, recorded responses, retries,
quarantine markers, persistent Hypothesis state, or tests that only import a
module or echo a constant. Coverage is evidence of exercised behavior, not a
reason to invent a test.

Keep Python modules at or below 350 physical lines and callables at or below
100 physical lines. `scripts/check_structure.py` enforces those bounds and the
declared import boundaries.

Process tests use bounded child programs and readiness signals. Real
crash-prone provider inputs belong in local acceptance evidence, not the normal
test suite.

## Documentation changes

Put each fact in one owning document:

- `README.md` explains the product, the two comparison models, and the first
  useful commands;
- `docs/usage.md` owns command syntax, outputs, exits, and operational warnings;
- `docs/cases.md` owns the Case grammar and generated-value bounds;
- `docs/evidence.md` owns bundle layouts, replay, triage vocabulary, and
  retained-data guidance;
- `docs/providers.md` and `docs/writer-profiles.md` own provider selection and
  writer-option support;
- `VERSIONING.md` owns package release and public compatibility policy; and
- `SECURITY.md` owns private vulnerability reporting.

Commands and JSON in public documentation must be run against a freshly built
wheel. Check the rendered README with `twine check`, verify its links resolve
from PyPI, and verify repository-relative links in the focused guides. Do not
expose local paths, private data, internal development notes, task names, or
private planning labels.

## Commits and pull requests

Commit messages follow
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
because the repository validates them at the `commit-msg` hook. Examples:

```text
fix(scan): preserve exact reader failure evidence
docs: explain schema-aware fuzz
```

Keep a pull request focused. Its description should state the user-visible
problem, the chosen behavior, the evidence used to verify it, and any remaining
limitation. Link the relevant issue when one exists.

Report suspected security vulnerabilities privately through
[SECURITY.md](SECURITY.md).
