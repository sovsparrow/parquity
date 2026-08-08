# Versioning

This document defines how Parquity package releases change the public surface.
Release history is recorded in [CHANGELOG.md](CHANGELOG.md).

## Package versions

Parquity versions use Python's PEP 440 spelling and follow Semantic Versioning
for the documented public surface.

Before 1.0.0:

- a minor release may add compatible features or make a documented breaking
  change while the public surface is still stabilizing;
- a patch release contains compatible fixes only;
- release candidates use forms such as `0.2.0rc1`; and
- post releases are reserved for packaging or documentation corrections, not
  code fixes.

Published distributions are immutable. The package version has one source in
`pyproject.toml`; the CLI and Python package read installed distribution
metadata rather than maintaining a second version constant.

## Public compatibility surface

The following are public once released:

- documented CLI commands, arguments, options, exit meanings, and status
  values;
- the `parquity` console entry point and `parquity.__version__`;
- provider extra names and documented reader/writer directions;
- the accepted Case grammar; and
- durable bundle and machine-output formats that carry a `parquity.*.vN`
  identity.

Other Python modules and objects are implementation details unless a public
document marks them otherwise.

Human terminal summaries are projections and may gain compatible presentation
improvements. Redirected output and explicit `--json` use the versioned
`parquity.cli.v1` machine format; its compatibility rules follow the artifact
format policy below.

Dropping a supported Python version, provider direction, Case branch, artifact
decoder, or documented CLI behavior is a compatibility change and must appear
in the changelog.

## Package versions and artifact formats

A package version such as `0.1.0` identifies an installed Parquity release. A
format identity such as `parquity.case.v1` identifies the grammar of a saved
document. They are intentionally independent.

An existing format identity never changes meaning. An incompatible change to a
grammar, canonicalization rule, inventory, identity rule, occurrence
extraction, or family projection requires a new format identity. A package may
support more than one format generation while users migrate.

The Case contract belongs to [Writing Cases](docs/cases.md). Bundle layouts,
hashes, replay states, and derived triage identities belong to
[Evidence and replay](docs/evidence.md). This file does not duplicate those
format references.

## Provider behavior and reproducibility

Parquity records provider and package versions with evidence because provider
behavior can change independently of Parquity. A dependency lower bound is an
installation constraint, not a claim that future provider combinations will
produce the same result.

Hypothesis seeds are scoped to the Parquity, Hypothesis, Python, and provider
environment that produced them. The reduced canonical `case.json`, not the
seed, is the durable generated reproducer.

This policy follows [Semantic Versioning 2.0.0](https://semver.org/) and
Python's [version specifier standard](https://packaging.python.org/en/latest/specifications/version-specifiers/).
