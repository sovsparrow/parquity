# Security policy

This file is for privately reporting vulnerabilities in Parquity. Operational
guidance for scanning untrusted files and sharing evidence appears where those
actions are documented: [Using Parquity](docs/usage.md) and
[Evidence and replay](docs/evidence.md).

## Supported releases

Parquity provides security fixes for its latest published release. Older
releases and unreleased source checkouts have no security-support commitment.
Before the first package release, there is no supported published version.

## Report a vulnerability

Use the repository's **Security → Report a vulnerability** form. Do not place a
suspected vulnerability, proof of concept, sensitive input, or private bundle
in a public issue.

Include, when available:

- the affected Parquity version;
- impact and the conditions required to reproduce it;
- operating system and Python version;
- selected provider names and versions;
- a minimal non-sensitive reproducer;
- any mitigation you have already tested.

If you are unsure whether an issue belongs to Parquity or one of its providers,
report it here anyway. Please allow time for private assessment before public
disclosure. The project does not promise a fixed response time, bounty, CVE
assignment, or fix for every report.

## Scope

Parquity-owned security boundaries include input and bundle validation, path
handling, artifact integrity, subprocess invocation and supervision, and
unexpected disclosure caused by Parquity.

An interoperability disagreement or ordinary provider failure is not by
itself a Parquity vulnerability. A vulnerability in PyArrow, DuckDB, Polars,
DataFusion, or fastparquet normally belongs upstream unless Parquity's use of
that provider creates or materially expands the exposure.
