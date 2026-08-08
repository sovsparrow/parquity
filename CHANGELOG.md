# Changelog

All notable changes to Parquity are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and package releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Compare Parquet output across PyArrow, DuckDB, and Polars, with optional
  DataFusion and fastparquet providers.
- Generate small interoperability Cases with generic fuzz, or keep a supplied
  schema fixed while searching values and container shapes. Failing Cases are
  reduced automatically.
- Scan existing Parquet files with each reader in a separate process so a
  provider error, timeout, or crash can be retained as evidence.
- Save each finding as a validated, replayable bundle containing the relevant
  Case or source file, provider versions, matrix results, and reproduction
  scripts.
- Group repeated symptoms automatically in aggregate reports and expose an
  optional read-only triage view, without presenting family counts as defect
  counts.
- Present concise tables and summaries on interactive terminals while keeping
  canonical JSON stable for pipes, redirects, and explicit `--json` output.
- Exercise gzip, Brotli, row-group, and statistics writer options where the
  selected writer supports them.
- Support Python 3.11 through 3.14 and ship typed package metadata.
