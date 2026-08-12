# Changelog

All notable changes to Parquity are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and package releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-12

### Added

- Generate deterministic Markdown reports for `check`, `fuzz`, and `scan`.
  Reports summarize failures, link to saved reproducers, and record the command
  and environment needed to reproduce the run.
- Publish new generated evidence as `parquity.run.v2` and new scan evidence as
  `parquity.scan-run.v2` and `parquity.scan-finding.v2`. Released v1 bundles
  remain readable and replayable.
- Keep generated failures beyond the reproducer limit represented in
  `run.json`.
- Record Python, platform, provider, and dependency versions in new scan
  evidence.

### Changed

- Rename `--max-findings` to `--max-saved` for `fuzz` and `scan`.
- Let equivalent generated failures share one minimized reproducer while
  retaining the affected Case identities in `run.json`.
- Show replay results through the same report format used by the original run.
- Preserve structural depth and map/list roles while deduplicating generated
  failures across field and row indexes.

### Fixed

- Distinguish missing paths, unsupported directories, and malformed bundles
  when replay input is invalid.
- Preserve complete scan diagnostics in standalone reports.
- Prevent provider output from corrupting scan worker control messages.
- Treat supported equivalent Arrow schema representations as equal during scan
  comparison.
- Report finite-strategy exhaustion without claiming that the requested
  example bound was reached.

### Removed

- Remove the `triage` command. Use `replay` to re-evaluate saved evidence.

## [0.1.0] - 2026-08-09

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

[Unreleased]: https://github.com/sovsparrow/parquity/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sovsparrow/parquity/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sovsparrow/parquity/releases/tag/v0.1.0
