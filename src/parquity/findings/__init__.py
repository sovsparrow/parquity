FINDING_FORMAT = "parquity.finding.v1"
REQUIRED_ARTIFACTS = (
    "REPORT.md",
    "case.json",
    "matrix.json",
    "reproduce.py",
    "upstream_repro.py",
)
OPTIONAL_INPUT = "input.parquet"
OPTIONAL_DISCOVERED_CASE = "discovered_case.json"

__all__ = [
    "FINDING_FORMAT",
    "OPTIONAL_DISCOVERED_CASE",
    "OPTIONAL_INPUT",
    "REQUIRED_ARTIFACTS",
]
