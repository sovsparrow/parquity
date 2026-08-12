from __future__ import annotations

MAX_FILES = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_VISITED_ENTRIES = 4096
MAX_STDOUT_BYTES = 16 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_OBSERVATION_BYTES = 256 * 1024 * 1024
MAX_RETAINED_INPUT_BYTES = 512 * 1024 * 1024

SCAN_LIMITS = {
    "max_files": MAX_FILES,
    "max_file_bytes": MAX_FILE_BYTES,
    "max_source_bytes": MAX_SOURCE_BYTES,
    "max_visited_entries": MAX_VISITED_ENTRIES,
    "max_observation_bytes": MAX_OBSERVATION_BYTES,
    "max_retained_input_bytes": MAX_RETAINED_INPUT_BYTES,
    "max_stdout_bytes": MAX_STDOUT_BYTES,
    "max_stderr_bytes": MAX_STDERR_BYTES,
}
__all__ = [
    "MAX_FILES",
    "MAX_FILE_BYTES",
    "MAX_OBSERVATION_BYTES",
    "MAX_RETAINED_INPUT_BYTES",
    "MAX_SOURCE_BYTES",
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "MAX_VISITED_ENTRIES",
    "SCAN_LIMITS",
]
