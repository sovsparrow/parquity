from __future__ import annotations

from typing import TypeGuard

MIN_FUZZ_EXAMPLES = 1
MIN_FUZZ_SEED = 0
MIN_FUZZ_SAVED_LIMIT = 1
DEFAULT_FUZZ_SAVED_LIMIT = 8
MAX_FUZZ_SAVED_LIMIT = 64
MAX_FUZZ_SEED = 2**64 - 1

MIN_SCAN_TIMEOUT_SECONDS = 1
MAX_SCAN_TIMEOUT_SECONDS = 300
DEFAULT_SCAN_TIMEOUT_SECONDS = 30

MIN_SCAN_SAVED_LIMIT = 1
MAX_SCAN_SAVED_LIMIT = 64
DEFAULT_SCAN_SAVED_LIMIT = 32


def fuzz_examples_is_valid(value: object) -> TypeGuard[int]:
    return _is_integer(value) and value >= MIN_FUZZ_EXAMPLES


def fuzz_seed_is_valid(value: object) -> TypeGuard[int]:
    return _is_integer(value) and MIN_FUZZ_SEED <= value <= MAX_FUZZ_SEED


def fuzz_saved_limit_is_valid(value: object) -> TypeGuard[int]:
    return _is_integer(value) and MIN_FUZZ_SAVED_LIMIT <= value <= MAX_FUZZ_SAVED_LIMIT


def scan_timeout_is_valid(value: object) -> TypeGuard[int]:
    return _is_integer(value) and MIN_SCAN_TIMEOUT_SECONDS <= value <= MAX_SCAN_TIMEOUT_SECONDS


def scan_saved_limit_is_valid(value: object) -> TypeGuard[int]:
    return _is_integer(value) and MIN_SCAN_SAVED_LIMIT <= value <= MAX_SCAN_SAVED_LIMIT


def _is_integer(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = [
    "DEFAULT_FUZZ_SAVED_LIMIT",
    "DEFAULT_SCAN_SAVED_LIMIT",
    "DEFAULT_SCAN_TIMEOUT_SECONDS",
    "MAX_FUZZ_SAVED_LIMIT",
    "MAX_FUZZ_SEED",
    "MAX_SCAN_SAVED_LIMIT",
    "MAX_SCAN_TIMEOUT_SECONDS",
    "MIN_FUZZ_EXAMPLES",
    "MIN_FUZZ_SAVED_LIMIT",
    "MIN_FUZZ_SEED",
    "MIN_SCAN_SAVED_LIMIT",
    "MIN_SCAN_TIMEOUT_SECONDS",
    "fuzz_examples_is_valid",
    "fuzz_saved_limit_is_valid",
    "fuzz_seed_is_valid",
    "scan_saved_limit_is_valid",
    "scan_timeout_is_valid",
]
