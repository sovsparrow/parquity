from __future__ import annotations

import hashlib
from typing import TypeGuard


def is_sha256(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def digest_matches(payload: bytes, sha256: str, byte_count: int) -> bool:
    return len(payload) == byte_count and sha256_hex(payload) == sha256


__all__ = ["digest_matches", "is_sha256", "sha256_hex"]
