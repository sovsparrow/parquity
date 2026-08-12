from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from .digests import sha256_hex


class DetailRule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    replacement: str


DETAIL_RULES_V1 = (
    DetailRule(
        "temporary-root-separator", re.compile(r"<parquity-temp>[/\\]+"), "<parquity-temp>/"
    ),
    DetailRule("whitespace", re.compile(r"\s+"), " "),
)


def bounded_detail(value: object) -> str:
    return " ".join(str(value).split())[:500]


def normalize_detail(detail: str, transient_roots: tuple[Path, ...] = ()) -> str:
    normalized = detail
    roots = sorted({str(path) for path in transient_roots}, key=len, reverse=True)
    for root in roots:
        normalized = normalized.replace(root, "<parquity-temp>")
    return " ".join(normalized.split())


def normalize_detail_v1(detail: str) -> str:
    normalized = detail
    for rule in DETAIL_RULES_V1:
        normalized = rule.pattern.sub(rule.replacement, normalized)
    return normalized.strip()


def detail_sha256_v1(detail: str) -> str:
    return sha256_hex(normalize_detail_v1(detail).encode())


__all__ = [
    "DETAIL_RULES_V1",
    "bounded_detail",
    "detail_sha256_v1",
    "normalize_detail",
    "normalize_detail_v1",
]
