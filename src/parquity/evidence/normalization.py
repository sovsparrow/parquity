from __future__ import annotations

import re
from pathlib import PurePath
from typing import NamedTuple

from .digests import sha256_hex


class DetailRule(NamedTuple):
    name: str
    pattern: re.Pattern[str]
    replacement: str


TEMPORARY_ROOT = "<parquity-temp>"

DETAIL_RULES_V1 = (
    DetailRule(
        "temporary-root-separator", re.compile(r"<parquity-temp>[/\\]+"), "<parquity-temp>/"
    ),
    DetailRule("whitespace", re.compile(r"\s+"), " "),
)

# What remains of a substituted transient root is the rest of the path, still spelled with the
# platform's own separator. Since the normalized detail is what the fingerprint hashes, leaving it
# native gives the same failure two identities — one on Windows, one everywhere else — so evidence
# recorded on one platform cannot be replayed against the other.
_TEMPORARY_PATH = re.compile(re.escape(TEMPORARY_ROOT) + r"\S*")


def bounded_detail(value: object) -> str:
    return " ".join(str(value).split())[:500]


def normalize_detail(detail: str, transient_roots: tuple[PurePath, ...] = ()) -> str:
    normalized = detail
    roots = sorted({str(path) for path in transient_roots}, key=len, reverse=True)
    for root in roots:
        normalized = normalized.replace(root, TEMPORARY_ROOT)
    normalized = _TEMPORARY_PATH.sub(lambda match: match.group().replace("\\", "/"), normalized)
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
