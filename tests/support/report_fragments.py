from __future__ import annotations


def report_fragments(specification: str) -> tuple[str, ...]:
    return tuple(specification.split(";"))


__all__ = ["report_fragments"]
