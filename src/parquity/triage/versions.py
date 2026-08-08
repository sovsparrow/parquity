from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .model import Occurrence


def observed_versions(
    occurrences: tuple[Occurrence, ...],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    packages: dict[str, set[str]] = {}
    providers: dict[tuple[str, str], set[str]] = {}
    for item in occurrences:
        for package, version in item.package_versions:
            packages.setdefault(package, set()).add(version)
        for role, engine, version in item.provider_versions:
            providers.setdefault((role, engine), set()).add(version)
    package_data: list[dict[str, object]] = [
        {"package": package, "versions": sorted(versions)}
        for package, versions in sorted(packages.items())
    ]
    provider_data: list[dict[str, object]] = [
        {"role": role, "engine": engine, "versions": sorted(versions)}
        for (role, engine), versions in sorted(providers.items())
    ]
    return package_data, provider_data


def version_text(values: list[dict[str, object]], name_key: str) -> str:
    return "; ".join(
        f"{item.get('role', '')} {item[name_key]} "
        f"{','.join(cast(list[str], item['versions']))}".strip()
        for item in values
    )


__all__ = ["observed_versions", "version_text"]
