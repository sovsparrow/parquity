from __future__ import annotations

from collections.abc import Iterable

from parquity.engines import ENGINE_DESCRIPTORS

_COMMAND_WORKFLOW_ROOTS = (
    "parquity.findings",
    "parquity.runs",
    "parquity.scans",
)
_EXACT_OWNER_PATHS = frozenset(
    {
        "parquity.case.arrow",
        "parquity.cli.generated",
        "parquity.cli.smoke",
        "parquity.comparison.table",
        "parquity.generation.workflow",
        "parquity.matrix",
        "parquity.model",
    }
)


def _engine_capability_roots() -> tuple[str, ...]:
    roots = {
        value
        for descriptor in ENGINE_DESCRIPTORS
        for value in (descriptor.import_name, descriptor.adapter_module)
    }
    if len(roots) != 2 * len(ENGINE_DESCRIPTORS) or any(
        not value or value.startswith(".") or value.endswith(".") for value in roots
    ):
        raise RuntimeError("engine descriptor import ownership is incomplete or ambiguous")
    return tuple(sorted(roots))


_CAPABILITY_ROOTS = (*_engine_capability_roots(), *_COMMAND_WORKFLOW_ROOTS)


def loaded_capability_modules(module_names: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            name
            for name in module_names
            if name in _EXACT_OWNER_PATHS
            or any(name == root or name.startswith(f"{root}.") for root in _CAPABILITY_ROOTS)
        )
    )


__all__ = ["loaded_capability_modules"]
