from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from importlib import import_module, metadata
from typing import Literal, NamedTuple, Protocol, cast

from .base import EngineDescriptor, EngineIdentity, EngineReader, EngineWriter
from .external import (
    EXTERNAL_TIER,
    ExternalEngineConfigurationError,
    ExternalEngineProtocolError,
    ExternalEngineTimeout,
    ExternalRegistration,
    external_registrations,
)


@dataclass(frozen=True, slots=True)
class EngineAvailability:
    name: str
    distribution: str
    tier: str
    reader: bool
    writer: bool
    available: bool
    version: str | None
    installation_hint: str | None
    detail: str

    def __post_init__(self) -> None:
        if self.available and self.version is None:
            raise ValueError("an available engine requires a version")
        if not self.available and not self.installation_hint:
            raise ValueError("an unavailable engine requires an installation hint")


CORE_ENGINE_DESCRIPTORS = (
    EngineDescriptor(
        name="pyarrow",
        distribution="pyarrow",
        import_name="pyarrow",
        adapter_module="parquity.engines.pyarrow",
        installation_hint="Install with: python -m pip install pyarrow",
        tier="core",
        reader=True,
        writer=True,
    ),
    EngineDescriptor(
        name="duckdb",
        distribution="duckdb",
        import_name="duckdb",
        adapter_module="parquity.engines.duckdb",
        installation_hint="Install with: python -m pip install duckdb",
        tier="core",
        reader=True,
        writer=True,
    ),
    EngineDescriptor(
        name="polars",
        distribution="polars",
        import_name="polars",
        adapter_module="parquity.engines.polars",
        installation_hint="Install with: python -m pip install polars",
        tier="core",
        reader=True,
        writer=True,
    ),
)

EXTENDED_ENGINE_DESCRIPTORS = (
    EngineDescriptor(
        name="datafusion",
        distribution="datafusion",
        import_name="datafusion",
        adapter_module="parquity.engines.datafusion",
        installation_hint="Install with: python -m pip install 'parquity[datafusion]'",
        tier="extended",
        reader=True,
        writer=False,
    ),
    EngineDescriptor(
        name="fastparquet",
        distribution="fastparquet",
        import_name="fastparquet",
        adapter_module="parquity.engines.fastparquet",
        installation_hint="Install with: python -m pip install 'parquity[fastparquet]'",
        tier="extended",
        reader=True,
        writer=True,
    ),
)

ENGINE_DESCRIPTORS = CORE_ENGINE_DESCRIPTORS + EXTENDED_ENGINE_DESCRIPTORS
PYTHON_SUPPORT = {item.name: ["3.11", "3.12", "3.13", "3.14"] for item in ENGINE_DESCRIPTORS}
BUILTIN_ENGINE_NAMES = frozenset(item.name for item in ENGINE_DESCRIPTORS)


def registered_descriptors() -> tuple[EngineDescriptor, ...]:
    return ENGINE_DESCRIPTORS + tuple(item.descriptor for item in _external())


def _external() -> tuple[ExternalRegistration, ...]:
    return external_registrations(BUILTIN_ENGINE_NAMES)


def external_engine_names() -> frozenset[str]:
    return frozenset(item.spec.name for item in _external())


def _selected(descriptors: Sequence[EngineDescriptor] | None) -> Sequence[EngineDescriptor]:
    return registered_descriptors() if descriptors is None else descriptors


class EngineFactory(Protocol):
    def __call__(self, version: str) -> object: ...


@dataclass(frozen=True, slots=True)
class EngineResolution:
    availability: EngineAvailability
    reader: EngineReader | None
    writer: EngineWriter | None


class EngineSelectionError(ValueError):
    def __init__(
        self,
        kind: str,
        detail: str,
        unavailable: tuple[EngineAvailability, ...] = (),
    ) -> None:
        self.kind = kind
        self.detail = detail
        self.unavailable = unavailable
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class EngineSelection:
    writer_names: tuple[str, ...]
    reader_names: tuple[str, ...]
    writers: tuple[EngineWriter, ...]
    readers: tuple[EngineReader, ...]

    @property
    def writer_versions(self) -> tuple[tuple[str, str], ...]:
        return tuple((engine.identity.name, engine.identity.version) for engine in self.writers)

    @property
    def reader_versions(self) -> tuple[tuple[str, str], ...]:
        return tuple((engine.identity.name, engine.identity.version) for engine in self.readers)


class ReaderSelection(NamedTuple):
    reader_names: tuple[str, ...]
    readers: tuple[EngineReader, ...]

    @property
    def reader_versions(self) -> tuple[tuple[str, str], ...]:
        return tuple((engine.identity.name, engine.identity.version) for engine in self.readers)


def discover_engines(
    descriptors: Sequence[EngineDescriptor] | None = None,
) -> tuple[EngineAvailability, ...]:
    return tuple(_availability(descriptor) for descriptor in _selected(descriptors))


def resolve_engine(
    name: str,
    descriptors: Sequence[EngineDescriptor] | None = None,
) -> EngineResolution:
    selected = _selected(descriptors)
    descriptor = next((candidate for candidate in selected if candidate.name == name), None)
    if descriptor is None:
        choices = ", ".join(candidate.name for candidate in selected)
        availability = EngineAvailability(
            name=name,
            distribution=name,
            tier="unregistered",
            reader=False,
            writer=False,
            available=False,
            version=None,
            installation_hint=f"Choose a registered engine: {choices}",
            detail="engine is not registered",
        )
        return EngineResolution(availability, None, None)
    if descriptor.tier == EXTERNAL_TIER:
        return _resolve_external(descriptor.name)
    availability = _distribution_availability(descriptor)
    if not availability.available or availability.version is None:
        return EngineResolution(availability, None, None)
    try:
        import_module(descriptor.import_name)
    except ModuleNotFoundError as error:
        if error.name != descriptor.import_name:
            raise
        missing_provider = EngineAvailability(
            name=descriptor.name,
            distribution=descriptor.distribution,
            tier=descriptor.tier,
            reader=descriptor.reader,
            writer=descriptor.writer,
            available=False,
            version=availability.version,
            installation_hint=descriptor.installation_hint,
            detail="provider import was not found",
        )
        return EngineResolution(missing_provider, None, None)
    module = import_module(descriptor.adapter_module)
    factory_value = cast(object, getattr(module, "create_engine", None))
    if not callable(factory_value):
        raise TypeError("adapter does not expose a callable create_engine")
    factory = cast(EngineFactory, factory_value)
    engine = factory(availability.version)
    reader, writer = _validate_engine(engine, descriptor, availability.version)
    return EngineResolution(availability, reader, writer)


def resolve_engines(
    names: Sequence[str],
    descriptors: Sequence[EngineDescriptor] | None = None,
) -> tuple[EngineResolution, ...]:
    selected = _selected(descriptors)
    return tuple(resolve_engine(name, selected) for name in names)


def resolve_engine_selection(
    writer_names: str | Sequence[str] | None,
    reader_names: str | Sequence[str] | None,
    descriptors: Sequence[EngineDescriptor] | None = None,
) -> EngineSelection:
    selected = _selected(descriptors)
    writers = _canonical_names(writer_names, "writer", selected)
    readers = _canonical_names(reader_names, "reader", selected)
    requested = tuple(
        descriptor.name for descriptor in selected if descriptor.name in {*writers, *readers}
    )
    resolutions = {name: resolve_engine(name, selected) for name in requested}
    _require_available(tuple(resolutions.values()))
    resolved_writers: list[EngineWriter] = []
    resolved_readers: list[EngineReader] = []
    for name in writers:
        writer = resolutions[name].writer
        if writer is None:
            raise TypeError("resolved writer is missing its declared direction")
        resolved_writers.append(writer)
    for name in readers:
        reader = resolutions[name].reader
        if reader is None:
            raise TypeError("resolved reader is missing its declared direction")
        resolved_readers.append(reader)
    return EngineSelection(writers, readers, tuple(resolved_writers), tuple(resolved_readers))


def resolve_reader_selection(
    reader_names: str | Sequence[str] | None,
    descriptors: Sequence[EngineDescriptor] | None = None,
) -> ReaderSelection:
    """Resolves the readers for `scan`, which external engines may not join.

    Reader-only selection is what `scan` and replay of scan evidence use, and scan reads its files
    inside a worker with its own contract: a bridge that stops answering is classified there by
    rules written for an in-process provider, and `ReaderOutcomeKind.TIMEOUT` has nothing mapped to
    it. Rather than let that be discovered from a confusing run, an external engine is refused
    here until the scan worker knows what to do with one.
    """
    selected = _selected(descriptors)
    names = _canonical_names(reader_names, "reader", selected)
    by_name = {descriptor.name: descriptor for descriptor in selected}
    external = [name for name in names if by_name[name].tier == EXTERNAL_TIER]
    if external:
        raise EngineSelectionError(
            "ENGINE_CAPABILITY_ERROR",
            f"external engines are not available to scan: {', '.join(external)}",
        )
    resolutions = resolve_engines(names, selected)
    _require_available(resolutions)
    readers: list[EngineReader] = []
    for resolution in resolutions:
        if resolution.reader is None:
            raise TypeError("resolved reader is missing its declared direction")
        readers.append(resolution.reader)
    return ReaderSelection(names, tuple(readers))


def default_engine_names(
    direction: Literal["reader", "writer"],
    descriptors: Sequence[EngineDescriptor] = ENGINE_DESCRIPTORS,
) -> tuple[str, ...]:
    return tuple(
        descriptor.name
        for descriptor in descriptors
        if descriptor.tier == "core" and getattr(descriptor, direction)
    )


def _require_available(resolutions: tuple[EngineResolution, ...]) -> None:
    unavailable = tuple(
        item.availability for item in resolutions if not item.availability.available
    )
    if unavailable:
        names = ", ".join(item.name for item in unavailable)
        raise EngineSelectionError(
            "ENGINE_UNAVAILABLE", f"selected engine availability failed: {names}", unavailable
        )


def _canonical_names(
    requested: str | Sequence[str] | None,
    direction: Literal["reader", "writer"],
    descriptors: Sequence[EngineDescriptor],
) -> tuple[str, ...]:
    if requested is None:
        names = list(default_engine_names(direction, descriptors))
    elif isinstance(requested, str):
        names = [name.strip() for name in requested.split(",")]
    else:
        names = list(requested)
    if not names or any(not name for name in names):
        raise EngineSelectionError("INVALID_ENGINE_SET", f"{direction} set contains an empty name")
    if len(names) != len(set(names)):
        raise EngineSelectionError(
            "INVALID_ENGINE_SET", f"{direction} set contains a duplicate name"
        )
    by_name = {descriptor.name: descriptor for descriptor in descriptors}
    unknown = [name for name in names if name not in by_name]
    if unknown:
        raise EngineSelectionError(
            "UNKNOWN_ENGINE", f"unknown {direction} engine: {', '.join(unknown)}"
        )
    incompatible = [name for name in names if not getattr(by_name[name], direction)]
    if incompatible:
        raise EngineSelectionError(
            "ENGINE_CAPABILITY_ERROR",
            f"engine does not support {direction}: {', '.join(incompatible)}",
        )
    selected = set(names)
    return tuple(descriptor.name for descriptor in descriptors if descriptor.name in selected)


def _availability(descriptor: EngineDescriptor) -> EngineAvailability:
    if descriptor.tier != EXTERNAL_TIER:
        return _distribution_availability(descriptor)
    registration = next((item for item in _external() if item.spec.name == descriptor.name), None)
    if registration is None:
        raise EngineSelectionError(
            "ENGINE_UNAVAILABLE", f"external engine is no longer configured: {descriptor.name}"
        )
    return _external_availability(registration)


def _external_availability(registration: ExternalRegistration) -> EngineAvailability:
    descriptor = registration.descriptor
    info = registration.info
    return EngineAvailability(
        name=descriptor.name,
        distribution=descriptor.distribution,
        tier=EXTERNAL_TIER,
        reader=descriptor.reader,
        writer=descriptor.writer,
        available=info is not None,
        version=None if info is None else info.version,
        installation_hint=None if info is not None else descriptor.installation_hint,
        detail=registration.detail,
    )


def _resolve_external(name: str) -> EngineResolution:
    from .external.adapter import create_engine  # noqa: PLC0415 - defers the pyarrow import.

    registration = next((item for item in _external() if item.spec.name == name), None)
    if registration is None:
        raise EngineSelectionError(
            "ENGINE_UNAVAILABLE", f"external engine is no longer configured: {name}"
        )
    availability = _external_availability(registration)
    info = registration.info
    if info is None:
        return EngineResolution(availability, None, None)
    engine = create_engine(registration.spec, info)
    return EngineResolution(
        availability, engine if info.reader else None, engine if info.writer else None
    )


def _distribution_availability(descriptor: EngineDescriptor) -> EngineAvailability:
    try:
        version = metadata.version(descriptor.distribution)
    except metadata.PackageNotFoundError:
        return EngineAvailability(
            name=descriptor.name,
            distribution=descriptor.distribution,
            tier=descriptor.tier,
            reader=descriptor.reader,
            writer=descriptor.writer,
            available=False,
            version=None,
            installation_hint=descriptor.installation_hint,
            detail="distribution metadata was not found",
        )
    return EngineAvailability(
        name=descriptor.name,
        distribution=descriptor.distribution,
        tier=descriptor.tier,
        reader=descriptor.reader,
        writer=descriptor.writer,
        available=True,
        version=version,
        installation_hint=None,
        detail="distribution metadata found",
    )


__all__ = [
    "BUILTIN_ENGINE_NAMES",
    "CORE_ENGINE_DESCRIPTORS",
    "ENGINE_DESCRIPTORS",
    "EXTENDED_ENGINE_DESCRIPTORS",
    "EXTERNAL_TIER",
    "PYTHON_SUPPORT",
    "EngineAvailability",
    "EngineDescriptor",
    "EngineFactory",
    "EngineIdentity",
    "EngineReader",
    "EngineResolution",
    "EngineSelection",
    "EngineSelectionError",
    "EngineWriter",
    "ExternalEngineConfigurationError",
    "ExternalEngineProtocolError",
    "ExternalEngineTimeout",
    "ExternalRegistration",
    "ReaderSelection",
    "default_engine_names",
    "discover_engines",
    "external_engine_names",
    "registered_descriptors",
    "resolve_engine",
    "resolve_engine_selection",
    "resolve_engines",
    "resolve_reader_selection",
]


def _validate_engine(
    engine: object,
    descriptor: EngineDescriptor,
    version: str,
) -> tuple[EngineReader | None, EngineWriter | None]:
    identity = cast(object, getattr(engine, "identity", None))
    if not isinstance(identity, EngineIdentity) or identity != EngineIdentity(
        descriptor.name, version
    ):
        raise TypeError("adapter factory returned inconsistent engine identity")
    is_reader = callable(cast(object, getattr(engine, "read", None)))
    is_writer = callable(cast(object, getattr(engine, "write", None)))
    if is_reader != descriptor.reader or is_writer != descriptor.writer:
        raise TypeError("adapter factory returned inconsistent engine directions")
    reader = cast(EngineReader, engine) if is_reader else None
    writer = cast(EngineWriter, engine) if is_writer else None
    return reader, writer
