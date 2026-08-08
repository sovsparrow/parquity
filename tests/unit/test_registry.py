from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

import parquity.engines as registry
from parquity.engines.base import EngineDescriptor, EngineIdentity

if TYPE_CHECKING:
    import pyarrow as pa

Factory = Callable[[str], object]


def _descriptor(
    name: str,
    *,
    tier: str = "extended",
    reader: bool = True,
    writer: bool = True,
) -> EngineDescriptor:
    return EngineDescriptor(
        name=name,
        distribution=f"{name}-distribution",
        import_name=f"{name}_provider",
        adapter_module=f"{name}_adapter",
        installation_hint=f"install {name}",
        tier=tier,
        reader=reader,
        writer=writer,
    )


def _install_factory(
    monkeypatch: pytest.MonkeyPatch,
    descriptor: EngineDescriptor,
    factory: Factory,
) -> None:
    provider = ModuleType(descriptor.import_name)
    adapter = ModuleType(descriptor.adapter_module)

    def installed_version(distribution: str) -> str:
        assert distribution == descriptor.distribution
        return "1.0"

    monkeypatch.setattr(adapter, "create_engine", factory, raising=False)
    monkeypatch.setattr(registry.metadata, "version", installed_version)
    monkeypatch.setitem(sys.modules, descriptor.import_name, provider)
    monkeypatch.setitem(sys.modules, descriptor.adapter_module, adapter)


@dataclass(frozen=True, slots=True)
class _Reader:
    identity: EngineIdentity

    def read(self, path: Path) -> pa.Table:
        raise AssertionError(path)


@dataclass(frozen=True, slots=True)
class _ReaderWriter:
    identity: EngineIdentity

    def read(self, path: Path) -> pa.Table:
        raise AssertionError(path)

    def write(self, table: pa.Table, path: Path) -> None:
        del table, path


def test_discovery_reads_metadata_and_directions_without_importing_implementations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("synthetic", writer=False)

    def synthetic_version(distribution: str) -> str:
        assert distribution == descriptor.distribution
        return "4.5.6"

    monkeypatch.setattr(registry.metadata, "version", synthetic_version)
    assert descriptor.import_name not in sys.modules
    assert descriptor.adapter_module not in sys.modules

    availability = registry.discover_engines((descriptor,))[0]

    assert descriptor.import_name not in sys.modules
    assert descriptor.adapter_module not in sys.modules
    assert availability.available
    assert availability.version == "4.5.6"
    assert availability.tier == "extended"
    assert availability.reader
    assert not availability.writer


def test_missing_distribution_returns_declared_unavailable_evidence_with_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("missing", writer=False)

    def missing_version(distribution: str) -> str:
        raise metadata.PackageNotFoundError(distribution)

    monkeypatch.setattr(registry.metadata, "version", missing_version)

    resolution = registry.resolve_engine(descriptor.name, (descriptor,))

    assert resolution.reader is None
    assert resolution.writer is None
    assert not resolution.availability.available
    assert resolution.availability.version is None
    assert resolution.availability.reader
    assert not resolution.availability.writer
    assert resolution.availability.installation_hint == "install missing"


def test_missing_provider_import_returns_unavailable_evidence_with_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("provider_that_does_not_exist_for_parquity")

    def installed_version(distribution: str) -> str:
        assert distribution == descriptor.distribution
        return "1.0"

    monkeypatch.setattr(registry.metadata, "version", installed_version)

    resolution = registry.resolve_engine(descriptor.name, (descriptor,))

    assert resolution.reader is None
    assert resolution.writer is None
    assert not resolution.availability.available
    assert resolution.availability.version == "1.0"
    assert resolution.availability.installation_hint == f"install {descriptor.name}"


def test_provider_import_missing_nested_dependency_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("nested_import_failure")

    def installed_version(distribution: str) -> str:
        assert distribution == descriptor.distribution
        return "1.0"

    def import_with_nested_failure(name: str) -> ModuleType:
        del name
        raise ModuleNotFoundError(name="nested_provider_dependency")

    monkeypatch.setattr(registry.metadata, "version", installed_version)
    monkeypatch.setattr(registry, "import_module", import_with_nested_failure)

    with pytest.raises(ModuleNotFoundError):
        registry.resolve_engine(descriptor.name, (descriptor,))


def test_unexpected_metadata_and_internal_adapter_failures_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_descriptor = _descriptor("metadata_failure")

    def fail_metadata(distribution: str) -> str:
        del distribution
        raise RuntimeError("unexpected metadata failure")

    monkeypatch.setattr(registry.metadata, "version", fail_metadata)
    with pytest.raises(RuntimeError):
        registry.resolve_engine(metadata_descriptor.name, (metadata_descriptor,))

    adapter_descriptor = _descriptor("missing_adapter")

    def installed_version(distribution: str) -> str:
        assert distribution == adapter_descriptor.distribution
        return "1.0"

    monkeypatch.setattr(registry.metadata, "version", installed_version)
    monkeypatch.setitem(
        sys.modules,
        adapter_descriptor.import_name,
        ModuleType(adapter_descriptor.import_name),
    )
    with pytest.raises(ModuleNotFoundError):
        registry.resolve_engine(adapter_descriptor.name, (adapter_descriptor,))


def test_non_callable_and_failing_adapter_factories_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    non_callable = _descriptor("non_callable")
    provider = ModuleType(non_callable.import_name)
    adapter = ModuleType(non_callable.adapter_module)

    def installed_version(distribution: str) -> str:
        assert distribution == non_callable.distribution
        return "1.0"

    monkeypatch.setattr(adapter, "create_engine", object(), raising=False)
    monkeypatch.setattr(registry.metadata, "version", installed_version)
    monkeypatch.setitem(sys.modules, non_callable.import_name, provider)
    monkeypatch.setitem(sys.modules, non_callable.adapter_module, adapter)
    with pytest.raises(TypeError):
        registry.resolve_engine(non_callable.name, (non_callable,))

    failing = _descriptor("failing_factory")

    def fail_factory(version: str) -> object:
        del version
        raise RuntimeError("unexpected factory failure")

    _install_factory(monkeypatch, failing, fail_factory)
    with pytest.raises(RuntimeError):
        registry.resolve_engine(failing.name, (failing,))


def test_reader_only_resolution_exposes_no_fake_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("reader_only", writer=False)

    def create_engine(version: str) -> object:
        return _Reader(EngineIdentity(descriptor.name, version))

    _install_factory(monkeypatch, descriptor, create_engine)

    resolution = registry.resolve_engine(descriptor.name, (descriptor,))

    assert resolution.reader is not None
    assert resolution.reader.identity == EngineIdentity(descriptor.name, "1.0")
    assert resolution.writer is None


def test_reader_writer_resolution_shares_one_immutable_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("reader_writer")

    def create_engine(version: str) -> object:
        return _ReaderWriter(EngineIdentity(descriptor.name, version))

    _install_factory(monkeypatch, descriptor, create_engine)

    resolution = registry.resolve_engine(descriptor.name, (descriptor,))

    assert resolution.reader is not None
    assert resolution.writer is not None
    assert resolution.reader.identity is resolution.writer.identity


def test_resolution_refuses_undeclared_and_missing_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader_only = _descriptor("undeclared_writer", writer=False)

    def reader_writer(version: str) -> object:
        return _ReaderWriter(EngineIdentity(reader_only.name, version))

    _install_factory(monkeypatch, reader_only, reader_writer)
    with pytest.raises(TypeError):
        registry.resolve_engine(reader_only.name, (reader_only,))

    reader_writer_descriptor = _descriptor("missing_writer")

    def reader(version: str) -> object:
        return _Reader(EngineIdentity(reader_writer_descriptor.name, version))

    _install_factory(monkeypatch, reader_writer_descriptor, reader)
    with pytest.raises(TypeError):
        registry.resolve_engine(reader_writer_descriptor.name, (reader_writer_descriptor,))

    malformed = _descriptor("non_callable_reader", writer=False)

    class NonCallableReader:
        identity = EngineIdentity(malformed.name, "1.0")
        read = object()

    def non_callable_reader(version: str) -> object:
        del version
        return NonCallableReader()

    _install_factory(monkeypatch, malformed, non_callable_reader)
    with pytest.raises(TypeError):
        registry.resolve_engine(malformed.name, (malformed,))


def test_resolution_refuses_inconsistent_shared_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor("expected")
    conflicts = iter(
        (
            _ReaderWriter(EngineIdentity("other", "1.0")),
            _ReaderWriter(EngineIdentity(descriptor.name, "2.0")),
        )
    )

    def create_engine(version: str) -> object:
        del version
        return next(conflicts)

    _install_factory(monkeypatch, descriptor, create_engine)

    with pytest.raises(TypeError):
        registry.resolve_engine(descriptor.name, (descriptor,))
    with pytest.raises(TypeError):
        registry.resolve_engine(descriptor.name, (descriptor,))


def test_descriptors_refuse_invalid_tiers_and_directionless_declarations() -> None:
    with pytest.raises(ValueError):
        _descriptor("invalid_tier", tier="unknown")
    with pytest.raises(ValueError):
        _descriptor("directionless", reader=False, writer=False)


def test_unknown_engine_resolution_is_a_structured_configuration_error() -> None:
    descriptor = _descriptor("known")

    resolution = registry.resolve_engine("unknown", (descriptor,))

    assert resolution.reader is None
    assert resolution.writer is None
    assert not resolution.availability.available
    assert resolution.availability.tier == "unregistered"
    assert resolution.availability.installation_hint == "Choose a registered engine: known"


def test_reader_selection_rejects_invalid_capability_and_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer_only = _descriptor("writer_only", reader=False)
    with pytest.raises(registry.EngineSelectionError) as capability:
        registry.resolve_reader_selection("writer_only", (writer_only,))
    assert capability.value.kind == "ENGINE_CAPABILITY_ERROR"

    missing = _descriptor("missing", tier="core", writer=False)

    def missing_version(distribution: str) -> str:
        raise metadata.PackageNotFoundError(distribution)

    monkeypatch.setattr(registry.metadata, "version", missing_version)
    with pytest.raises(registry.EngineSelectionError) as unavailable:
        registry.resolve_reader_selection(None, (missing,))
    assert unavailable.value.kind == "ENGINE_UNAVAILABLE"
    assert unavailable.value.unavailable[0].installation_hint == "install missing"
