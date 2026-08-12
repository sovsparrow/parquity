import hashlib
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

import parquity.scans.discovery as discovery_module
import parquity.scans.supervision as process_module
from parquity.engines import resolve_reader_selection
from parquity.scans.discovery import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_SOURCE_BYTES,
    MAX_VISITED_ENTRIES,
    ScanConfigurationError,
    discover_input,
    snapshot_file,
)
from parquity.scans.workflow import execute_scan


def _failure(function: Callable[..., object], *args: object) -> ScanConfigurationError:
    with pytest.raises(ScanConfigurationError) as failure:
        function(*args)
    return failure.value


def test_explicit_file_accepts_any_suffix_and_snapshot_binds_exact_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "no-extension"
    payload = b"fixed parquet-shaped test bytes"
    source.write_bytes(payload)
    source_opens = 0
    original_open = discovery_module.os.open

    def recording_open(path: Path, flags: int) -> int:
        nonlocal source_opens
        source_opens += 1
        return original_open(path, flags)

    monkeypatch.setattr(discovery_module.os, "open", recording_open)
    discovery = discover_input(source)
    snapshot = snapshot_file(discovery.files[0], tmp_path / "private")
    status = source.lstat()
    assert (discovery.skipped_symlinks, discovery.input_kind) == (0, "file")
    assert (discovery.total_bytes, discovery.visited_entries) == (len(payload), 1)
    assert discovery.files[0].identity == (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )
    assert source_opens == 1
    assert (snapshot.relative_path, snapshot.byte_count) == ("no-extension", len(payload))
    assert snapshot.sha256 == hashlib.sha256(payload).hexdigest()
    assert snapshot.path.read_bytes() == payload
    assert str(tmp_path) not in snapshot.relative_path


def test_scan_fails_closed_when_process_group_isolation_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source.parquet"
    source.write_bytes(b"not parquet")
    monkeypatch.delattr(process_module.os, "killpg")
    with pytest.raises(ScanConfigurationError) as unavailable:
        execute_scan(
            source,
            tmp_path / "result",
            resolve_reader_selection("pyarrow"),
            timeout_seconds=30,
            max_saved=1,
        )
    assert unavailable.value.kind == "SCAN_UNAVAILABLE"
    assert not (tmp_path / "result").exists()


def test_directory_discovery_counts_ignored_entries_and_is_utf8_byte_sorted(
    tmp_path: Path,
) -> None:
    root = tmp_path / "input"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "z.PARQUET").write_bytes(b"z")
    (root / "ignored.txt").write_bytes(b"ignored")
    (nested / "a.parquet").write_bytes(b"a")
    (nested / "é.parquet").write_bytes(b"accent")
    discovery = discover_input(root)
    expected = sorted(
        ("nested/a.parquet", "nested/é.parquet", "z.PARQUET"),
        key=lambda value: value.encode("utf-8"),
    )
    assert tuple(item.relative_path for item in discovery.files) == tuple(expected)
    assert discovery.input_kind == "directory"
    assert (discovery.total_bytes, discovery.visited_entries) == (len(b"zaaccent"), 6)


def test_directory_does_not_follow_symlinks_and_reports_them(tmp_path: Path) -> None:
    root = tmp_path / "input"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "hidden.parquet").write_bytes(b"outside")
    (root / "kept.parquet").write_bytes(b"kept")
    (root / "linked.parquet").symlink_to(outside / "hidden.parquet")
    (root / "linked-directory").symlink_to(outside, target_is_directory=True)
    discovery = discover_input(root)
    assert tuple(item.relative_path for item in discovery.files) == ("kept.parquet",)
    assert (discovery.skipped_symlinks, discovery.visited_entries) == (2, 4)
    assert _failure(discover_input, root / "linked.parquet").kind == "INVALID_INPUT"


def test_empty_and_non_regular_inputs_are_configuration_errors(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _failure(discover_input, empty).kind == "EMPTY_INPUT"
    missing = tmp_path / "missing"
    assert _failure(discover_input, missing).kind == "INVALID_INPUT"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert _failure(discover_input, fifo).kind == "INVALID_INPUT"


def test_fixed_file_count_and_byte_limits_are_enforced_before_snapshot(tmp_path: Path) -> None:
    too_many = tmp_path / "many"
    too_many.mkdir()
    for index in range(MAX_FILES + 1):
        (too_many / f"{index:03}.parquet").write_bytes(b"x")
    assert _failure(discover_input, too_many).kind == "SCAN_LIMIT_EXCEEDED"
    large = tmp_path / "large.parquet"
    with large.open("wb") as stream:
        stream.truncate(MAX_FILE_BYTES + 1)
    assert _failure(discover_input, large).kind == "SCAN_LIMIT_EXCEEDED"
    total = tmp_path / "total"
    total.mkdir()
    for index in range(MAX_SOURCE_BYTES // MAX_FILE_BYTES + 1):
        path = total / f"{index}.parquet"
        with path.open("wb") as stream:
            stream.truncate(MAX_FILE_BYTES)
    assert _failure(discover_input, total).kind == "SCAN_LIMIT_EXCEEDED"


class _Entry:
    def __init__(self, index: int, status: os.stat_result, calls: list[int]) -> None:
        self.name = f"{index}.txt"
        self.path = f"ignored/{self.name}"
        self._index = index
        self._status = status
        self._calls = calls

    def stat(self, *, follow_symlinks: bool) -> os.stat_result:
        assert follow_symlinks is False
        self._calls[self._index] += 1
        return self._status


class _EntryStream:
    def __init__(self, entries: tuple[_Entry, ...]) -> None:
        self._entries = entries

    def __enter__(self) -> "_EntryStream":
        return self

    def __exit__(self, *errors: object) -> None:
        del errors

    def __iter__(self) -> Iterator[_Entry]:
        return iter(self._entries)


def test_total_visited_entry_bound_precedes_additional_metadata_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "input"
    root.mkdir()
    sample = tmp_path / "sample"
    sample.write_text("ignored")
    calls = [0] * MAX_VISITED_ENTRIES
    status = sample.lstat()
    entries = tuple(_Entry(index, status, calls) for index in range(len(calls)))

    def controlled_scandir(_: Path) -> _EntryStream:
        return _EntryStream(entries)

    monkeypatch.setattr(discovery_module.os, "scandir", controlled_scandir)
    exhausted = _failure(discover_input, root)
    assert exhausted.kind == "SCAN_LIMIT_EXCEEDED"
    assert "4,096-entry limit" in exhausted.detail
    assert (sum(calls), set(calls)) == (MAX_VISITED_ENTRIES - 1, {0, 1})


def test_snapshot_refuses_source_drift(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "source.parquet"
    source.write_bytes(b"before")
    item = discover_input(source).files[0]
    source.write_bytes(b"after-change")
    assert _failure(snapshot_file, item, tmp_path / "private").kind == "INPUT_DRIFT"

    source.write_bytes(b"original")
    replaced = discover_input(source).files[0]
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"distinct")
    replacement.replace(source)
    assert _failure(snapshot_file, replaced, tmp_path / "distinct").kind == "INPUT_DRIFT"

    source.write_bytes(b"original")
    linked = discover_input(source).files[0]
    target = tmp_path / "target"
    target.write_bytes(b"original")
    source.unlink()
    source.symlink_to(target)
    assert _failure(snapshot_file, linked, tmp_path / "symlink").kind == "INPUT_DRIFT"

    source.unlink()
    source.write_bytes(b"original")
    unavailable = discover_input(source).files[0]
    with monkeypatch.context() as patch:
        patch.delattr(discovery_module.os, "O_NOFOLLOW")
        assert _failure(snapshot_file, unavailable, tmp_path / "missing-primitive").kind == (
            "SCAN_UNAVAILABLE"
        )

    def unsupported_open(path: Path, flags: int) -> int:
        del path, flags
        raise OSError(discovery_module.errno.ENOTSUP, "unsupported")

    monkeypatch.setattr(discovery_module.os, "open", unsupported_open)
    assert _failure(snapshot_file, unavailable, tmp_path / "unsupported").kind == "SCAN_UNAVAILABLE"


def test_snapshot_distinguishes_source_reads_from_target_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "source.parquet"
    source.write_bytes(b"source bytes")
    item = discover_input(source).files[0]
    source_handle = MagicMock()
    source_handle.__enter__.return_value.read.side_effect = OSError("controlled source failure")
    with monkeypatch.context() as patch:
        patch.setattr(discovery_module.os, "fdopen", Mock(return_value=source_handle))
        source_failure = _failure(snapshot_file, item, tmp_path / "source-failure")
    assert source_failure.kind == "INPUT_DRIFT"
    target_handle, target_open = MagicMock(), Mock(return_value=MagicMock())
    target_open.return_value = target_handle
    target_handle.__enter__.return_value.write.side_effect = OSError(
        discovery_module.errno.EIO, "target failure"
    )
    with monkeypatch.context() as patch:
        patch.setattr(type(source), "open", target_open)
        target_failure = _failure(snapshot_file, item, tmp_path / "target-write")
    assert target_failure.kind == "OUTPUT_ERROR"
