from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NamedTuple

from . import windows
from .limits import MAX_FILE_BYTES, MAX_FILES, MAX_SOURCE_BYTES, MAX_VISITED_ENTRIES


class ScanConfigurationError(ValueError):
    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(detail)


class FileIdentity(NamedTuple):
    device: int
    inode: int
    mode: int
    byte_count: int
    modified_ns: int
    changed_ns: int


class DiscoveredFile(NamedTuple):
    source: Path
    relative_path: str
    identity: FileIdentity

    @property
    def byte_count(self) -> int:
        return self.identity.byte_count


class Discovery(NamedTuple):
    files: tuple[DiscoveredFile, ...]
    skipped_symlinks: int
    total_bytes: int
    input_kind: str
    visited_entries: int


class Snapshot(NamedTuple):
    path: Path
    relative_path: str
    byte_count: int
    sha256: str


def discover_input(source: Path) -> Discovery:
    try:
        status = source.lstat()
    except OSError as error:
        raise ScanConfigurationError("INVALID_INPUT", "scan input is not accessible") from error
    mode = status.st_mode
    if stat.S_ISLNK(mode):
        raise ScanConfigurationError("INVALID_INPUT", "scan input must not be a symbolic link")
    if stat.S_ISREG(mode):
        files = (_discovered(source, source.name, status),)
        skipped = 0
        visited = 1
    elif stat.S_ISDIR(mode):
        files, skipped, visited = _directory_files(source)
    else:
        raise ScanConfigurationError(
            "INVALID_INPUT", "scan input must be a regular file or directory"
        )
    if not files:
        raise ScanConfigurationError("EMPTY_INPUT", "scan input contains no Parquet files")
    total = sum(item.byte_count for item in files)
    if total > MAX_SOURCE_BYTES:
        raise _limit("discovered source bytes exceed 512 MiB")
    return Discovery(files, skipped, total, "file" if stat.S_ISREG(mode) else "directory", visited)


def snapshot_file(source: DiscoveredFile, directory: Path) -> Snapshot:
    target = directory / "input.parquet"
    try:
        directory.mkdir(parents=True)
    except OSError as error:
        raise _output() from error
    try:
        descriptor = _open_source(source.source)
        try:
            before = _identity(os.fstat(descriptor))
            if before != source.identity:
                raise _drift()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                copied_digest, copied_bytes = _digest(stream, target)
            after = _identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)
    except ScanConfigurationError:
        raise
    except OSError as error:
        raise _drift() from error
    if before != after or copied_bytes != source.byte_count:
        raise _drift()
    return Snapshot(target, source.relative_path, copied_bytes, copied_digest)


def _directory_files(root: Path) -> tuple[tuple[DiscoveredFile, ...], int, int]:
    found: list[DiscoveredFile] = []
    skipped = 0
    pending = [root]
    visited = 1
    try:
        while pending:
            directory = pending.pop()
            entries: list[tuple[str, Path, os.stat_result]] = []
            with os.scandir(directory) as stream:
                for entry in stream:
                    if visited >= MAX_VISITED_ENTRIES:
                        raise _limit("visited directory entries exceed the 4,096-entry limit")
                    visited += 1
                    entry.name.encode("utf-8")
                    entries.append((entry.name, Path(entry.path), _entry_status(entry)))
            entries.sort(key=lambda item: item[0].encode("utf-8"))
            child_directories: list[Path] = []
            for name, path, status in entries:
                skipped += _classify_entry(name, path, status, root, found, child_directories)
            pending.extend(reversed(child_directories))
    except ScanConfigurationError:
        raise
    except (OSError, UnicodeError) as error:
        raise ScanConfigurationError("INVALID_INPUT", "scan directory could not be read") from error
    ordered = tuple(sorted(found, key=lambda item: item.relative_path.encode("utf-8")))
    return ordered, skipped, visited


def _classify_entry(
    name: str,
    path: Path,
    status: os.stat_result,
    root: Path,
    found: list[DiscoveredFile],
    directories: list[Path],
) -> int:
    if stat.S_ISLNK(status.st_mode):
        return 1
    if stat.S_ISDIR(status.st_mode):
        directories.append(path)
    elif stat.S_ISREG(status.st_mode) and name.casefold().endswith(".parquet"):
        found.append(_discovered(path, path.relative_to(root).as_posix(), status))
        if len(found) > MAX_FILES:
            raise _limit("discovered file count exceeds 256")
    return 0


def _entry_status(entry: os.DirEntry[str]) -> os.stat_result:
    status = entry.stat(follow_symlinks=False)
    if windows.IS_WINDOWS and not status.st_ino:
        # A Windows directory entry carries no file index, so its device and inode read as zero.
        # The snapshot compares this identity against one taken from the open handle, which does
        # carry them, so a directory scan would report drift on every file. Take a real stat, which
        # opens the file to read its index, and keep the two comparable.
        status = os.stat(entry.path, follow_symlinks=False)
    return status


def _discovered(path: Path, relative_path: str, status: os.stat_result) -> DiscoveredFile:
    try:
        relative_path.encode("utf-8")
    except UnicodeError as error:
        raise ScanConfigurationError("INVALID_INPUT", "scan file could not be inspected") from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ScanConfigurationError("INVALID_INPUT", "scan input must contain regular files")
    size = status.st_size
    if not portable_path(relative_path) or size > MAX_FILE_BYTES:
        if size > MAX_FILE_BYTES:
            raise _limit("one source file exceeds 64 MiB")
        raise ScanConfigurationError("INVALID_INPUT", "scan path is not portable UTF-8")
    return DiscoveredFile(path, relative_path, _identity(status))


def _digest(stream: BinaryIO, target: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    try:
        with target.open("xb") as output:
            while True:
                try:
                    chunk = stream.read(1024 * 1024)
                except OSError as error:
                    raise _drift() from error
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_FILE_BYTES:
                    raise _limit("one source file exceeds 64 MiB")
                digest.update(chunk)
                if output.write(chunk) != len(chunk):
                    raise _output()
            output.flush()
    except ScanConfigurationError:
        raise
    except OSError as error:
        raise _output() from error
    return digest.hexdigest(), count


def _open_source(path: Path) -> int:
    if windows.IS_WINDOWS:
        # FILE_FLAG_OPEN_REPARSE_POINT is the same guarantee O_NOFOLLOW gives: the reparse point
        # is opened rather than followed, so the regular-file check below rejects it.
        try:
            return windows.open_without_following(path)
        except OSError as error:
            raise _drift() from error
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    except AttributeError as error:
        raise ScanConfigurationError(
            "SCAN_UNAVAILABLE", "scan input admission requires no-follow file access"
        ) from error
    try:
        return os.open(path, flags)
    except OSError as error:
        unsupported = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}
        if error.errno in unsupported:
            raise ScanConfigurationError(
                "SCAN_UNAVAILABLE", "scan input admission requires no-follow file access"
            ) from error
        raise _drift() from error


def _identity(status: os.stat_result) -> FileIdentity:
    if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
        raise _drift()
    return FileIdentity(
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        # Windows puts the creation time in this field and reports it differently through a path
        # than through an open handle, so comparing the two would fail every admission. What it
        # guards against -- a file substituted between discovery and copy -- is already covered
        # there: st_dev is the volume serial and st_ino the file ID, which together identify the
        # file itself rather than the name it was reached by.
        0 if windows.IS_WINDOWS else status.st_ctime_ns,
    )


def _drift() -> ScanConfigurationError:
    return ScanConfigurationError("INPUT_DRIFT", "source changed while it was copied")


def _limit(detail: str) -> ScanConfigurationError:
    return ScanConfigurationError("SCAN_LIMIT_EXCEEDED", detail)


def _output() -> ScanConfigurationError:
    return ScanConfigurationError("OUTPUT_ERROR", "scan snapshot could not be created")


def portable_path(value: str) -> bool:
    if not value or value == "." or "\0" in value:
        return False
    path = PurePosixPath(value)
    return value == path.as_posix() and not (path.is_absolute() or ".." in path.parts)
