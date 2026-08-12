from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


class DestinationExistsError(FileExistsError):
    pass


class StagingError(OSError):
    pass


def require_destination_absent(destination: Path) -> None:
    try:
        destination.lstat()
    except FileNotFoundError:
        return
    raise DestinationExistsError(destination)


def atomic_publish_directory(source: Path, destination: Path) -> None:
    try:
        source.rename(destination)
    except OSError as error:
        try:
            require_destination_absent(destination)
        except DestinationExistsError as destination_error:
            raise destination_error from error
        raise


def remove_tree(path: Path, *, preserve_active_error: bool = False) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError:
        if not preserve_active_error:
            raise


@contextmanager
def staging_directory(
    destination: Path,
    *,
    suffix: str = "",
    publication_name: str | None = None,
) -> Generator[Path]:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        root = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.parquity{suffix}-",
                dir=destination.parent,
            )
        )
    except OSError as error:
        raise StagingError("publication staging could not be created") from error
    staging = root if publication_name is None else root / publication_name
    try:
        yield staging
    finally:
        try:
            remove_tree(root, preserve_active_error=sys.exc_info()[0] is not None)
        except OSError as error:
            raise StagingError("publication staging could not be removed") from error


__all__ = [
    "DestinationExistsError",
    "StagingError",
    "atomic_publish_directory",
    "remove_tree",
    "require_destination_absent",
    "staging_directory",
]
