"""Shared test support."""

from __future__ import annotations

from pathlib import Path


def symlinks_available(root: Path) -> bool:
    """Whether this environment can create a symlink at all.

    Windows refuses without Developer Mode or elevation, reporting
    ``OSError: [WinError 1314] A required privilege is not held by the client``. Probing beats
    checking the platform, so a developer who has enabled it still runs the assertions that a
    symlinked artifact is rejected.
    """
    target = root / "_symlink-probe-target"
    link = root / "_symlink-probe-link"
    try:
        target.write_text("probe", encoding="utf-8")
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        return False
    finally:
        link.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
    return True


__all__ = ["symlinks_available"]
