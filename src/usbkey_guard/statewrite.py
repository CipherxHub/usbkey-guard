r"""Durable state writes with an actionable message when permissions block them.

State files (vaults.json, config.json, journal/state.json) hold registration
bookkeeping only - never key material - but they live under %PROGRAMDATA% and
are usually written by the SYSTEM enforcer or an elevated installer. Windows
then grants BUILTIN\Users read-only on those files, so a normal desktop session
could not replace them and every vault action failed with WinError 5.
"""
import os
from pathlib import Path
from typing import Any, Callable

from .errors import PermissionProblem

REMEDY = (
    "The state folder is not writable by this account. Run this once from an "
    "Administrator prompt:  usbkey-setup repair-permissions"
)


def discard(tmp: Path) -> None:
    """Remove a half-written temp file; never raises."""
    try:
        os.unlink(tmp)
    except OSError:
        pass


def permission_error(path: Path, exc: OSError) -> PermissionProblem:
    return PermissionProblem(f"cannot update {path}: access denied. {REMEDY}")


def save(path: Path, payload: dict[str, Any],
         writer: Callable[[Path, dict[str, Any]], None]) -> None:
    """Write `payload` through `writer` to a temp file, then replace `path`.

    Any permission failure becomes a PermissionProblem carrying the remedy,
    and the temp file is removed so no stale `.tmp` is left behind.
    """
    tmp = path.with_name(path.name + ".tmp")
    try:
        writer(tmp, payload)
        os.replace(tmp, path)
    except PermissionError as exc:
        discard(tmp)
        raise permission_error(path, exc) from exc
