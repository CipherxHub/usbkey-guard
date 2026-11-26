r"""Process handling. Graceful close first; force kill is a last resort.

The only real data-loss vector in this tool is terminating an app with unsaved
work, so the graceful window is the default and is logged.
"""
import time
from typing import Iterable

import psutil
import win32con
import win32gui
import win32process

from . import paths
from .log import get_log

_log = get_log("procs")


def find_protected_processes(paths_to_match: Iterable[str]) -> list[psutil.Process]:
    roots = [paths.norm(p) for p in paths_to_match]
    found = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            exe = proc.info.get("exe")
            if not exe:
                continue
            normalized = paths.norm(exe)
            if any(normalized.startswith(r + "\\") or normalized == r for r in roots):
                found.append(proc)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
    return found


def _windows_for_pids(pids: set[int]) -> list[int]:
    handles = []
    def collect(hwnd, _):
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid in pids and win32gui.IsWindowVisible(hwnd):
                handles.append(hwnd)
        except Exception:
            pass
        return True
    win32gui.EnumWindows(collect, None)
    return handles


def close_gracefully(procs: list[psutil.Process], timeout_seconds: float) -> list[int]:
    """Send WM_CLOSE, then poll. Returns PIDs that did not exit."""
    pids = {p.pid for p in procs}
    for hwnd in _windows_for_pids(pids):
        try:
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        except Exception as exc:
            _log.warning("WM_CLOSE failed for hwnd %s: %s", hwnd, exc)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        alive = [p.pid for p in procs if p.is_running()]
        if not alive:
            return []
        time.sleep(0.2)
    return [p.pid for p in procs if p.is_running()]


def stop_protected_processes(paths_to_match: Iterable[str], grace_seconds: float) -> dict[str, list[int]]:
    procs = find_protected_processes(paths_to_match)
    if not procs:
        return {"closed": [], "forced": []}
    _log.info("closing %d protected processes gracefully", len(procs))
    remaining = close_gracefully(procs, grace_seconds)
    forced = []
    for proc in procs:
        if proc.pid in remaining:
            try:
                proc.kill()
                forced.append(proc.pid)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
    for pid in forced:
        _log.warning("forced termination of pid %s after grace period", pid)
    return {"closed": [p.pid for p in procs if p.pid not in remaining], "forced": forced}
