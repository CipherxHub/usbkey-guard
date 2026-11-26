r"""Orchestration: manifest, named mutex, lock/unlock, journal replay, verification."""
import contextlib
import json
import os
import time
from typing import Any, Iterator

import pywintypes
import win32event
import win32api
import winerror

from . import acl, journal, paths, snapshot, statewrite
from .errors import ConfigCorrupt, JournalUnreconciled, MutexHeld, VerifyDrift
from .log import get_log

_log = get_log("enforce")
CONFIG = paths.STATE_ROOT / "config.json"
MUTEX_NAME = "Global\\usbkey-enforcer"
MONITOR_MUTEX_NAME = "Global\\usbkey-monitor"
_monitor_mutex = None
DEFAULT_SETTINGS = {"grace_seconds": 3, "shutdown_grace_seconds": 15}


def _corrupt_message(exc: Exception) -> str:
    import time
    saved = None
    try:
        saved = CONFIG.with_name(CONFIG.name + ".corrupt-" + time.strftime("%Y%m%d-%H%M%S"))
        saved.write_bytes(CONFIG.read_bytes())
    except OSError:
        saved = None
    tail = f" A copy was saved to {saved}." if saved else ""
    return (
        f"state file is corrupt: {CONFIG} ({exc}).{tail} "
        "Nothing was deleted. Restore a good copy before running any command."
    )


def load_config() -> dict[str, Any]:
    paths.ensure_state_tree()
    if not CONFIG.exists():
        return {"roots": [], "settings": dict(DEFAULT_SETTINGS)}
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigCorrupt(_corrupt_message(exc)) from exc
    if not isinstance(cfg, dict):
        raise ConfigCorrupt(_corrupt_message(ValueError("unexpected structure")))
    cfg.setdefault("roots", [])
    if not isinstance(cfg["roots"], list):
        raise ConfigCorrupt(_corrupt_message(ValueError("roots is not a list")))
    settings = dict(DEFAULT_SETTINGS)
    settings.update(cfg.get("settings") or {})
    cfg["settings"] = settings
    return cfg


def _write_json_durable(path, payload: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def save_config(cfg: dict[str, Any]) -> None:
    statewrite.save(CONFIG, cfg, _write_json_durable)


@contextlib.contextmanager
def single_instance(timeout_ms: int = 2000) -> Iterator[None]:
    try:
        mutex = win32event.CreateMutex(None, True, MUTEX_NAME)
    except pywintypes.error as exc:
        # A SYSTEM-owned mutex has a DACL a desktop user cannot open. That is
        # the service working, not a reason to crash the command.
        if getattr(exc, "winerror", None) == winerror.ERROR_ACCESS_DENIED:
            raise MutexHeld("another enforcer instance holds the mutex") from exc
        raise
    last = win32api.GetLastError()
    if last == winerror.ERROR_ALREADY_EXISTS:
        mutex.Close()
        raise MutexHeld("another enforcer instance holds the mutex")
    try:
        yield
    finally:
        win32event.ReleaseMutex(mutex)
        mutex.Close()


def claim_monitor() -> bool:
    """Take the process-lifetime monitor slot; False when one already runs.

    The per-operation mutex above serialises lock/unlock, but it does not stop a
    second monitor (for example one left behind after the task was recreated)
    from cycling alongside the first. This handle is held until the process
    exits, and Windows releases it automatically.
    """
    global _monitor_mutex
    try:
        mutex = win32event.CreateMutex(None, True, MONITOR_MUTEX_NAME)
    except pywintypes.error as exc:
        # Access denied means the SYSTEM service owns it: a monitor is running.
        return getattr(exc, "winerror", None) != winerror.ERROR_ACCESS_DENIED
    except Exception:
        return True  # cannot create it: do not block the service
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        mutex.Close()
        return False
    _monitor_mutex = mutex
    return True


def add_root(path: str, allow_dummy: bool = False) -> dict[str, Any]:
    from .audit import audit

    report = audit(path, allow_dummy=allow_dummy)
    if not report["passed"]:
        raise ValueError("; ".join(report["refusals"]))
    rid = snapshot.root_id(path)
    cfg = load_config()
    if any(r["id"] == rid for r in cfg["roots"]):
        raise ValueError("root already protected: " + path)
    snap = snapshot.capture(path)
    stick_dir = None
    try:
        from . import keystore
        stick_dir = keystore.find_key(load_config().get("identity") or {})
    except Exception:
        pass
    snapshot.save(rid, snap, stick_dir)
    cfg["roots"].append({
        "id": rid,
        "path": path,
        "locked": acl.is_locked(path),
        "added_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit": report,
    })
    save_config(cfg)
    _log.info("added root %s (%s)", path, rid)
    return cfg["roots"][-1]


def remove_root(key: str) -> None:
    """Remove a root by id or by path; refuses while it is still locked."""
    cfg = load_config()
    key_norm = paths.norm(key)
    root = next(
        (r for r in cfg["roots"]
         if r.get("id") == key or paths.norm(r.get("path", "")) == key_norm),
        None,
    )
    if root is None:
        raise ValueError("no protected root matches: " + str(key))
    if root.get("locked") or acl.is_locked(root["path"]):
        raise ValueError(
            "refusing to remove a locked root; unlock it first: " + root["path"]
        )
    cfg["roots"] = [r for r in cfg["roots"] if r.get("id") != root["id"]]
    save_config(cfg)


def lock_all(dry_run: bool = False) -> list[str]:
    cfg = load_config()
    j = journal.Journal()
    changed = []
    with single_instance():
        for root in cfg["roots"]:
            path, rid = root["path"], root["id"]
            try:
                if root.get("locked") and acl.is_locked(path):
                    continue
                pre = snapshot.capture(path)
                if dry_run:
                    acl.apply_lock(path, pre, dry_run=True)
                    changed.append("DRY-RUN " + path)
                    continue
                snapshot.save(rid, pre)
                intent = j.intent("lock", rid, path, pre, {
                    "set_owner": acl.SYSTEM_SID, "add_deny": acl.USERS_SID,
                })
                acl.apply_lock(path, pre)
                post = snapshot.capture(path)
                j.done(intent["rid"], post)
                root["locked"] = True
                save_config(cfg)
                changed.append("LOCKED " + path)
            except Exception as exc:
                # One bad root must never stop the rest from locking.
                _log.exception("lock failed for %s", path)
                changed.append(f"FAILED {path}: {exc}")
    return changed


def unlock_all(dry_run: bool = False, force: bool = False,
               stick_dir: str | None = None) -> list[str]:
    cfg = load_config()
    j = journal.Journal()
    changed = []
    with single_instance():
        for root in cfg["roots"]:
            path, rid = root["path"], root["id"]
            try:
                if not root.get("locked") and not acl.is_locked(path):
                    continue
                try:
                    snap = snapshot.load(rid)
                except (OSError, ValueError):
                    snap = snapshot.capture(path)
                if dry_run:
                    acl.apply_unlock(path, snap, dry_run=True)
                    changed.append("DRY-RUN " + path)
                    continue
                # While the stick is present, keep the second recovery copy current.
                snapshot.save(rid, snap, stick_dir)
                intent = j.intent("unlock", rid, path, {"owner": snap["owner"]}, {
                    "remove_deny": acl.USERS_SID, "restore_sddl": True,
                })
                acl.apply_unlock(path, snap)
                post = snapshot.capture(path)
                j.done(intent["rid"], post)
                if not acl.matches_snapshot(path, snap):
                    _log.error("permission drift after unlock: %s", path)
                    raise VerifyDrift("unlock did not restore the snapshot for " + path)
                # Windows auto-inheritance may add an extra owner ACE. Adopt the
                # verified post-state as the new baseline for future cycles.
                snapshot.save(rid, post, stick_dir)
                root["locked"] = False
                save_config(cfg)
                changed.append("UNLOCKED " + path)
            except Exception as exc:
                _log.exception("unlock failed for %s", path)
                changed.append(f"FAILED {path}: {exc}")
    return changed


def replay() -> list[str]:
    """Reconcile every intent record without a matching done/reconciled record."""
    j = journal.Journal()
    pending = j.unreconciled()
    notes = []
    cfg = load_config()
    config_dirty = False

    def set_cfg_locked(root_id: str, value: bool) -> None:
        nonlocal config_dirty
        for root in cfg["roots"]:
            if root["id"] == root_id and bool(root.get("locked")) != value:
                root["locked"] = value
                config_dirty = True

    with single_instance():
        for intent in pending:
            rid, path, op = intent.get("root"), intent.get("path"), intent.get("op")
            try:
                locked_now = acl.is_locked(path)
                if op == "lock":
                    if locked_now:
                        j.done(intent["rid"], snapshot.capture(path))
                        set_cfg_locked(rid, True)
                        notes.append(f"lock completed: {path}")
                    elif snapshot.exists(rid):
                        acl.apply_lock(path, snapshot.load(rid))
                        j.done(intent["rid"], snapshot.capture(path))
                        set_cfg_locked(rid, True)
                        notes.append(f"lock rolled forward: {path}")
                    else:
                        j.reconciled(intent["rid"], "no snapshot; no mutation applied")
                        set_cfg_locked(rid, False)
                        notes.append(f"lock skipped (no snapshot): {path}")
                elif op == "unlock":
                    if snapshot.exists(rid):
                        acl.apply_unlock(path, snapshot.load(rid))
                        j.done(intent["rid"], snapshot.capture(path))
                        set_cfg_locked(rid, False)
                        notes.append(f"unlock rolled forward: {path}")
                    elif not locked_now:
                        j.reconciled(intent["rid"], "already unlocked")
                        set_cfg_locked(rid, False)
                        notes.append(f"unlock already effective: {path}")
                    else:
                        raise JournalUnreconciled(
                            f"cannot safely unlock {path}: snapshot missing. "
                            "Use the manual recovery runbook."
                        )
                else:
                    j.reconciled(intent["rid"], "unknown op")
            except JournalUnreconciled:
                raise
            except Exception as exc:
                raise JournalUnreconciled(f"replay failed for {path}: {exc}") from exc
    if config_dirty:
        save_config(cfg)
    for note in notes:
        _log.info("replay: %s", note)
    return notes


def verify() -> list[str]:
    cfg = load_config()
    problems = []
    for root in cfg["roots"]:
        path, rid = root["path"], root["id"]
        expected = bool(root.get("locked"))
        actual = acl.is_locked(path)
        if expected != actual:
            problems.append(f"{path}: expected locked={expected}, actual={actual}")
        if not expected and snapshot.exists(rid):
            try:
                snap = snapshot.load(rid)
            except (OSError, ValueError) as exc:
                problems.append(f"{path}: snapshot unreadable: {exc}")
            else:
                if not acl.matches_snapshot(path, snap):
                    problems.append(f"{path}: permissions drifted from snapshot")
    if journal.Journal().unreconciled():
        problems.append("journal has unreconciled intents; run `journal replay`")
    return problems
