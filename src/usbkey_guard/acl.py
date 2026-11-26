r"""THE ONLY module that mutates protected filesystem objects.

Two mutations, both reversible:
  1. add one inheritable deny ACE for BUILTIN\Users (S-1-5-32-545)
  2. change owner to NT AUTHORITY\SYSTEM (S-1-5-18)

No content is read or written. No file is created, moved or deleted.
Never deny Everyone or Authenticated Users: SYSTEM belongs to both and would
lose its own recovery path.
"""
from typing import Any

import win32con
import win32security

from . import snapshot
from .log import get_log
from .privs import enable_privileges

USERS_SID = "S-1-5-32-545"
SYSTEM_SID = "S-1-5-18"
DENY_SID = win32security.ConvertStringSidToSid(USERS_SID)
SYSTEM = win32security.ConvertStringSidToSid(SYSTEM_SID)
DENY_MASK = win32con.GENERIC_ALL
INHERIT = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
ACCESS_DENIED = win32security.ACCESS_DENIED_ACE_TYPE

_log = get_log("acl")


def _dacl(path: str) -> Any:
    enable_privileges()
    sd = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    return sd.GetSecurityDescriptorDacl()


def _owner(path: str) -> str:
    enable_privileges()
    sd = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
    )
    return win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())


def _our_deny_indices(dacl: Any) -> list[int]:
    indices = []
    for i in range(dacl.GetAceCount()):
        try:
            (ace_type, flags), mask, sid = dacl.GetAce(i)
        except Exception:
            continue
        if (
            int(ace_type) == ACCESS_DENIED
            and win32security.ConvertSidToStringSid(sid) == USERS_SID
            and int(mask) in (DENY_MASK, 0x001F01FF)
            and (int(flags) & INHERIT) in (0, INHERIT)
        ):
            indices.append(i)
    return indices


def is_locked(path: str) -> bool:
    try:
        if _owner(path) != SYSTEM_SID:
            return False
        return len(_our_deny_indices(_dacl(path))) > 0
    except Exception as exc:
        _log.error("is_locked failed for %s: %s", path, exc)
        return False


def apply_lock(path: str, snap: dict[str, Any], dry_run: bool = False) -> None:
    """Add the deny ACE and set owner to SYSTEM. Idempotent."""
    if dry_run:
        _log.info("DRY-RUN lock %s: add deny %s, owner -> %s", path, USERS_SID, SYSTEM_SID)
        return
    enable_privileges()
    if is_locked(path):
        _log.info("already locked, no-op: %s", path)
        return
    dacl = _dacl(path)
    if not _our_deny_indices(dacl):
        dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION_DS, INHERIT, DENY_MASK, DENY_SID)
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION, None, None, dacl, None,
        )
    if _owner(path) != SYSTEM_SID:
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION, SYSTEM, None, None, None,
        )
    if not is_locked(path):
        raise RuntimeError("lock verification failed for " + path)


def apply_unlock(path: str, snap: dict[str, Any], dry_run: bool = False) -> None:
    """Restore the authoritative snapshot. Idempotent."""
    if dry_run:
        _log.info("DRY-RUN unlock %s: remove deny %s, owner -> %s", path, USERS_SID, snap["owner"])
        return
    enable_privileges()
    if not is_locked(path):
        _log.info("not locked, no-op: %s", path)
        return
    snapshot.restore(path, snap)
    if is_locked(path):
        raise RuntimeError("unlock verification failed for " + path)


def remove_deny_fallback(path: str) -> None:
    """Last-resort surgical removal when a snapshot is unavailable."""
    enable_privileges()
    dacl = _dacl(path)
    for index in reversed(_our_deny_indices(dacl)):
        dacl.DeleteAce(index)
    win32security.SetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION, None, None, dacl, None,
    )


def _ace_key(ace: dict[str, Any]) -> tuple[Any, ...]:
    return (ace.get("type"), ace.get("flags"), ace.get("mask"), ace.get("sid"))


def matches_snapshot(path: str, snap: dict[str, Any]) -> bool:
    """Semantic equivalence: owner restored, no deny ACE, no permission lost.

    Windows may add an explicit owner ACE when ownership is restored, so an
    exact SDDL string comparison is too strict. Extra allow ACEs are tolerated;
    missing ones are not.
    """
    try:
        current = snapshot.capture(path)
        if current["sddl"] == snap["sddl"]:
            return True
        if current["owner"] != snap["owner"]:
            return False
        if _our_deny_indices(_dacl(path)):
            return False
        saved = {_ace_key(a) for a in snap["aces"]}
        now = {_ace_key(a) for a in current["aces"]}
        return saved <= now
    except Exception as exc:
        _log.error("snapshot comparison failed: %s", exc)
        return False
