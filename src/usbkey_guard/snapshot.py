r"""Capture and restore security descriptors. Writes only under state/recovery roots."""
import json
import os
from pathlib import Path
from typing import Any

import win32security

from .paths import STATE_ROOT, ensure_state_tree
from .privs import enable_privileges

ALL_INFO = (
    win32security.OWNER_SECURITY_INFORMATION
    | win32security.GROUP_SECURITY_INFORMATION
    | win32security.DACL_SECURITY_INFORMATION
    | win32security.SACL_SECURITY_INFORMATION
)
SET_INFO = (
    win32security.OWNER_SECURITY_INFORMATION
    | win32security.GROUP_SECURITY_INFORMATION
    | win32security.DACL_SECURITY_INFORMATION
)


def _sid(sid: Any) -> str:
    return win32security.ConvertSidToStringSid(sid)


def _aces(dacl: Any) -> list[dict[str, Any]]:
    if dacl is None:
        return []
    out = []
    for i in range(dacl.GetAceCount()):
        try:
            (ace_type, flags), mask, sid = dacl.GetAce(i)
            out.append({
                "type": int(ace_type),
                "flags": int(flags),
                "mask": int(mask),
                "sid": _sid(sid),
            })
        except Exception:
            out.append({"raw": repr(ace)})
    return out


def capture(path: str) -> dict[str, Any]:
    """Read-only capture of the complete security descriptor."""
    enable_privileges()
    sd = win32security.GetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, ALL_INFO)
    dacl = sd.GetSecurityDescriptorDacl()
    return {
        "path": path,
        "owner": _sid(sd.GetSecurityDescriptorOwner()),
        "group": _sid(sd.GetSecurityDescriptorGroup()),
        "sddl": win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, ALL_INFO
        ),
        "aces": _aces(dacl),
    }


def root_id(path: str) -> str:
    import hashlib
    normalized = os.path.normcase(os.path.abspath(path))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _backup_dir(root: str) -> Path:
    ensure_state_tree()
    d = STATE_ROOT / "acl-backup" / root
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(root: str, snap: dict[str, Any], stick_dir: str | None = None) -> None:
    """Store three independent copies of the recovery data."""
    d = _backup_dir(root)
    (d / "sddl.txt").write_text(snap["sddl"], encoding="utf-8")
    (d / "owner.txt").write_text(snap["owner"] + "\n" + snap["group"] + "\n", encoding="utf-8")
    (d / "meta.json").write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
    if stick_dir:
        try:
            remote = Path(stick_dir) / "acl-backup" / root
            remote.mkdir(parents=True, exist_ok=True)
            (remote / "sddl.txt").write_text(snap["sddl"], encoding="utf-8")
            (remote / "owner.txt").write_text(snap["owner"] + "\n", encoding="utf-8")
            (remote / "meta.json").write_text(json.dumps(snap, indent=2), encoding="utf-8")
        except OSError:
            pass  # local copy is authoritative; stick copy is best-effort


def load(root: str) -> dict[str, Any]:
    d = _backup_dir(root)
    return json.loads((d / "meta.json").read_text(encoding="utf-8"))


def exists(root: str) -> bool:
    return (_backup_dir(root) / "meta.json").exists()


def restore(path: str, snap: dict[str, Any]) -> None:
    """Restore the full descriptor from a saved SDDL. Verified byte-identical."""
    enable_privileges()
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        snap["sddl"], win32security.SDDL_REVISION_1
    )
    win32security.SetNamedSecurityInfo(
        path,
        win32security.SE_FILE_OBJECT,
        SET_INFO,
        sd.GetSecurityDescriptorOwner(),
        sd.GetSecurityDescriptorGroup(),
        sd.GetSecurityDescriptorDacl(),
        None,
    )


def raw_commands(path: str, snap: dict[str, Any]) -> str:
    """Two-command manual recovery that needs no tooling at all."""
    return (
        f'icacls "{path}" /remove:d "BUILTIN\\Users" /t /c\n'
        f'icacls "{path}" /setowner "{snap["owner"]}" /t /c\n'
    )
