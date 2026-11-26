r"""Path safety: denylist, filesystem and reparse validation. Read-only."""
import ntpath
import os
import stat
from pathlib import Path

import win32api
import win32con
import win32file

from . import config

STATE_ROOT = config.STATE_ROOT

_CLOUD_NAMES = {
    "onedrive", "onedrivedesktop", "dropbox", "google drive",
    "google drive file stream", "iclouddrive", "megasync", "synology drive",
}
_RECALL_ON_DATA_ACCESS = 0x00400000
_OFFLINE = 0x00001000
_REPARSE = stat.FILE_ATTRIBUTE_REPARSE_POINT


def norm(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(ntpath.normpath(str(path))))


def is_under(path: str | Path, parent: str | Path) -> bool:
    p, q = norm(path), norm(parent)
    return p == q or p.startswith(q.rstrip("\\") + "\\")


def ensure_state_tree() -> None:
    for sub in ("journal", "acl-backup", "logs", "tmp", "recovery", "vault-backup"):
        (STATE_ROOT / sub).mkdir(parents=True, exist_ok=True)


def _drive_root(path: str | Path) -> str:
    return ntpath.splitdrive(str(path))[0] + "\\"


def drive_roots() -> list[str]:
    raw = win32api.GetLogicalDriveStrings()
    return [d for d in raw.split("\x00") if d]


def filesystem_of(path: str | Path) -> str:
    try:
        return win32api.GetVolumeInformation(_drive_root(str(path)))[4]
    except Exception:
        return ""


def is_ntfs(path: str | Path) -> bool:
    return filesystem_of(path).upper() == "NTFS"


def is_removable(path: str | Path) -> bool:
    try:
        return win32file.GetDriveType(_drive_root(str(path))) == win32con.DRIVE_REMOVABLE
    except Exception:
        return True


def components(path: str | Path) -> list[str]:
    p = Path(str(path))
    parts = [str(parent) for parent in p.parents]
    parts.append(str(p))
    return parts


def reparse_components(path: str | Path) -> list[str]:
    found = []
    for component in components(path):
        try:
            attrs = os.lstat(component).st_file_attributes
        except (OSError, AttributeError):
            continue
        if attrs & _REPARSE:
            found.append(component)
    return found


def cloud_markers(path: str | Path) -> list[str]:
    found = []
    for component in components(path):
        if os.path.basename(component).lower() in _CLOUD_NAMES:
            found.append(component)
    if not os.path.isdir(str(path)):
        try:
            attrs = os.lstat(str(path)).st_file_attributes
            if attrs & (_RECALL_ON_DATA_ACCESS | _OFFLINE):
                found.append(str(path))
        except (OSError, AttributeError):
            pass
    return found


_STATE_SUBDIRS = ("journal", "acl-backup", "logs", "tmp", "recovery", "vault-backup")
_HIVE_NAMES = ("ntuser.dat", "ntuser.ini", "ntuser.dat.log1", "ntuser.dat.log2")


def _system_prefixes() -> list[str]:
    """OS-owned trees that must never be encrypted, locked or deleted."""
    candidates = [
        os.environ.get("WINDIR", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
    ]
    return sorted({os.path.normcase(str(p)) for p in candidates if p})


def protected_prefixes() -> list[str]:
    """Directories the tool must never protect, derived from this machine."""
    candidates = list(_system_prefixes()) + [
        os.environ.get("USERPROFILE", r"C:\Users"),
        str(config.STATE_ROOT),
        str(config.INSTALL_ROOT),
        str(config.PACKAGE_ROOT),
    ]
    return sorted({os.path.normcase(str(p)) for p in candidates if p})


def _tool_tree_hits(p: str) -> list[str]:
    """Refuse the tool's own state/install trees, but not every sibling folder."""
    hits: list[str] = []
    for root, subdirs_only in (
        (config.STATE_ROOT, True),
        (config.INSTALL_ROOT, False),
        (config.PACKAGE_ROOT, False),
    ):
        root_n = norm(root)
        if p == root_n:
            hits.append(str(root))
        elif subdirs_only:
            for sub in _STATE_SUBDIRS:
                candidate = Path(root) / sub
                if is_under(p, candidate):
                    hits.append(str(candidate))
        elif is_under(p, root_n):
            hits.append(str(root))
    return hits


def _system_hits(p: str) -> list[str]:
    hits = [prefix for prefix in _system_prefixes() if is_under(p, prefix)]
    hits += _tool_tree_hits(p)
    for marker in (r"\System Volume Information", r"\$Recycle.Bin"):
        if marker.lower() in p.lower():
            hits.append(marker)
    return hits


def nearest_existing(path: str | Path) -> str:
    """Closest ancestor that exists, for validating not-yet-created destinations."""
    p = Path(str(path))
    while True:
        if p.exists() or p.parent == p:
            return str(p)
        p = p.parent


def denylist_hits(path: str | Path, allow_dummy: bool = False) -> list[str]:
    """`allow_dummy` is kept for API compatibility and is ignored."""
    p = norm(path)
    hits = []
    for root in drive_roots():
        if p == norm(root):
            hits.append(root)
    for prefix in protected_prefixes():
        if is_under(p, prefix):
            hits.append(prefix)
    for marker in (r"\System Volume Information", r"\$Recycle.Bin"):
        if marker.lower() in p.lower():
            hits.append(marker)
    return hits


def safe_target(path: str | Path, allow_dummy: bool = False) -> None:
    """Raise ValueError with a reason if a path must never be protected."""
    p = norm(path)
    if not os.path.exists(p):
        raise ValueError("path does not exist")
    if os.path.isdir(p) and ntpath.splitdrive(p)[1] == "\\":
        raise ValueError("drive roots are forbidden")
    hits = denylist_hits(p)
    if hits:
        raise ValueError("protected system path: " + ", ".join(sorted(set(hits))))
    if not is_ntfs(p):
        raise ValueError("NTFS required; filesystem is " + (filesystem_of(p) or "unknown"))
    if is_removable(p):
        raise ValueError("removable volumes are forbidden")
    rp = reparse_components(p)
    if rp:
        raise ValueError("reparse point in path chain: " + ", ".join(rp))
    cloud = cloud_markers(p)
    if cloud:
        raise ValueError("cloud-sync path: " + ", ".join(cloud))
    if len(p) > 240:
        raise ValueError("path too long for reliable Win32 API use")


def _check_volume(p: str, what: str) -> None:
    if not is_ntfs(p):
        raise ValueError(what + ": NTFS required; filesystem is "
                         + (filesystem_of(p) or "unknown"))
    if is_removable(p):
        raise ValueError(what + ": removable volumes are forbidden")
    rp = reparse_components(p)
    if rp:
        raise ValueError(what + ": reparse point in path chain: " + ", ".join(rp))
    cloud = cloud_markers(p)
    if cloud:
        raise ValueError(what + ": cloud-sync path: " + ", ".join(cloud))
    if len(p) > 240:
        raise ValueError(what + ": path too long for reliable Win32 API use")


def safe_vault_source(path: str | Path) -> None:
    """Validate a path whose plaintext will be encrypted and then deleted.

    Deliberately more permissive than `safe_target`: a user's own Documents
    folder is a legitimate thing to encrypt. Only OS-owned trees, the profile
    root itself, registry hives and the tool's own state are refused.
    """
    p = norm(path)
    if not os.path.exists(p):
        raise ValueError("path does not exist")
    if os.path.isdir(p) and ntpath.splitdrive(p)[1] == "\\":
        raise ValueError("drive roots are forbidden")
    hits = _system_hits(p)
    home = norm(os.environ.get("USERPROFILE", ""))
    if home and p == home:
        hits.append("user profile root")
    if home:
        users_root = norm(ntpath.dirname(home))
        if p == users_root:
            hits.append("all user profiles")
    if os.path.basename(p).lower() in _HIVE_NAMES:
        hits.append("registry hive")
    if hits:
        raise ValueError("protected system path: " + ", ".join(sorted(set(hits))))
    _check_volume(p, "source")


def safe_vault_dest(path: str | Path, source: str | Path,
                    source_is_dir: bool) -> None:
    """Validate where ciphertext will be written. Never inside the source."""
    p = norm(path)
    s = norm(source)
    if (is_under(p, s) if source_is_dir else p == s) or is_under(s, p):
        raise ValueError("vault folder must not overlap the data being encrypted")
    anchor = nearest_existing(p)
    hits = _system_hits(anchor)
    # The destination may not exist yet, so also check it textually: a vault
    # must never be created inside the tool's own state tree.
    for extra in _tool_tree_hits(p):
        if extra not in hits:
            hits.append(extra)
    if hits:
        raise ValueError("protected system path: " + ", ".join(sorted(set(hits))))
    _check_volume(anchor, "vault destination")


def safe_vault_workdir(path: str | Path) -> None:
    """Validate a manifest-supplied folder that plaintext will be written into.

    A vault folder can be handed to `attach` by anyone, and its manifest is not
    authenticated for `work_dir`, so this is checked on every unlock/lock.
    """
    p = norm(path)
    if ntpath.splitdrive(p)[1] == "\\":
        raise ValueError("drive roots are forbidden as a vault work folder")
    hits = _system_hits(p)
    if hits:
        raise ValueError("protected system path: " + ", ".join(sorted(set(hits))))
    _check_volume(nearest_existing(p), "vault work folder")
