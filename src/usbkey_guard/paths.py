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


def protected_prefixes() -> list[str]:
    """Directories the tool must never protect, derived from this machine."""
    candidates = [
        os.environ.get("WINDIR", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
        os.environ.get("USERPROFILE", r"C:\Users"),
        str(config.STATE_ROOT),
        str(config.INSTALL_ROOT),
        str(config.PACKAGE_ROOT),
    ]
    return sorted({os.path.normcase(str(p)) for p in candidates if p})


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
