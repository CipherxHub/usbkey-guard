r"""Enable the Windows privileges the enforcer needs. Runs as SYSTEM in production."""
import win32api
import win32con
import win32security

from .log import get_log

REQUIRED = (
    "SeTakeOwnershipPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege",
    "SeSecurityPrivilege",
    "SeDebugPrivilege",
)

_log = get_log("privs")
_enabled = False


def enable_privileges() -> list[str]:
    """Return the privileges actually enabled; never raise on individual gaps."""
    global _enabled
    if _enabled:
        return list(REQUIRED)
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
    )
    granted = []
    try:
        pairs = []
        for name in REQUIRED:
            try:
                luid = win32security.LookupPrivilegeValue(None, name)
                pairs.append((luid, win32security.SE_PRIVILEGE_ENABLED))
                granted.append(name)
            except Exception as exc:
                _log.warning("privilege %s unavailable: %s", name, exc)
        if pairs:
            win32security.AdjustTokenPrivileges(token, False, pairs)
    finally:
        token.Close()
    _enabled = True
    _log.info("enabled privileges: %s", ",".join(granted))
    return granted


def is_admin_like() -> bool:
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
