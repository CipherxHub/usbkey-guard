r"""Read-only pre-flight analysis. Never mutates anything."""
import os
from typing import Any

import win32security

from . import paths
from .log import get_log

INHERITED_ACE = 0x10
_log = get_log("audit")


def _inheritance_broken(path: str) -> bool:
    try:
        sd = win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return False
        return not any(
            int(dacl.GetAce(i)[0][1]) & INHERITED_ACE
            for i in range(dacl.GetAceCount())
        )
    except Exception as exc:
        _log.warning("could not read ACL of %s: %s", path, exc)
        return False


def audit(path: str, allow_dummy: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": os.path.abspath(path),
        "passed": False,
        "refusals": [],
        "warnings": [],
        "stats": {"entries": 0, "inheritance_broken": 0, "reparse_skipped": 0},
    }
    try:
        paths.safe_target(path, allow_dummy=allow_dummy)
    except ValueError as exc:
        result["refusals"].append(str(exc))
        return result

    sample: list[str] = []
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in list(dirs):
                full = os.path.join(root, name)
                try:
                    if os.lstat(full).st_file_attributes & 0x400:
                        dirs.remove(name)
                        result["stats"]["reparse_skipped"] += 1
                except (OSError, AttributeError):
                    pass
            result["stats"]["entries"] += len(dirs) + len(files)
            for name in dirs[:]:
                full = os.path.join(root, name)
                if _inheritance_broken(full):
                    result["stats"]["inheritance_broken"] += 1
                    if len(sample) < 10:
                        sample.append(full)
            if result["stats"]["entries"] > 100000:
                result["warnings"].append("over 100k entries — verification will be slow")
                break
    if result["stats"]["inheritance_broken"]:
        result["warnings"].append(
            f'{result["stats"]["inheritance_broken"]} descendants have inheritance disabled '
            f"and will NOT be protected: {sample}"
        )
    result["passed"] = not result["refusals"]
    return result


def format_report(report: dict[str, Any]) -> str:
    lines = [f"PATH      : {report['path']}", f"RESULT    : {'PASS' if report['passed'] else 'REFUSED'}"]
    for r in report["refusals"]:
        lines.append(f"REFUSE    : {r}")
    for w in report["warnings"]:
        lines.append(f"WARNING   : {w}")
    lines.append("STATS     : " + ", ".join(f"{k}={v}" for k, v in report["stats"].items()))
    return "\n".join(lines)
