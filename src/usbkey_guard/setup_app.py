r"""All-users install: Program Files copy, Start menu entry, SYSTEM task.

The scheduled task and the Start menu launcher both run bootstrap scripts that
live in the install folder, so the installed copy is what actually executes
even when pip's site-packages is per-user.
"""
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import acl, config, paths

ENFORCER_BOOTSTRAP = "run_enforcer.py"
TUI_BOOTSTRAP = "run_tui.py"

_ENFORCER_SOURCE = """\
import sys
sys.path.insert(0, {install!r})
from usbkey_guard.cli import main
sys.exit(main(["monitor"]))
"""

_TUI_SOURCE = """\
import sys
sys.path.insert(0, {install!r})
from usbkey_guard.tui import main
sys.exit(main())
"""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def start_menu_dir() -> Path:
    """All-users Start menu, not the installing administrator's profile."""
    root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    return root / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "usbkey"


def pythonw() -> Path:
    return Path(sys.executable).with_name("pythonw.exe")


def python_console() -> Path:
    return Path(sys.executable).with_name("python.exe")


def task_command() -> str:
    script = Path(config.INSTALL_ROOT) / ENFORCER_BOOTSTRAP
    return f'"{pythonw()}" "{script}"'


def _assert_own_install_root(path: Path) -> None:
    resolved = Path(path).resolve()
    if resolved.name.lower() != config.APP_NAME.lower():
        raise RuntimeError(f"refusing to remove unexpected folder: {resolved}")
    if len(resolved.parts) < 3:
        raise RuntimeError(f"refusing to remove shallow folder: {resolved}")


def _write_bootstrap(name: str, source: str) -> None:
    (Path(config.INSTALL_ROOT) / name).write_text(source, encoding="utf-8")


def harden_state() -> bool:
    """Create the state tree as this admin and restrict it to admins + owner."""
    if os.environ.get("USBKEY_SKIP_HARDEN") == "1":
        print("State hardening skipped (USBKEY_SKIP_HARDEN=1).")
        return False
    paths.ensure_state_tree()
    ok = acl.harden_state_root(str(config.STATE_ROOT))
    print("State folder hardened:", config.STATE_ROOT if ok else "FAILED (left unchanged)")
    return ok


def install() -> int:
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    source = Path(config.PACKAGE_ROOT).resolve()
    dest = Path(config.INSTALL_ROOT).resolve()
    # The bootstrap puts `dest` on sys.path, so the package itself must live in
    # `dest\usbkey_guard` -- copying its contents directly into `dest` would
    # make `import usbkey_guard` fail for the SYSTEM task.
    pkg_dest = dest / "usbkey_guard"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        if source == pkg_dest:
            print("Package already lives in", pkg_dest)
        else:
            shutil.copytree(source, pkg_dest, dirs_exist_ok=True)
            print("Files installed to", pkg_dest)
        _write_bootstrap(ENFORCER_BOOTSTRAP, _ENFORCER_SOURCE.format(install=str(dest)))
        _write_bootstrap(TUI_BOOTSTRAP, _TUI_SOURCE.format(install=str(dest)))
    except OSError as exc:
        print("ERROR copying files:", exc)
        return 1

    menu = start_menu_dir()
    menu.mkdir(parents=True, exist_ok=True)
    launcher = menu / "usbkey TUI.bat"
    script = dest / TUI_BOOTSTRAP
    launcher.write_text(
        "@echo off\r\n"
        "title usbkey\r\n"
        f'if exist "{python_console()}" (\r\n'
        f'  "{python_console()}" "{script}"\r\n'
        "  goto end\r\n"
        ")\r\n"
        "where py >nul 2>nul\r\n"
        "if %errorlevel%==0 (\r\n"
        f'  py "{script}"\r\n'
        "  goto end\r\n"
        ")\r\n"
        f'python "{script}"\r\n'
        ":end\r\n"
        "pause\r\n",
        encoding="utf-8",
    )
    print("Start menu entry (all users):", launcher)
    print("Optional: `usbkey-setup harden` restricts the state folder to admins")
    print("(non-admin users then cannot create new vaults).")

    result = subprocess.run(
        ["schtasks", "/create", "/tn", config.TASK_NAME, "/tr", task_command(),
         "/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"],
        capture_output=True, text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


def uninstall() -> int:
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    subprocess.run(["schtasks", "/delete", "/tn", config.TASK_NAME, "/f"],
                   capture_output=True, text=True)
    print("Scheduled task removed.")
    menu = start_menu_dir()
    if menu.exists():
        _assert_own_install_root(menu)
        shutil.rmtree(menu)
        print("Start menu entry removed.")
    if config.INSTALL_ROOT.exists():
        _assert_own_install_root(config.INSTALL_ROOT)
        shutil.rmtree(config.INSTALL_ROOT)
        print("Program Files copy removed.")
    print("State in", config.STATE_ROOT, "was preserved (encrypted vaults stay safe).")
    return 0


def status() -> int:
    result = subprocess.run(["schtasks", "/query", "/tn", config.TASK_NAME],
                            capture_output=True, text=True)
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="usbkey-setup")
    p.add_argument("action", choices=["install", "uninstall", "status", "harden"])
    args = p.parse_args(argv)
    if args.action == "harden":
        if not is_admin():
            print("ERROR: run this as Administrator.")
            return 1
        return 0 if harden_state() else 1
    return {"install": install, "uninstall": uninstall, "status": status}[args.action]()


if __name__ == "__main__":
    sys.exit(main())
