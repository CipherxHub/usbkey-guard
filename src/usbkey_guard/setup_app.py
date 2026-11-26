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
import time
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


def interpreter_is_shared() -> bool:
    """True when the running Python is usable by every account on this PC.

    The Start menu launcher embeds this path, so a Python under
    `C:\\Users\\<name>` works for that one account (and for SYSTEM) but gives
    other users "Access is denied".
    """
    try:
        exe = Path(sys.executable).resolve()
        profiles = Path.home().parent
        return not exe.is_relative_to(profiles)
    except (OSError, ValueError):
        return True


def _task_running() -> bool:
    query = subprocess.run(["schtasks", "/query", "/tn", config.TASK_NAME, "/fo", "LIST"],
                           capture_output=True, text=True)
    return query.returncode == 0 and "Running" in query.stdout


def _start_service() -> int:
    """Start the task now: an onstart task otherwise does nothing until reboot."""
    if _task_running():
        print("Background service already running:", config.TASK_NAME)
        return 0
    started = subprocess.run(["schtasks", "/run", "/tn", config.TASK_NAME],
                             capture_output=True, text=True)
    if started.returncode != 0:
        print("WARNING: could not start the service:",
              (started.stdout or started.stderr).strip())
        print("It will start at the next boot.")
        return 0
    time.sleep(2)
    if _task_running():
        print("Background service running:", config.TASK_NAME)
        return 0
    print("WARNING: the service task was started but is not running.")
    print("Plaintext will NOT be locked when the stick is removed until it runs.")
    print("Run `usbkey-setup status`, or reboot, then try again.")
    return 1


def _assert_own_install_root(path: Path) -> None:
    resolved = Path(path).resolve()
    if resolved.name.lower() != config.APP_NAME.lower():
        raise RuntimeError(f"refusing to remove unexpected folder: {resolved}")
    if len(resolved.parts) < 3:
        raise RuntimeError(f"refusing to remove shallow folder: {resolved}")


def _write_bootstrap(name: str, source: str) -> None:
    (Path(config.INSTALL_ROOT) / name).write_text(source, encoding="utf-8")


def _write_shortcut(path: Path, launcher: Path) -> Path | None:
    """Create a real .lnk next to the .bat.

    Windows 11 Start search does not reliably surface .bat files, and a shortcut
    is what users actually click. Failures are non-fatal: the .bat still works.
    """
    try:
        import win32com.client

        shell = win32com.client.Dispatch("WScript.Shell")
        link = shell.CreateShortcut(str(path))
        link.TargetPath = str(Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")))
        link.Arguments = f'/c ""{launcher}""'
        link.WorkingDirectory = str(launcher.parent)
        link.Description = "usbkey - USB-key-gated encrypted vault"
        try:
            link.IconLocation = f"{python_console()},0"
        except OSError:
            pass
        link.Save()
        return path
    except Exception as exc:  # COM missing, policy blocked, ...
        print("WARNING: could not create Start menu shortcut:", exc)
        return None


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

    try:
        paths.ensure_state_tree()
        if acl.allow_state_writes(str(config.STATE_ROOT)):
            print("State folder writable by local users:", config.STATE_ROOT)
        else:
            print("State folder kept admin-only (hardened):", config.STATE_ROOT)
    except OSError as exc:
        print("WARNING: could not prepare the state folder:", exc)

    menu = start_menu_dir()
    menu.mkdir(parents=True, exist_ok=True)
    launcher = menu / "usbkey TUI.bat"
    script = dest / TUI_BOOTSTRAP
    # Bytes, not text: text mode turns the explicit CRLF into CR CR LF, which
    # cmd.exe mis-parses inside the parenthesised block (the launcher then just
    # flashes and closes).
    launcher.write_bytes(
        (
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
            "where python >nul 2>nul\r\n"
            "if %errorlevel%==0 (\r\n"
            f'  python "{script}"\r\n'
            "  goto end\r\n"
            ")\r\n"
            "echo.\r\n"
            "echo Python was not found. Install Python 3.11/3.12, then run:\r\n"
            "echo   pip install usbkey-guard\r\n"
            "echo   usbkey-setup install\r\n"
            ":end\r\n"
            "echo.\r\n"
            "pause\r\n"
        ).encode("utf-8")
    )
    shortcut = _write_shortcut(menu / "usbkey TUI.lnk", launcher)
    print("Start menu entry (all users):", shortcut or launcher)
    if not interpreter_is_shared():
        print()
        print("NOTE: this Python lives in a user profile:")
        print("   ", sys.executable)
        print("The all-users Start menu entry points at it, so it works for this")
        print("account (and for the SYSTEM service) but other users get 'Access is")
        print("denied'. For a machine-wide install, use a Python installed for all")
        print("users, e.g. python.org with 'Install for all users'.")
    print("Optional: `usbkey-setup harden` restricts the state folder to admins")
    print("(non-admin users then cannot create new vaults).")

    result = subprocess.run(
        ["schtasks", "/create", "/tn", config.TASK_NAME, "/tr", task_command(),
         "/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"],
        capture_output=True, text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    if result.returncode != 0:
        return result.returncode
    return _start_service()


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


def repair_permissions() -> int:
    """Re-grant local users write access to the state folder.

    Needed on installs made before 1.0.6, where files written by SYSTEM were
    read-only for a normal desktop session and every vault action failed with
    "Access is denied" on vaults.json.
    """
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    paths.ensure_state_tree()
    ok = acl.allow_state_writes(str(config.STATE_ROOT))
    print("State folder:", config.STATE_ROOT)
    if ok:
        print("Writable by local users: yes (the TUI now works without elevation)")
        return 0
    print("Writable by local users: no")
    print("If you ran `usbkey-setup harden`, this is expected: only administrators")
    print("can change vaults then. Otherwise run this from an elevated prompt.")
    return 1


def status() -> int:
    print("Python:", sys.executable)
    print("Usable by other users:",
          "yes" if interpreter_is_shared() else "no (it is inside a user profile)")
    print("Service:", "running" if _task_running() else "NOT running")
    result = subprocess.run(["schtasks", "/query", "/tn", config.TASK_NAME, "/fo", "LIST"],
                            capture_output=True, text=True)
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="usbkey-setup")
    p.add_argument("action", choices=["install", "uninstall", "status", "harden",
                                      "repair-permissions"])
    args = p.parse_args(argv)
    if args.action == "harden":
        if not is_admin():
            print("ERROR: run this as Administrator.")
            return 1
        return 0 if harden_state() else 1
    return {"install": install, "uninstall": uninstall, "status": status,
            "repair-permissions": repair_permissions}[args.action]()


if __name__ == "__main__":
    sys.exit(main())
