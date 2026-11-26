r"""All-users install: Program Files copy, Start menu entry, SYSTEM task."""
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def start_menu_dir() -> Path:
    root = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return root / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "usbkey"


def pythonw() -> Path:
    return Path(sys.executable).with_name("pythonw.exe")


def task_command() -> str:
    return f'"{pythonw()}" -m usbkey_guard.cli monitor'


def install() -> int:
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    try:
        shutil.copytree(config.PACKAGE_ROOT, config.INSTALL_ROOT, dirs_exist_ok=True)
    except OSError as exc:
        print("ERROR copying files:", exc)
        return 1
    print("Files installed to", config.INSTALL_ROOT)

    menu = start_menu_dir()
    menu.mkdir(parents=True, exist_ok=True)
    launcher = menu / "usbkey TUI.bat"
    launcher.write_text(
        f'@echo off\r\ntitle usbkey\r\n"{pythonw().with_name("python.exe")}" '
        f'-m usbkey_guard.tui\r\npause\r\n',
        encoding="utf-8",
    )
    print("Start menu entry:", launcher)

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
        shutil.rmtree(menu)
        print("Start menu entry removed.")
    if config.INSTALL_ROOT.exists():
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
    p.add_argument("action", choices=["install", "uninstall", "status"])
    args = p.parse_args(argv)
    return {"install": install, "uninstall": uninstall, "status": status}[args.action]()


if __name__ == "__main__":
    sys.exit(main())
