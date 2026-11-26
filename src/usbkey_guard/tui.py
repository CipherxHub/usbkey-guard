r"""Interactive menu for usbkey. No third-party UI dependencies."""
import getpass
import ntpath
import os
import shutil
import sys
from pathlib import Path

import win32api
import win32con
import win32file

from . import config, enforce, keystore, setup_app, vault

DRIVE_TYPES = {
    win32con.DRIVE_UNKNOWN: "unknown",
    win32con.DRIVE_NO_ROOT_DIR: "no root",
    win32con.DRIVE_REMOVABLE: "REMOVABLE",
    win32con.DRIVE_FIXED: "fixed",
    win32con.DRIVE_REMOTE: "network",
    win32con.DRIVE_CDROM: "cd-rom",
    win32con.DRIVE_RAMDISK: "ramdisk",
}


def clear() -> None:
    os.system("cls")


def ask(prompt: str) -> str:
    return input(prompt).strip().strip('"')


def pause() -> None:
    input("\nPress Enter to continue... ")


def heading(title: str) -> None:
    print("=" * 62)
    print(" usbkey  -  " + title)
    print("=" * 62)


def key_drive():
    cfg = enforce.load_config()
    return keystore.find_key(cfg.get("identity") or {})


def list_drives() -> list[str]:
    drives = [d for d in win32api.GetLogicalDriveStrings().split("\x00") if d]
    return sorted(drives)


def show_drives() -> list[str]:
    print("\nDetected drives:")
    drives = list_drives()
    for i, drive in enumerate(drives, 1):
        try:
            kind = DRIVE_TYPES.get(win32file.GetDriveType(drive), "?")
            label = win32api.GetVolumeInformation(drive)[0] or "(no label)"
            total, free = shutil.disk_usage(drive)[:2]
            marker = " <-- USB" if kind == "REMOVABLE" else ""
            print(f"  {i}) {drive}  {kind:9s} {label[:20]:20s} "
                  f"{free/1e9:.1f}/{total/1e9:.1f} GB{marker}")
        except OSError:
            print(f"  {i}) {drive}  (not ready)")
    return drives


def do_enroll() -> None:
    heading("SELECT USB KEY")
    cfg = enforce.load_config()
    if cfg.get("identity") and not ask("Already enrolled. Type REPLACE to change: ").upper() == "REPLACE":
        return
    drives = show_drives()
    raw = ask("\nEnter drive number (blank cancels): ")
    if not raw or not raw.isdigit() or not 1 <= int(raw) <= len(drives):
        return
    drive = drives[int(raw) - 1]
    kind = win32file.GetDriveType(drive)
    if kind != win32con.DRIVE_REMOVABLE:
        if ask("That is not a removable drive. Type YES to use anyway: ").upper() != "YES":
            return
    keyfile = Path(drive) / config.KEY_FILENAME
    if keyfile.exists():
        if ask("A key file exists. Type OVERWRITE to replace it: ").upper() != "OVERWRITE":
            return
        try:
            keyfile.unlink()
        except OSError as exc:
            print("Could not remove old key file:", exc)
            pause()
            return
    try:
        cfg = enforce.load_config()
        result = keystore.enroll(drive)
        cfg["identity"] = result["identity"]
        enforce.save_config(cfg)
        print("\nEnrolled:", result["identity"])
        print("Key file:", result["key_file"])
        print("\nIMPORTANT: existing encrypted vaults are bound to the old key.")
        print("They must be re-created or re-enrolled with the original stick.")
    except Exception as exc:
        print("FAILED:", exc)
    pause()


def show_status() -> None:
    heading("STATUS")
    drive = key_drive()
    print("USB key     :", "PRESENT on " + drive if drive else "ABSENT")
    cfg = enforce.load_config()
    print("Identity    :", "enrolled" if cfg.get("identity") else "NOT ENROLLED")
    print("ACL roots   :", len(cfg["roots"]))
    print("ACL verify  :", "OK" if not enforce.verify() else "DRIFT")
    print("\nVaults:")
    lines = vault.status()
    for line in lines:
        print("  " + line)
    problems = vault.verify()
    print("Vault verify:", "OK" if not problems else problems)
    pause()


def choose_vault() -> dict | None:
    items = vault.list_vaults()
    if not items:
        print("No vaults yet. Choose Encrypt first.")
        return None
    print("\nVaults:")
    for i, v in enumerate(items, 1):
        label = v.get("source_file") or v["work_dir"]
        print(f"  {i}) {v['id']}  -> {label}")
    raw = ask("Enter number or id (blank cancels): ")
    if not raw:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(items):
        return items[int(raw) - 1]
    for v in items:
        if (v["id"] == raw or v["work_dir"].lower() == raw.lower()
                or (v.get("source_file") or "").lower() == raw.lower()):
            return v
    print("No matching vault.")
    return None


def do_encrypt() -> None:
    heading("ENCRYPT A FILE OR FOLDER")
    if not key_drive():
        print("Insert the enrolled USB stick first (menu option 2).")
        pause()
        return
    target_raw = ask("File or folder path to encrypt: ")
    target = Path(target_raw) if target_raw else None
    if target is None or not (target.is_file() or target.is_dir()):
        print("That path does not exist.")
        pause()
        return
    default = str(target) + config.VAULT_SUFFIX
    vault_raw = ask(f"Where to store encrypted data [{default}]: ") or default
    drive, tail = ntpath.splitdrive(vault_raw)
    if drive and tail.strip("\\/") == "":
        print("Enter a full folder path, e.g. " + drive + "\\MyVault")
        pause()
        return
    vp = Path(vault_raw)
    if vp.exists() and not (vp.is_dir() and not any(vp.iterdir())):
        child = vp / (target.name + config.VAULT_SUFFIX)
        n = 1
        while child.exists():
            child = vp / f"{target.name}{config.VAULT_SUFFIX}.{n}"
            n += 1
        vault_raw = str(child)
        print("Using subfolder:", vault_raw)
    pw1 = getpass.getpass("New passphrase (hidden): ")
    pw2 = getpass.getpass("Confirm passphrase (hidden): ")
    if not pw1 or pw1 != pw2:
        print("Passphrases do not match or are empty.")
        pause()
        return
    count = 1 if target.is_file() else len([p for p in target.rglob("*") if p.is_file()])
    print(f"\n{count} file(s) will be encrypted. Plaintext is removed only after verification.")
    if ask("Type YES to continue: ").upper() != "YES":
        print("Cancelled.")
        pause()
        return
    try:
        m = vault.convert(str(target), vault_raw, passphrase=pw1, yes=True)
        print("\nDONE. Vault id:", m["id"])
        print("WRITE DOWN YOUR PASSPHRASE - it is never stored.")
    except Exception as exc:
        print("FAILED:", type(exc).__name__, exc)
    pause()


def do_unlock() -> None:
    heading("UNLOCK A VAULT")
    if not key_drive():
        print("Insert the enrolled USB stick first.")
        pause()
        return
    v = choose_vault()
    if not v:
        pause()
        return
    pw = getpass.getpass("Passphrase (hidden): ")
    try:
        files = vault.unlock(v["id"], passphrase=pw)
        print("\nDONE. Restored", len(files), "file(s).")
    except Exception as exc:
        print("FAILED:", type(exc).__name__, exc)
        print("Wrong passphrase, wrong USB stick, or damaged ciphertext.")
    pause()


def do_lock() -> None:
    heading("LOCK / WIPE PLAINTEXT")
    v = choose_vault()
    if not v:
        pause()
        return
    try:
        removed = vault.lock(v["id"])
        print("DONE. Removed", len(removed), "plaintext file(s).")
    except Exception as exc:
        print("NOT LOCKED:", exc)
        print("A changed file was preserved - no work was lost.")
    pause()


def do_verify() -> None:
    heading("VERIFY")
    problems = enforce.verify() + vault.verify()
    print("OK. Everything is consistent." if not problems else "DRIFT:\n  " + "\n  ".join(problems))
    pause()


def do_attach() -> None:
    heading("ATTACH EXISTING VAULT")
    p = ask("Path to vault folder (contains manifest.json): ")
    if not p:
        return
    try:
        m = vault.attach(p)
        print("Attached:", m["id"], "->", m.get("source_file") or m["work_dir"])
        print("Now choose Unlock and enter its passphrase.")
    except Exception as exc:
        print("FAILED:", exc)
    pause()


def do_service() -> None:
    heading("BACKGROUND ENFORCER")
    print("1) Status   2) Install   3) Uninstall")
    action = {"1": "status", "2": "install", "3": "uninstall"}.get(ask("Choose: "))
    if not action:
        return
    print({"status": setup_app.status, "install": setup_app.install,
           "uninstall": setup_app.uninstall}[action]())
    pause()


def do_export() -> None:
    heading("EXPORT RECOVERY BUNDLE")
    p = ask("Destination folder: ")
    if not p:
        return
    try:
        from . import cli
        cli.cmd_export_recovery(type("A", (), {"dir": p})())
    except Exception as exc:
        print("FAILED:", exc)
    pause()


def main() -> int:
    if not enforce.load_config().get("identity"):
        clear()
        heading("FIRST RUN - USB KEY SETUP")
        print("No USB key has been enrolled yet. Let's select one.")
        do_enroll()
    while True:
        clear()
        heading("MAIN MENU")
        print("USB key :", "IN  (" + str(key_drive()) + ")" if key_drive() else "OUT")
        print()
        print("  1) Status")
        print("  2) Select / change USB key")
        print("  3) Encrypt a file or folder")
        print("  4) Unlock a vault")
        print("  5) Lock (wipe plaintext)")
        print("  6) Verify integrity")
        print("  7) Attach existing vault")
        print("  8) Background service")
        print("  9) Export recovery bundle")
        print("  0) Exit")
        choice = ask("\nChoose: ")
        actions = {
            "1": show_status, "2": do_enroll, "3": do_encrypt, "4": do_unlock,
            "5": do_lock, "6": do_verify, "7": do_attach, "8": do_service,
            "9": do_export,
        }
        if choice == "0":
            print("Bye.")
            return 0
        if choice in actions:
            actions[choice]()
        else:
            print("Invalid choice.")
            pause()


if __name__ == "__main__":
    sys.exit(main())
