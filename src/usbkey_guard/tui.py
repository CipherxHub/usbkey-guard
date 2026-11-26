r"""Interactive menu for usbkey. No third-party UI dependencies."""
import getpass
import ntpath
import os
import shutil
import sys
import time
from pathlib import Path

import win32api
import win32con
import win32file

from . import config, enforce, keystore, setup_app, vault
from . import __version__ as VERSION

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
    if cfg.get("identity") and ask("Already enrolled. Type CHANGE to select a different stick: ").upper() != "CHANGE":
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
    replace = False
    adopt = False
    if keyfile.exists():
        print("\nThis stick already has a key file.")
        print("  USE       keep it - every vault made with this stick stays readable")
        print("            (this is what you want on a second PC)")
        print("  OVERWRITE make a brand-new key - every vault made with the old key")
        print("            becomes unreadable, even with the correct passphrase")
        choice = ask("Type USE or OVERWRITE: ").upper()
        if choice == "USE":
            adopt = True
        elif choice == "OVERWRITE":
            replace = True
        else:
            print("Cancelled. The key file was not changed.")
            return
    try:
        cfg = enforce.load_config()
        result = (keystore.adopt(drive) if adopt
                  else keystore.enroll(drive, replace=replace))
        cfg["identity"] = result["identity"]
        enforce.save_config(cfg)
        if adopt:
            print("\nUsing the existing key file:", result["key_file"])
            print("Vaults made with this stick stay readable. Nothing was rewritten.")
        else:
            print("\nEnrolled:", result["identity"])
            print("Key file:", result["key_file"])
        if result.get("previous_key_backup"):
            print("Previous key backed up to:", result["previous_key_backup"])
        print("\nNext: attach your encrypted folder (menu option 7), then unlock it.")
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
        if m.get("kept"):
            print("These files changed during conversion and were kept as plaintext:")
            for name in m["kept"]:
                print("  " + name)
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
        text = str(exc)
        print("FAILED:", type(exc).__name__, text)
        if "refusing to overwrite" in text:
            print("Your current files were left untouched. Move them aside and try again.")
        else:
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


def do_remove() -> None:
    heading("STOP PROTECTING A VAULT")
    v = choose_vault()
    if not v:
        pause()
        return
    print("\nThis decrypts the vault for good. The files stay in")
    print("  " + v["work_dir"])
    print("as ordinary unencrypted files, and the encrypted copy is deleted.")
    print("Anything you no longer need can then be deleted normally.")
    if ask("Type DELETE to continue (blank cancels): ").upper() != "DELETE":
        print("Cancelled. Nothing was changed.")
        pause()
        return
    keep = ask("Keep the encrypted copy on disk as a backup? [y/N]: ").lower() == "y"
    pw = getpass.getpass("Passphrase (hidden): ")
    try:
        r = vault.remove(v["id"], passphrase=pw, yes=True, keep_ciphertext=keep)
        print("\nDONE.", r["files"], "file(s) are now ordinary files.")
        print("Encrypted copy:", "kept at " + r["vault_dir"] if keep else "deleted")
        for note in r["leftovers"]:
            print("left alone:", note)
    except Exception as exc:
        text = str(exc)
        print("NOT CHANGED:", text)
        if "refusing to overwrite" in text:
            print("You edited these files after unlocking. Move the edited copies")
            print("aside, unlock again, then stop protection.")
        elif "InvalidTag" in type(exc).__name__ or "InvalidTag" in text:
            print("Wrong passphrase, wrong USB stick, or damaged ciphertext.")
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
    dest = ask("Restore into (blank keeps the folder recorded in the vault): ")
    try:
        m = vault.attach(p, work_dir=dest or None)
        reg = next(v for v in vault.list_vaults() if v["id"] == m["id"])
        print("Attached:", m["id"], "->", reg["work_dir"])
        print("Now choose Unlock and enter its passphrase.")
    except Exception as exc:
        print("FAILED:", exc)
    pause()


def do_service() -> None:
    heading("BACKGROUND ENFORCER")
    print("1) Status   2) Install / repair   3) Remove usbkey from this PC")
    choice = ask("Choose: ")
    if choice == "3":
        do_uninstall()
        return
    action = {"1": "status", "2": "install"}.get(choice)
    if not action:
        return
    print({"status": setup_app.status, "install": setup_app.install}[action]())
    pause()


def do_uninstall() -> None:
    heading("REMOVE USBKEY FROM THIS PC")
    try:
        vaults = vault.list_vaults()
        cfg = enforce.load_config()
    except Exception as exc:
        print("Cannot read the state folder:", exc)
        print("Delete", config.STATE_ROOT, "manually, then run this in an")
        print("Administrator PowerShell:")
        print("  python -m usbkey_guard.setup_app uninstall --purge")
        pause()
        return
    locked = [r for r in cfg.get("roots", []) if r.get("locked")]
    if vaults or locked:
        print("This PC still has protected data:\n")
        for v in vaults:
            print("  vault", v["id"], "->", v["work_dir"])
        for r in locked:
            print("  locked folder", r["path"])
        print("\nRemove that protection first (menu option 8), then uninstall.")
        print("Removing the tool now would leave it encrypted with no way to")
        print("decrypt it on this machine. Nothing was changed.")
        pause()
        return
    print("This removes from this PC:")
    print("  - the Start menu shortcut and the Program Files copy")
    print("  - the background service usbkey-enforcer")
    print("  - the state folder (registrations, logs)")
    print("  - the Python package usbkey-guard")
    print("\nThis does NOT touch:")
    print("  - your USB stick: key.dat stays, so your vaults stay readable")
    print("  - any vault folder or ordinary file")
    print("\nWindows will ask for Administrator permission.")
    if ask("Type REMOVE to continue (blank cancels): ").upper() != "REMOVE":
        print("Cancelled. Nothing was changed.")
        pause()
        return
    if not setup_app.elevate_uninstall():
        print("\nCould not start the Administrator step.")
        print("Run these in an Administrator PowerShell instead:")
        print("  python -m usbkey_guard.setup_app uninstall --purge")
        print("  python -m pip uninstall -y usbkey-guard")
        pause()
        return
    print("\nA separate Administrator window is finishing the removal.")
    print("You can close this window once it reports success.")
    raise SystemExit(0)


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


def service_issue() -> str:
    """Empty when the installed copy is current and its service is running."""
    try:
        installed = (Path(config.INSTALL_ROOT) / setup_app.VERSION_MARKER).read_text(
            encoding="utf-8").strip()
    except OSError:
        installed = ""
    if not installed:
        return "the system copy on this PC is missing or older than this version"
    if installed != VERSION:
        return f"the system copy is {installed}, this is {VERSION}"
    if not setup_app._task_running():
        return "the background service is not running"
    return ""


def _wait_for_install(timeout: float = 120.0) -> bool:
    """The elevated window writes VERSION last; wait for it, then carry on."""
    marker = Path(config.INSTALL_ROOT) / setup_app.VERSION_MARKER
    deadline = time.time() + timeout
    while time.time() < deadline:
        if marker.is_file():
            return True
        time.sleep(0.5)
    return False


def offer_service_setup() -> bool:
    """Offer the one-time Administrator step. True when the caller must stop."""
    issue = service_issue()
    if not issue:
        return False
    clear()
    heading("BACKGROUND SERVICE")
    print("usbkey:", issue + ".")
    print("Without it, pulling the USB stick will not re-encrypt unlocked folders.")
    print("Windows will ask for Administrator permission.\n")
    if ask("Set it up now? [Y/n]: ").lower() not in ("", "y", "yes"):
        print("Skipped. Menu option 9 sets it up later.")
        pause()
        return False
    if not setup_app.elevate_install():
        print("\nCould not elevate. Run this in an Administrator PowerShell:")
        print("  python -m usbkey_guard.setup_app install")
        pause()
        return False
    print("\nAn Administrator window is installing it. Waiting...")
    if _wait_for_install():
        print("Installed. The menu continues below.")
        pause()
        return False
    print("\nStill installing. Reopen usbkey when that window finishes.")
    return True


def _main() -> int:
    if not enforce.load_config().get("identity"):
        clear()
        heading("FIRST RUN - USB KEY SETUP")
        print("No USB key has been enrolled yet. Let's select one.")
        do_enroll()
    if offer_service_setup():
        return 0
    while True:
        clear()
        heading("MAIN MENU")
        drive = key_drive()
        print("USB key :", "IN  (" + str(drive) + ")" if drive else "OUT")
        print()
        print("  1) Status")
        print("  2) Select / change USB key")
        print("  3) Encrypt a file or folder")
        print("  4) Unlock a vault")
        print("  5) Lock (wipe plaintext)")
        print("  6) Verify integrity")
        print("  7) Attach existing vault")
        print("  8) Stop protecting a vault (decrypt for good)")
        print("  9) Background service")
        print(" 10) Export recovery bundle")
        print(" 11) Remove usbkey from this PC")
        print("  0) Exit")
        choice = ask("\nChoose: ")
        actions = {
            "1": show_status, "2": do_enroll, "3": do_encrypt, "4": do_unlock,
            "5": do_lock, "6": do_verify, "7": do_attach, "8": do_remove,
            "9": do_service, "10": do_export, "11": do_uninstall,
        }
        if choice == "0":
            print("Bye.")
            return 0
        if choice in actions:
            try:
                actions[choice]()
            except Exception as exc:
                print("\nERROR:", type(exc).__name__, exc)
                pause()
        else:
            print("Invalid choice.")
            pause()


def main() -> int:
    try:
        return _main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as exc:
        print("\nusbkey: fatal:", type(exc).__name__, exc)
        print("State was not modified. Check C:\\ProgramData\\usbkey\\logs for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
