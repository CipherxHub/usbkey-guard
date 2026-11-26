r"""usbkey command-line interface. Use `usbkey-tui` for the interactive menu."""
import argparse
import json
import sys
import time
from pathlib import Path

from . import audit as audit_mod
from . import config, enforce, keystore, paths, procs, setup_app, snapshot, vault
from .errors import UsbKeyError
from .journal import Journal
from .log import get_log

_log = get_log("cli")


def runbook_text() -> str:
    return """USBKEY MANUAL RECOVERY
======================

Your files are encrypted with AES-GCM. Without the USB key AND your passphrase
nobody can read them - including an administrator. Keep this page offline.

1. Plug in the USB stick and open the TUI, choose Unlock, enter your passphrase.
2. If the tool is broken, reinstall it, then run:
       usbkey vault attach <path-to-your-vault-folder>
       usbkey-tui   -> Unlock
3. If the stick is lost, there is no recovery without the passphrase.
4. For ACL-protected folders (legacy), two commands restore access as admin:
       icacls "D:\\SomeFolder" /remove:d "BUILTIN\\Users" /t /c
       icacls "D:\\SomeFolder" /setowner "%USERDOMAIN%\\%USERNAME%" /t /c

LIMITS: this is protection at rest, not against a keylogger or a copied unlocked file.
"""


def _confirm(args) -> bool:
    return args.dry_run or args.yes or input("Type YES to continue: ").strip().upper() == "YES"


def _passphrase(args) -> str | None:
    """Never require the passphrase on the command line: it leaks to the
    process list and shell history on a shared machine."""
    if getattr(args, "passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")
    value = getattr(args, "passphrase", None)
    if value:
        print("WARNING: --passphrase is visible to other users; prefer the prompt "
              "or --passphrase-stdin.", file=sys.stderr)
        return value
    return None  # vault prompts with getpass


def cmd_doctor(args) -> int:
    print("usbkey doctor")
    print("  python       :", sys.version.split()[0])
    print("  state root   :", config.STATE_ROOT)
    print("  install root :", config.INSTALL_ROOT)
    print("  admin token  :", setup_app.is_admin())
    try:
        cfg = enforce.load_config()
        vaults = vault.list_vaults()
    except UsbKeyError as exc:
        print("  state        : UNREADABLE -", exc)
        return exc.code
    print("  ACL roots    :", len(cfg["roots"]))
    print("  vaults       :", len(vaults))
    print("  identity     :", "enrolled" if cfg.get("identity") else "NOT ENROLLED")
    pending = Journal().unreconciled()
    print("  journal      :", f"{len(pending)} unreconciled")
    return 4 if pending else 0


def cmd_status(args) -> int:
    cfg = enforce.load_config()
    identity = cfg.get("identity") or {}
    drive = keystore.find_key(identity) if identity else None
    print("STATUS: key", ("PRESENT on " + str(drive)) if drive else "ABSENT")
    for root in cfg["roots"]:
        print(f"  ACL  {root['id']} locked={root.get('locked')} {root['path']}")
    for line in vault.status():
        print("  VAULT", line)
    return 0


def cmd_enroll(args) -> int:
    cfg = enforce.load_config()
    if cfg.get("identity") and not args.replace:
        print("Already enrolled. Use --replace to re-enroll (existing vaults must be re-attached).")
        return 1
    result = keystore.enroll(args.drive, replace=args.replace)
    cfg["identity"] = result["identity"]
    enforce.save_config(cfg)
    print("Enrolled:", result["identity"])
    print("Key file:", result["key_file"])
    if result.get("previous_key_backup"):
        print("Previous key backed up to:", result["previous_key_backup"])
    return 0


def cmd_audit(args) -> int:
    report = audit_mod.audit(args.path)
    print(audit_mod.format_report(report))
    return 0 if report["passed"] else 7


def cmd_protect(args) -> int:
    if args.action == "list":
        for r in enforce.load_config()["roots"]:
            print(r["id"], "locked=", r.get("locked"), r["path"])
        return 0
    if args.action == "remove":
        enforce.remove_root(args.target)
        print("Removed", args.target)
        return 0
    if not args.i_have_a_backup:
        print("Refusing: pass --i-have-a-backup")
        return 7
    root = enforce.add_root(args.target)
    print("Protected:", root["path"], "id=", root["id"])
    return 0


def _report(lines) -> bool:
    """Print result lines; return True if any of them failed."""
    failed = False
    for line in lines:
        print(line)
        if "FAILED" in line:
            failed = True
    return failed


def cmd_lock(args) -> int:
    if not _confirm(args):
        return 1
    cfg = enforce.load_config()
    if not args.now:
        print("Processes:", procs.stop_protected_processes(
            [r["path"] for r in cfg["roots"]], cfg["settings"]["shutdown_grace_seconds"]))
    failed = _report(enforce.lock_all(dry_run=args.dry_run))
    if not args.dry_run:
        failed = _report(["vault: " + line for line in vault.lock_all()]) or failed
    return 6 if failed else 0


def cmd_unlock(args) -> int:
    cfg = enforce.load_config()
    drive = keystore.find_key(cfg.get("identity") or {})
    if not args.force and not drive:
        print("Key absent. Insert USB or use --force as admin.")
        return 2
    if not _confirm(args):
        return 1
    failed = _report(enforce.unlock_all(dry_run=args.dry_run, force=args.force,
                                        stick_dir=drive if not args.dry_run else None))
    return 6 if failed else 0


def cmd_verify(args) -> int:
    problems = enforce.verify() + vault.verify()
    if problems:
        print("DRIFT DETECTED:")
        for p in problems:
            print(" -", p)
        return 6
    print("OK")
    return 0


def cmd_journal(args) -> int:
    j = Journal()
    if args.action == "replay":
        for note in enforce.replay():
            print(note)
        return 0
    for r in j.records()[-args.n:]:
        print(json.dumps(r, sort_keys=True, default=str))
    print("unreconciled:", len(j.unreconciled()))
    return 0


def cmd_log(args) -> int:
    f = config.STATE_ROOT / "logs" / "usbkey.log"
    if not f.exists():
        print("no log yet")
        return 0
    print("\n".join(f.read_text(encoding="utf-8", errors="replace").splitlines()[-args.n:]))
    return 0


def cmd_export_recovery(args) -> int:
    dest = Path(args.dir)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "RUNBOOK.md").write_text(runbook_text(), encoding="utf-8")
    for root in enforce.load_config()["roots"]:
        rid = root["id"]
        if snapshot.exists(rid):
            snap = snapshot.load(rid)
            (dest / f"acl-{rid}-sddl.txt").write_text(snap["sddl"], encoding="utf-8")
            (dest / f"acl-{rid}-restore.cmd").write_text(
                snapshot.raw_commands(root["path"], snap), encoding="utf-8")
    for v in vault.list_vaults():
        try:
            m = vault._manifest(v)
        except Exception as exc:
            print("skipped vault", v.get("id"), "-", exc)
            continue
        (dest / f"vault-{v['id']}-manifest.json").write_text(
            json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")
    print("Recovery bundle:", dest)
    print("Keep it somewhere OTHER than the encrypted machine.")
    return 0


def cmd_vault(args) -> int:
    if args.action == "convert":
        if not args.work_dir or not args.vault_dir:
            print("--work-dir and --vault-dir are both required")
            return 1
        if not args.yes:
            print("Pass --yes after confirming your backup.")
            return 1
        m = vault.convert(args.work_dir, args.vault_dir,
                          passphrase=_passphrase(args), yes=True)
        print("Vault id:", m["id"], "files:", len(m["files"]))
        if m.get("kept"):
            print("Kept (changed during conversion, still plaintext):", ", ".join(m["kept"]))
        return 0
    if args.action == "attach":
        if not args.vault_dir:
            print("--vault-dir is required")
            return 1
        m = vault.attach(args.vault_dir)
        print("Attached vault:", m["id"])
        return 0
    if args.action == "status":
        print("\n".join(vault.status()))
        return 0
    if args.action == "verify":
        problems = vault.verify()
        print("OK" if not problems else "\n".join(problems))
        return 0 if not problems else 6
    if args.action == "lock":
        return 6 if _report(vault.lock_all()) else 0
    if args.action == "unlock":
        if not args.vault_id:
            print("--vault-id is required")
            return 1
        for line in vault.unlock(args.vault_id, passphrase=_passphrase(args),
                                 force=args.force):
            print("restored:", line)
        return 0
    return 1


def cmd_service(args) -> int:
    if args.action == "harden":
        return setup_app.main(["harden"])
    return {"install": setup_app.install, "uninstall": setup_app.uninstall,
            "status": setup_app.status}[args.action]()


def cmd_monitor(args) -> int:
    cfg = enforce.load_config()
    identity = cfg.get("identity")
    if not identity:
        print("not enrolled")
        return 2
    try:
        for note in enforce.replay():
            print("replay:", note)
    except Exception as exc:
        # A broken journal must not stop the enforcer from protecting data.
        _log.exception("journal replay failed")
        print("replay error:", type(exc).__name__, exc)
    grace = cfg["settings"]["grace_seconds"]
    was_present = None
    locked = False
    retry_at = 0.0
    while True:
        try:
            drive = keystore.find_key(identity)
            present = drive is not None
            if present:
                if was_present is not True:
                    print("key PRESENT", time.strftime("%H:%M:%S"))
                    for line in enforce.unlock_all(stick_dir=drive):
                        print(line)
                was_present = True
                locked = False
                retry_at = 0.0
            else:
                if was_present is None:
                    print("key ABSENT", time.strftime("%H:%M:%S"))
                elif was_present:
                    print("key ABSENT", time.strftime("%H:%M:%S"))
                    time.sleep(grace)
                # Keep retrying while the stick stays out: a file that was busy
                # on the first attempt must still be wiped a few seconds later.
                if (not locked and time.time() >= retry_at
                        and keystore.find_key(identity) is None):
                    current = enforce.load_config()
                    print("Processes:", procs.stop_protected_processes(
                        [r["path"] for r in current["roots"]],
                        current["settings"]["shutdown_grace_seconds"]))
                    failed = _report(enforce.lock_all())
                    failed = _report(["vault: " + line for line in vault.lock_all()]) or failed
                    locked = not failed
                    if failed:
                        retry_at = time.time() + 15
                was_present = False
        except Exception as exc:
            # A single bad root or unreadable manifest must not stop the
            # enforcer from protecting everything else on the next cycle.
            _log.exception("monitor cycle failed")
            print("monitor error:", type(exc).__name__, exc)
        if args.once:
            break
        time.sleep(1)
    return 0


def cmd_gate(args) -> int:
    cfg = enforce.load_config()
    if not keystore.find_key(cfg.get("identity") or {}):
        print("usbkey: key absent - launch denied:", args.exe)
        return 2
    import subprocess
    return subprocess.call([args.exe] + args.rest)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="usbkey", description="USB-key-gated encrypted vault")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("verify").set_defaults(func=cmd_verify)

    e = sub.add_parser("enroll")
    e.add_argument("--drive", required=True)
    e.add_argument("--replace", action="store_true")
    e.set_defaults(func=cmd_enroll)

    a = sub.add_parser("audit")
    a.add_argument("path")
    a.set_defaults(func=cmd_audit)

    pr = sub.add_parser("protect")
    pr.add_argument("action", choices=["add", "remove", "list"])
    pr.add_argument("target", nargs="?")
    pr.add_argument("--i-have-a-backup", action="store_true")
    pr.set_defaults(func=cmd_protect)

    lk = sub.add_parser("lock")
    lk.add_argument("--dry-run", action="store_true")
    lk.add_argument("--now", action="store_true")
    lk.add_argument("--yes", action="store_true")
    lk.set_defaults(func=cmd_lock)

    ul = sub.add_parser("unlock")
    ul.add_argument("--dry-run", action="store_true")
    ul.add_argument("--force", action="store_true")
    ul.add_argument("--yes", action="store_true")
    ul.set_defaults(func=cmd_unlock)

    jr = sub.add_parser("journal")
    jr.add_argument("action", choices=["show", "replay"])
    jr.add_argument("-n", type=int, default=50)
    jr.set_defaults(func=cmd_journal)

    lg = sub.add_parser("log")
    lg.add_argument("-n", type=int, default=50)
    lg.set_defaults(func=cmd_log)

    ex = sub.add_parser("export-recovery")
    ex.add_argument("dir")
    ex.set_defaults(func=cmd_export_recovery)

    va = sub.add_parser("vault")
    va.add_argument("action", choices=["convert", "attach", "unlock", "lock", "status", "verify"])
    va.add_argument("--work-dir")
    va.add_argument("--vault-dir")
    va.add_argument("--vault-id")
    va.add_argument("--passphrase")
    va.add_argument("--passphrase-stdin", action="store_true",
                    help="read the passphrase from stdin (safer than --passphrase)")
    va.add_argument("--force", action="store_true",
                    help="unlock: overwrite files that differ from the vault")
    va.add_argument("--yes", action="store_true")
    va.set_defaults(func=cmd_vault)

    sv = sub.add_parser("service")
    sv.add_argument("action", choices=["install", "uninstall", "status", "harden"])
    sv.set_defaults(func=cmd_service)

    mo = sub.add_parser("monitor")
    mo.add_argument("--once", action="store_true")
    mo.set_defaults(func=cmd_monitor)

    gt = sub.add_parser("gate")
    gt.add_argument("--exe", required=True)
    gt.add_argument("rest", nargs=argparse.REMAINDER)
    gt.set_defaults(func=cmd_gate)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except UsbKeyError as exc:
        print(f"ERROR({exc.code}): {exc}")
        return exc.code
    except Exception as exc:
        _log.exception("unhandled")
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
