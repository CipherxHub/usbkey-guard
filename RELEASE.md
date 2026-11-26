# Release build notes

Package: `usbkey-guard` 1.0.3 (pip-installable, Windows only)

## What is included

- `src/usbkey_guard/` — all runtime modules, no hardcoded machine paths
- TUI with first-run USB drive selection, encryption, unlock, lock, verify,
  attach-existing-vault, stop-protecting, service control and recovery export
- CLI for scripting/recovery
- `usbkey-setup install|uninstall|status|harden` — Program Files copy, all-users
  Start menu entry, SYSTEM scheduled task
- `config.py` — all paths overridable by `USBKEY_STATE` / `USBKEY_INSTALL`
- `README.md`, `INSTALL.md`, `QUICKSTART.md`, `LIMITATIONS.md`, `LICENSE`
- 57 automated tests including source-level no-destructive guard, crash replay,
  unique vault IDs, path/manifest traversal, all-or-nothing unlock, verified
  unprotect, corrupt-state handling and the installed-copy import layout

## Verified

- `pip install -e .` succeeds
- `python -m pytest tests -q` → 57 passed
- `python -m usbkey_guard --help` works
- convert → verify → unlock → lock round trip, including empty folders, a
  modified file that must survive locking, and a vault released back to
  ordinary files
- manifests written by 1.0.1 (no `kdf` key) still unlock
- TUI first-run correctly detects a removable drive and offers it for enrollment

## Clean state

The release defaults to a fresh state root (`%PROGRAMDATA%\usbkey`) and asks for USB
enrollment on first run. Nothing from any development machine is shipped. Existing
encrypted vaults can always be registered with:

```
usbkey vault attach <path-to-vault-folder>
```

## Console-script note

Some managed machines block pip's generated `.exe` launchers with Application Control.
On those machines use the module forms instead — they are equivalent:

```
python -m usbkey_guard
python -m usbkey_guard.tui
python -c "from usbkey_guard.setup_app import install; install()"
```
