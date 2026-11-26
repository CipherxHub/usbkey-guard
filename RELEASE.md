# Release build notes

Package: `usbkey-guard` 1.0.5 (pip-installable, Windows only)

## What is included

- `src/usbkey_guard/` - all runtime modules, no hardcoded machine paths
- TUI with first-run USB drive selection, encryption, unlock, lock, verify,
  attach-existing-vault (with a restore-folder override), second-PC key adopt,
  stop-protecting, service control and recovery export
- CLI for scripting/recovery
- `usbkey-setup install|uninstall|status|harden` - Program Files copy, all-users
  Start menu shortcut, SYSTEM scheduled task
- `config.py` - all paths overridable by `USBKEY_STATE` / `USBKEY_INSTALL`
- `README.md`, `INSTALL.md`, `QUICKSTART.md`, `LIMITATIONS.md`, `LICENSE`
- 68 automated tests including source-level no-destructive guard, crash replay,
  unique vault IDs, path/manifest traversal, all-or-nothing unlock, verified
  unprotect, second-PC key adopt, corrupt-state handling, the installed-copy
  import layout and the Start menu launcher encoding

## Verified

- `pip install -e .` succeeds
- `python -m pytest tests -q` -> 68 passed
- `python -m usbkey_guard --help` works
- convert -> verify -> unlock -> lock round trip, including empty folders, a
  modified file that must survive locking, and a vault released back to
  ordinary files
- adopting an existing key.dat leaves the file byte-identical
- attach --work-dir restores a vault made on another machine into a new folder
- manifests written by 1.0.1 (no `kdf` key) still unlock
- TUI first-run correctly detects a removable drive and offers it for enrollment

## Fixed in 1.0.5

- The all-users Start menu launcher was written in text mode, so every line ended
  up as CR CR LF. `cmd.exe` mis-parses that inside the parenthesised block and the
  window just closed. It is now written as bytes with real CRLF.
- The Start menu entry is now a proper `usbkey TUI.lnk` shortcut (with the .bat
  kept as a fallback), because Windows 11 Start search does not reliably surface
  `.bat` files.
- The launcher now prints a readable message when Python is not on PATH instead
  of failing silently.

## Clean state

The release defaults to a fresh state root (`%PROGRAMDATA%\usbkey`) and asks for USB
enrollment on first run. Nothing from any development machine is shipped. Existing
encrypted vaults can always be registered with:

```
usbkey vault attach <path-to-vault-folder>
```

On a second machine, adopt the existing stick instead of overwriting its key:

```
usbkey enroll --drive E:\ --use-existing
usbkey vault attach --vault-dir D:\Private.vault --work-dir C:\Users\me\Private
```

## Console-script note

Some managed machines block pip's generated `.exe` launchers with Application Control.
On those machines use the module forms instead - they are equivalent:

```
python -m usbkey_guard
python -m usbkey_guard.tui
python -c "from usbkey_guard.setup_app import install; install()"
```
