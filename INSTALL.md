# Installation (all users)

## Prerequisites

- Windows 10/11, NTFS volume for the data you want to protect
- Python 3.11 or 3.12 (64-bit)
- Administrator rights for the one-time system setup

## Install

```powershell
pip install usbkey-guard
usbkey-setup install
```

Installing from a downloaded source zip works too:

```powershell
cd <extracted source folder>
pip install .
usbkey-setup install
```

Either form registers `usbkey`, `usbkey-tui` and `usbkey-setup`.
`usbkey-setup install`:
- copies the package to `C:\Program Files\usbkey`
- adds a Start menu entry named `usbkey TUI`
- creates the SYSTEM scheduled task `usbkey-enforcer` (starts at boot, watches the USB stick)

State (identity, vault manifests, journal, logs) lives in `C:\ProgramData\usbkey`.
Override it with `USBKEY_STATE` before importing if you need a different location.

If your organisation blocks generated `.exe` launchers (Application Control / WDAC), use the
module forms instead — they are equivalent:

```powershell
python -m usbkey_guard --help
python -m usbkey_guard.tui
python -c "from usbkey_guard.setup_app import install; install()"
```

## First run

```powershell
usbkey-tui
```

If no key is enrolled, the TUI immediately shows a drive list. Pick the USB stick.
Input a passphrase when creating your first vault and **write it down** — it is never stored.

## Uninstall

```powershell
usbkey-setup uninstall
pip uninstall usbkey-guard
```

Uninstall preserves `C:\ProgramData\usbkey` so encrypted vaults are not lost. Reinstall,
then use `usbkey vault attach <vault folder>` to register them again.
