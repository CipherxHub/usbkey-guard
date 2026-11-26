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
- copies the package to `C:\Program Files\usbkey\usbkey_guard`
- adds an all-users Start menu entry named `usbkey TUI`
- creates the SYSTEM scheduled task `usbkey-enforcer` (starts at boot, watches the USB stick)

The task and the Start menu entry run bootstrap scripts from
`C:\Program Files\usbkey`, so the installed copy is what executes even when pip
installed into one user's profile. The launcher falls back to `py`/`python` if the
installing interpreter is not readable by another user.

State (identity, vault manifests, journal, logs) lives in `C:\ProgramData\usbkey`.
Override it with `USBKEY_STATE` before importing if you need a different location.

`usbkey-setup harden` (optional, Administrator) restricts the state folder to
Administrators, SYSTEM and its owner, so unprivileged users cannot add or edit vault
registrations. The trade-off is that non-admin users can then no longer create new
vaults; the default leaves the folder as a normal ProgramData directory.

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

## Using the same stick on a second PC (laptop)

Install the same way on the laptop (`pip install usbkey-guard`, then
`usbkey-setup install` as Administrator), then:

1. Plug in the stick that already holds `key.dat`.
2. Run `usbkey-tui`. It finds the existing key file and offers **USE** or
   **OVERWRITE**. Choose **USE**.
   - `USE` registers the stick on this PC and leaves `key.dat` untouched, so
     every vault made with it stays readable.
   - `OVERWRITE` creates a new key and permanently locks the old vaults. Do not
     choose it unless you mean it.
   - CLI equivalent: `usbkey enroll --drive E:\ --use-existing`
3. Copy the encrypted vault folder to the laptop (or use a drive it can see), then:
   ```powershell
   usbkey vault attach --vault-dir D:\Bank.vault --work-dir C:\Users\me\Bank
   usbkey vault unlock --vault-id <id>
   ```
   `--work-dir` is the folder to restore into on this machine. Without it the
   path recorded in the manifest is used, which may not exist here.
4. Run `usbkey-setup install` once, so the laptop's background task watches the
   stick too.

Nothing secret is copied between machines: the vault key is derived from the
passphrase, the stick's secret and that stick's volume identity. Copying
`key.dat` to a different stick does not work.

## If the Start menu entry does nothing

`usbkey-setup install` writes both a shortcut (`usbkey TUI.lnk`) and a fallback
script (`usbkey TUI.bat`) to the all-users Start menu folder. If the entry is
missing right after installing, sign out and back in (or restart Explorer) so the
Start menu rebuilds its list. The TUI can always be started directly:

```powershell
python "C:\Program Files\usbkey\run_tui.py"
```

If a window flashes and closes, run that command in an open PowerShell to see the
error; the usual cause is Python not being on `PATH`.

## If a vault action says "Access is denied"

```
NOT CHANGED: cannot update C:\ProgramData\usbkey\vaults.json: access denied
```

The state files were written by SYSTEM or by an elevated session, so Windows gave
`BUILTIN\Users` read-only on them. This affects installs made before 1.0.6 and is
fixed by one elevated command:

```powershell
usbkey-setup repair-permissions
```

After that the TUI works from a normal desktop session. `usbkey-setup install`
runs the same repair, and `usbkey-setup harden` deliberately reverses it
(admin-only vault management).

## Uninstall

```powershell
usbkey-setup uninstall
pip uninstall usbkey-guard
```

Uninstall preserves `C:\ProgramData\usbkey` so encrypted vaults are not lost. Reinstall,
then use `usbkey vault attach <vault folder>` to register them again.
