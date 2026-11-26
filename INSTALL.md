# Installation (all users)

## Prerequisites

- Windows 10/11, NTFS volume for the data you want to protect
- Python 3.11 or 3.12 (64-bit)
- Administrator rights for the one-time system setup

## Install

```powershell
pip install -U usbkey-guard
python -m usbkey_guard
```

That is the whole install. The menu does the rest: on first start it offers the
one-time Administrator step

```
usbkey: the system copy on this PC is missing or older than this version.
Without it, pulling the USB stick will not re-encrypt unlocked folders.
Windows will ask for Administrator permission.

Set it up now? [Y/n]:
```

Press Enter and approve the UAC prompt. A separate window installs the
machine-wide part; the menu waits for it, prints `Installed.`, and carries on in
the same window. No second command to remember, and no separate
`usbkey-setup install` step.

The same prompt appears after an upgrade (`pip install -U usbkey-guard`): the
installed copy records its version, so the menu notices when the system copy is
older and offers to refresh it.

You only need the manual form if you decline that prompt, or if the automatic
step is blocked by policy:

```powershell
# Administrator PowerShell
python -m usbkey_guard.setup_app install
```

Installing from a downloaded source zip works the same way:

```powershell
cd <extracted source folder>
pip install .
python -m usbkey_guard
```

`python -m usbkey_guard` with no arguments opens the menu. `usbkey`,
`usbkey-tui` and `usbkey-setup` are also registered when pip's `Scripts` folder
is on `PATH`; if PowerShell says `The term 'usbkey' is not recognized`, the
package is installed but that folder is not on `PATH` (normal with the new
Python install manager). The module forms always work:

```powershell
python -m usbkey_guard
python -m usbkey_guard.setup_app status
```

To get the short commands instead, add pip's script folder to your user `PATH`
once, then open a new terminal:

```powershell
$scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
[Environment]::SetEnvironmentVariable(
    'Path', [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + $scripts, 'User')
```

The Administrator step (automatic on first start, or
`python -m usbkey_guard.setup_app install`):
- copies the package to `C:\Program Files\usbkey\usbkey_guard`
- adds an all-users Start menu entry named `usbkey TUI`
- creates the SYSTEM scheduled task `usbkey-enforcer` and starts it immediately
- grants local users write access to the metadata in `C:\ProgramData\usbkey`

Everything is machine-wide: install once, then every account on that PC opens
**usbkey TUI** from the Start menu. Each user still needs the stick and the
passphrase; they share the service, not the keys.

The task and the Start menu entry run bootstrap scripts from
`C:\Program Files\usbkey`, so the installed copy is what executes even when pip
installed into one user's profile.

One caveat: both point at the Python that ran the install. If that Python is in a
user profile (`C:\Users\<name>\...`, which is where the new Python install manager
puts it), the Start menu entry works only for that account. Install Python from
python.org with **Install for all users** (`C:\Program Files\Python312`) when the
PC is shared. The menu warns when it detects this, and
`python -m usbkey_guard.setup_app status` shows the interpreter, whether other
users can use it, and whether the service is running.

State (identity, vault manifests, journal, logs) lives in `C:\ProgramData\usbkey`.
Override it with `USBKEY_STATE` before importing if you need a different location.

`usbkey-setup harden` (optional, Administrator) restricts the state folder to
Administrators, SYSTEM and its owner, so unprivileged users cannot add or edit vault
registrations. The trade-off is that non-admin users can then no longer create new
vaults; the default leaves the folder as a normal ProgramData directory.

Module form: `python -m usbkey_guard.setup_app harden`.

If your organisation blocks generated `.exe` launchers (Application Control / WDAC), use the
module forms instead — they are equivalent:

```powershell
python -m usbkey_guard
python -m usbkey_guard.setup_app status
```

## First run

```powershell
python -m usbkey_guard
```

The menu offers the Administrator step first (see above), then shows a drive
list if no key is enrolled. Pick the USB stick. Input a passphrase when creating
your first vault and **write it down** — it is never stored.

## Using the same stick on a second PC (laptop)

Install the same way on the laptop (`pip install -U usbkey-guard`, then
`python -m usbkey_guard` and accept the Administrator prompt), then:

1. Plug in the stick that already holds `key.dat`.
2. Run `python -m usbkey_guard`. It finds the existing key file and offers
   **USE** or **OVERWRITE**. Choose **USE**.
   - `USE` registers the stick on this PC and leaves `key.dat` untouched, so
     every vault made with it stays readable.
   - `OVERWRITE` creates a new key and permanently locks the old vaults. Do not
     choose it unless you mean it.
   - CLI equivalent: `usbkey enroll --drive E:\ --use-existing`
3. Copy the encrypted vault folder to the laptop (or use a drive it can see), then:
   ```powershell
   python -m usbkey_guard vault attach --vault-dir D:\Bank.vault --work-dir C:\Users\me\Bank
   python -m usbkey_guard vault unlock --vault-id <id>
   ```
   `--work-dir` is the folder to restore into on this machine. Without it the
   path recorded in the manifest is used, which may not exist here.
4. Check the laptop's service once: `python -m usbkey_guard.setup_app status`
   must say `Service: running`, so pulling the stick there re-locks the folder.

Nothing secret is copied between machines: the vault key is derived from the
passphrase, the stick's secret and the stick's on-disk serial. The same stick
therefore opens the same vault on both PCs, and copying `key.dat` to a
different stick does not work.

If **USE** is rejected, read the message before doing anything else. "Belongs to
a different stick" means this is not the stick that created `key.dat` (the two
serials are printed). Do **not** choose **OVERWRITE** to get past an error: it
replaces the secret, and every vault made with the old key becomes unreadable.
If you already overwrote it, the previous key was saved on the PC where you
chose OVERWRITE at
`C:\ProgramData\usbkey\keystore-backup\key-<date>-<time>.dat`; copy the newest
one back to the stick as `key.dat` to recover the old vaults.

## If the plaintext is still there after you pull the stick

Locking is done by the background service, not by the TUI. Two checks:

```powershell
python -m usbkey_guard.setup_app status
python -m usbkey_guard status
```

`... setup_app status` must print `Service: running`. If it says `NOT running`,
the service is not watching the stick, so nothing will be re-encrypted: open
`python -m usbkey_guard`, choose **9) Background service → 2) Install / repair**,
or reboot. `python -m usbkey_guard status` must list the vault you expect.

The service also waits `grace_seconds` after the stick disappears (3 by default)
before locking, and it skips a vault whose plaintext folder is missing.

## If the service will not start (`Service: NOT running`)

Typical output on an affected PC:

```
Service: NOT running
Task state: ready | last result: 0x00041303 (has not run yet)
...
Status:        Ready
Next Run Time: N/A
```

The files stay readable after the stick is pulled, and a reboot does not help.

**Cause:** installs made before 1.0.11 created the task with plain
`schtasks /create`, and Windows' defaults for a new task are *start only on AC
power* and *stop on battery*. On a laptop that boots on battery the task never
starts, and unplugging the charger stops it.

**Fix:** upgrade, then reinstall once so the task is rewritten:

```powershell
pip install -U usbkey-guard
python -m usbkey_guard
# accept the "system copy is older" prompt, or as Administrator:
python -m usbkey_guard.setup_app install
```

From 1.0.11 the task is registered from XML with:

- battery restrictions off (starts and keeps running on battery),
- no execution time limit, restart after a failure (3 tries, 1 minute apart),
- a **boot** trigger and a **logon** trigger, so a missed boot start recovers at
  the next sign-in,
- `StartWhenAvailable`, so a start missed while the PC was off runs afterwards.

Check it took effect:

```powershell
python -m usbkey_guard.setup_app status
```

`Service: running` and `Task state: running` are what you want. If it still
fails, the status output now names the reason (`last result`), and the enforcer
writes startup failures to `C:\ProgramData\usbkey\logs\enforcer-boot.log` —
usually a Python that cannot import `pywin32`/`psutil`, which the install
preflight also reports.

## If the Start menu entry does nothing

The Administrator step writes both a shortcut (`usbkey TUI.lnk`) and a fallback
script (`usbkey TUI.bat`) to the all-users Start menu folder. If the entry is
missing right after installing, sign out and back in (or restart Explorer) so the
Start menu rebuilds its list. The menu can always be started directly:

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
# Administrator PowerShell
python -m usbkey_guard.setup_app repair-permissions
```

After that the TUI works from a normal desktop session. The Administrator step
runs the same repair, and `python -m usbkey_guard.setup_app harden` deliberately
reverses it (admin-only vault management).

## Uninstall

Easiest: run `python -m usbkey_guard` and choose **11) Remove usbkey from this
PC**. It lists what will be deleted, refuses while a vault or a locked folder is
still registered (remove that protection first, option 8), asks you to type
`REMOVE`, then raises the UAC prompt and removes the service, the Start menu
entry, the Program Files copy, the state folder and the Python package.

From a command line, the same removal:

```powershell
# Administrator PowerShell
python -m usbkey_guard.setup_app uninstall --purge
python -m pip uninstall -y usbkey-guard
```

`--purge` also deletes `C:\ProgramData\usbkey`. Without it the state folder is
preserved, which is what you want if vaults still exist: reinstall, then
`python -m usbkey_guard vault attach --vault-dir <vault folder>` registers them
again.

Neither form touches your USB stick (`key.dat` stays, so existing vaults remain
readable) or any vault folder.
