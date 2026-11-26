# Release build notes

Package: `usbkey-guard` 1.0.15 (pip-installable, Windows only)

## What is included

- `src/usbkey_guard/` - all runtime modules, no hardcoded machine paths
- `python -m usbkey_guard` opens the menu; the same module offers the one-time
  Administrator step on first start, so there is no second command to remember
- TUI with first-run USB drive selection, encryption, unlock, lock, verify,
  attach-existing-vault (with a restore-folder override), second-PC key adopt,
  stop-protecting, service control, recovery export and complete removal
- CLI for scripting/recovery
- `usbkey-setup install|uninstall|status|harden|repair-permissions` - Program
  Files copy, all-users Start menu shortcut, SYSTEM scheduled task (created and
  started), state-folder permissions, `uninstall --purge` for a full removal
- `config.py` - all paths overridable by `USBKEY_STATE` / `USBKEY_INSTALL`
- `README.md`, `INSTALL.md`, `QUICKSTART.md`, `LIMITATIONS.md`, `LICENSE`
- 162 automated tests including source-level no-destructive guard, crash replay,
  unique vault IDs, path/manifest traversal, all-or-nothing unlock, verified
  unprotect, second-PC key adopt (including a different volume GUID and a legacy
  key file), cross-machine vault keys, state-permission repair, service start and
  a source-wide dependency scan (every non-stdlib import in the package, probed
  both isolated and normally so a per-user-only install is caught), task XML
  registration (battery, triggers, watchdog, restart, escaping), service diagnosis
  (missing interpreter, Store alias, missing bootstrap, boot-log tail, missing
  module), locale-proof task state, the install preflight, the enrollment wait,
  removal safety, the first-run service offer, the no-argument menu entry point,
  corrupt-state handling, the installed-copy import layout and the Start menu
  launcher encoding

## Verified

- `pip install -e .` succeeds
- `python -m pytest tests -q` -> 161 passed, 1 skipped here (the mutual-exclusion
  test skips itself on a PC where the real enforcer is already running)
- `python -m usbkey_guard --help` works
- convert -> verify -> unlock -> lock round trip, including empty folders, a
  modified file that must survive locking, and a vault released back to
  ordinary files
- adopting an existing key.dat leaves the file byte-identical
- attach --work-dir restores a vault made on another machine into a new folder
- manifests written by 1.0.1 (no `kdf` key) still unlock
- TUI first-run correctly detects a removable drive and offers it for enrollment

## Fixed in 1.0.15

The laptop got past the `cryptography` check and then failed with
`ModuleNotFoundError: No module named '_cffi_backend'`, even though `pip` said
`Requirement already satisfied`. The package was there — in
`%APPDATA%\Python\Python312\site-packages`, the per-user folder that a SYSTEM
task cannot read. Every check the tool ran used the installing user's
`sys.path`, so it could not see the difference.

- The dependency probe now runs with `-I` (isolated), which drops the per-user
  site folder and `PYTHONPATH`. That is exactly what the SYSTEM task sees, so a
  dependency that exists only under `%APPDATA%` is reported instead of passing.
- When the package imports fine non-isolated but fails isolated, the message says
  so in plain words: it can only be imported from the user-profile folder, and
  the SYSTEM service cannot read that folder.
- The fix line is now one command, with `--force-reinstall`, and it names `cffi`
  as well: `"C:\Python312\python.exe" -m pip install --force-reinstall pywin32
  psutil cryptography cffi`. `status` marks it as needing an elevated
  PowerShell, because that is what makes pip write to
  `C:\Python312\Lib\site-packages` instead of the per-user folder.

## Fixed in 1.0.14

The install preflight still missed the failure that stopped a laptop: it probed
`usbkey_guard`, `win32event` and `psutil` by name, so a Python without
`cryptography` passed the check and the enforcer then died at startup with
`ModuleNotFoundError: No module named 'cryptography'`.

- The preflight now scans the installed package's source and imports every
  non-stdlib module it references (13 today: `cryptography.exceptions`,
  `cryptography.hazmat.primitives.ciphers.aead`, `psutil`, `pywintypes`,
  `win32api`, `win32com.client`, `win32con`, `win32event`, `win32file`,
  `win32gui`, `win32process`, `win32security`, `winerror`), so a dependency
  added in a later version is checked without anyone updating a list, and lazy
  imports inside functions are covered too.
- One run reports every missing module at once instead of only the first
  traceback.
- `status` reads `No module named 'x'` from the boot log and prints the repair
  command for the task's own interpreter, e.g.
  `"C:\Python312\python.exe" -m pip install pywin32 psutil cryptography`.
- `install` no longer says "install again" without saying what to install.
- A watchdog tick that finds the service already running is decoded as
  "start skipped: already running" instead of an unknown `0x800710E0`.

## Fixed in 1.0.13

The 1.0.12 diagnosis treated every "not running" as "never started", which is
the wrong advice for the most common case: the task ran, then the process was
ended (Task Manager, `schtasks /end`, antivirus). Windows reports
`0x41306 (terminated)` for that, and `RestartOnFailure` does not fire.

- `status` now reads the last result: a terminated process is reported as
  terminated, with the note that the five-minute watchdog restarts it and the
  one-line command to start it immediately.
- A clean exit (result 0) points at `logs\usbkey.log` instead of guessing.
- Two new tests cover the terminated and boot-log paths.

## Fixed in 1.0.12

1.0.11 made the task *startable*, but on a PC where it still did not run the
tool only said `Service: NOT running` and left the user to guess. The usual
reasons are environmental, not settings: the registered `pythonw.exe` no longer
exists, it is the Microsoft Store alias (which a SYSTEM task cannot execute), or
that interpreter cannot import `pywin32`/`psutil` because they were installed
for one user or into a virtualenv.

- `usbkey-setup status` now prints the task's actual command, flags a missing
  interpreter, a Store alias, or a missing `run_enforcer.py`, and prints the
  tail of `logs\enforcer-boot.log` (the enforcer's own startup traceback, since
  `pythonw.exe` has no console). It exits 1 while the service is down.
- The TUI refresh no longer says "Installed" and stops there: after the
  elevated window it re-checks the service and prints the same explanation.
- The task gained a **five-minute repetition trigger**. `RestartOnFailure` only
  covers a process that exits with an error; a service ended from Task Manager,
  killed by antivirus or by an update stayed down until the next boot. With
  `MultipleInstancesPolicy=IgnoreNew` the watchdog never duplicates a healthy
  instance.
- `install` now returns failure (and prints the reason) when the task was
  created but the service did not come up, instead of reporting success.

## Fixed in 1.0.11

The service could sit at `Status: Ready` forever: `schtasks /create` gives a new
task Windows' defaults "start only on AC power" and "stop on battery", so a
laptop that boots on battery never started the enforcer, and unplugging the
charger stopped it. Pulling the stick then left plaintext readable, including
after a reboot.

- The task is now registered from XML with battery restrictions off, no
  execution time limit, restart-on-failure (3 tries, 1 minute apart),
  `StartWhenAvailable`, and both a **boot** and a **logon** trigger. A missed
  boot start recovers at the next sign-in.
- Running state is read through the Task Scheduler COM API instead of parsing
  `schtasks` text, which is localised (on a non-English Windows the old check
  never saw "Running").
- `status` now prints the task state and a decoded `last result`
  (`0x41303 = has not run yet`, `0x80070002 = file not found`, ...) and warns
  when an old task still blocks battery starts.
- `install` runs a preflight: the task's Python must import the installed
  package plus `pywin32`/`psutil`, or the install says so instead of leaving a
  service that exits instantly.
- The enforcer bootstrap writes startup failures to
  `C:\ProgramData\usbkey\logs\enforcer-boot.log` (pythonw has no console).
- The monitor no longer exits when no key is enrolled yet; a boot-started
  service waits for the first enrollment instead of dying until the next boot.

`USE` on a second PC also failed with "that key file was copied from a different
stick" for the *right* stick. Windows stores volume GUIDs in the per-machine
mount-manager database, so the same stick reports a different GUID on every PC,
and the old check compared those GUIDs. Vault keys mixed the GUID in as well, so
even after a forced re-enroll a vault made on the first PC would not open on the
second one.

- `key.dat` now binds to the stick's on-disk volume serial only, and version 1
  key files are verified with the GUID stored inside the file, not the one this
  PC reports. `USE` therefore works on any PC, and still refuses a key copied to
  a different stick (the two serials are printed).
- New vaults derive the key from `passphrase + stick secret + volume serial`, so
  the same stick and passphrase open the vault on every PC.
- Vaults made before 1.0.11 still unlock: the old material is tried with both
  this PC's GUID and the enrolling PC's GUID (kept in `key.dat`), before the
  "wrong passphrase" error.
- A failed enrollment is now logged with its traceback, and the TUI says whether
  anything was written (adopting never touches the stick).
- The monitor's single-instance mutex is owned by SYSTEM, so a desktop user got
  `Access is denied` creating it; that now means "already running" instead of
  crashing the command or letting a second monitor fight the service.

If you already chose `OVERWRITE` to get past that error, the old key was saved
before the rewrite: copy the newest `key-*.dat` from
`C:\ProgramData\usbkey\keystore-backup` (on the PC where you chose it) back to
the stick as `key.dat` to recover vaults made with the old key.

## Added in 1.0.10

Documentation only, so the published pages match the 1.0.9 behaviour:

- README, INSTALL, QUICKSTART and LIMITATIONS now all show the two-line install
  (`pip install -U usbkey-guard`, `python -m usbkey_guard`) and the exact
  "Set it up now?" prompt. INSTALL no longer says to reopen the menu, which
  1.0.9 made unnecessary.
- QUICKSTART gained an **Upgrading** section and lost the mojibake that an
  earlier encoding pass had left in it.
- README's command-line section says how to run the same commands as
  `python -m usbkey_guard ...` when `usbkey` is not on `PATH`.
- Every remaining `usbkey-setup` example in the user docs has a module-form
  equivalent next to it.

## Added in 1.0.9

- `python -m usbkey_guard` with no arguments now opens the menu instead of
  printing argparse usage.
- First start offers the Administrator step itself: "Set it up now? [Y/n]" →
  UAC → the system copy, Start menu entry and service are installed in a
  separate window. The install no longer needs a remembered second command.
- The installed copy writes a `VERSION` marker. The menu compares it with the
  running package, so after `pip install -U usbkey-guard` it offers to refresh
  the system copy instead of silently running the old service. A missing marker
  (any 1.0.8 or older install) counts as out of date.
- `setup_app.install()` can elevate itself; non-admin runs print the exact
  Administrator command only if UAC is refused.

## Added in 1.0.8

- TUI option **11) Remove usbkey from this PC**: one place to uninstall without
  remembering commands. It lists exactly what will be removed, refuses while a
  vault or a locked folder is still registered (so encrypted data can never be
  stranded), requires the word `REMOVE`, then raises UAC and deletes the service,
  the Start menu entry, the Program Files copy, the state folder and the pip
  package. It never touches the stick or a vault folder.
- `usbkey-setup uninstall --purge` performs the same full removal from a
  command line; without `--purge` the state folder is kept as before.
- The Background service submenu now points at that same removal instead of
  silently deleting half the install.

## Fixed in 1.0.7

- `usbkey-setup install` created the `usbkey-enforcer` task but never started it,
  so after a fresh install nothing locked the plaintext until the next reboot.
  It now starts the task and reports whether it is actually running; a service
  that will not start is a hard warning, because the data would stay readable.
- The install and the Start menu entry embed the path of the Python that ran
  them. A Python inside a user profile (`C:\Users\<name>\...`, the default for
  the new Python install manager) works for that account and for SYSTEM but not
  for other users. Install now says so, and `usbkey-setup status` shows the
  interpreter, whether it is usable by other users, and whether the service is
  running.

## Fixed in 1.0.6

- Vault actions from a normal (non-elevated) session failed with
  `[WinError 5] Access is denied: '...\\vaults.json.tmp' -> '...\\vaults.json'`.
  Windows grants `BUILTIN\Users` create-file on `%PROGRAMDATA%` but only read on
  files written by SYSTEM or an elevated session. `usbkey-setup install` now
  grants local users modify on the state tree (metadata only, never key
  material), and `usbkey-setup repair-permissions` fixes an existing install.
- A permission failure now reports the remedy and removes its temp file instead
  of leaving a stale `vaults.json.tmp` behind.
- `usbkey-setup harden` records a marker, so a later install or repair does not
  silently undo the admin-only setting.

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
