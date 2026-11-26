# Quick start

1. Plug in the USB stick you want to use as the key.
2. Run `python -m usbkey_guard` (or `usbkey-tui`).
3. Accept the one-time Administrator prompt if it appears. A small window
   installs the Start menu entry and the background service that re-locks folders
   when the stick is pulled; the menu waits and then continues by itself.
4. If asked, select the removable drive from the list. This writes `key.dat` to it.
5. Choose **3) Encrypt a file or folder**.
   - Enter the path, e.g. `D:\Private`
   - Enter or accept the vault destination, e.g. `D:\Private.vault`
   - Enter and confirm a passphrase
   - Type `YES`
6. The original files vanish from `D:\Private`. Only ciphertext remains in the vault.
7. Choose **4) Unlock a vault**, select it, enter the passphrase. Files return.
8. Unplug the USB stick. Within ~5 seconds the decrypted files are wiped again.
9. Plug it back in. Files stay gone until you unlock with the passphrase again.

## Everyday commands

```
python -m usbkey_guard status              # key present? vaults locked?
python -m usbkey_guard vault verify        # integrity check
python -m usbkey_guard vault remove --vault-id <id> --yes   # decrypt for good
python -m usbkey_guard export-recovery D:\Recovery          # bundle to keep off this PC
```

If `usbkey` itself is on `PATH`, the short forms are identical.

To stop protecting something you no longer need, use **8) Stop protecting a vault**
(or `vault remove`). It decrypts the files, deletes the encrypted copy, and
leaves ordinary files you can delete normally. ACL-protected folders come out with
`protect remove <path>` after unlocking them.

## Upgrading

```powershell
pip install -U usbkey-guard
python -m usbkey_guard
```

The installed copy records its version. If it is older than the package you just
installed, the menu says so and offers to refresh the system copy and service
(one UAC prompt). Answer Enter, and it continues into the menu when the install
finishes.

## Moving to a laptop

1. Install there: `pip install -U usbkey-guard`, then `python -m usbkey_guard` and
   accept the Administrator prompt.
2. Plug in the same stick and open the menu. When it finds the existing key file,
   choose **USE** — never **OVERWRITE**, which would lock your old vaults for good.
3. Copy the encrypted folder over, then
   `python -m usbkey_guard vault attach --vault-dir D:\Private.vault --work-dir C:\Users\me\Private`
   and unlock with your passphrase.

The stick works on both machines; nothing secret is copied between them.

## If something goes wrong

- Wrong passphrase → refused with a clear message, nothing is written.
- Edited file at lock time → lock refuses to delete it; your changes are preserved.
- A file in the work folder that differs from the vault → unlock refuses to overwrite it
  and writes nothing at all. Move it aside, then unlock again (or `--force`).
- Want to stop protecting a vault → **8) Stop protecting a vault**, or
  `python -m usbkey_guard vault remove --vault-id <id> --yes`. Files become ordinary files.
- Reinstalled machine → `python -m usbkey_guard vault attach --vault-dir D:\Private.vault`, then unlock.
- Lost stick → there is no recovery. Keep a second copy of `key.dat` on a spare stick
  and keep your passphrase somewhere safe.
