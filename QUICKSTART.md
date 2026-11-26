# Quick start

1. Plug in the USB stick you want to use as the key.
2. Run `usbkey-tui`.
3. If asked, select the removable drive from the list. This writes `key.dat` to it.
4. Choose **3) Encrypt a file or folder**.
   - Enter the path, e.g. `D:\Private`
   - Enter or accept the vault destination, e.g. `D:\Private.vault`
   - Enter and confirm a passphrase
   - Type `YES`
5. The original files vanish from `D:\Private`. Only ciphertext remains in the vault.
6. Choose **4) Unlock a vault**, select it, enter the passphrase. Files return.
7. Unplug the USB stick. Within ~5 seconds the decrypted files are wiped again.
8. Plug it back in. Files stay gone until you unlock with the passphrase again.

## Everyday commands

```
usbkey status              # key present? vaults locked?
usbkey vault verify        # integrity check
usbkey export-recovery D:\Recovery   # bundle to keep OFF this machine
```

## If something goes wrong

- Wrong passphrase → `InvalidTag`, nothing is written.
- Edited file at lock time → lock refuses to delete it; your changes are preserved.
- A file in the work folder that differs from the vault → unlock refuses to overwrite it
  and writes nothing at all. Move it aside, then unlock again (or `--force`).
- Reinstalled machine → `usbkey vault attach D:\Private.vault`, then unlock.
- Lost stick → there is no recovery. Keep a second copy of `key.dat` on a spare stick
  and keep your passphrase somewhere safe.
