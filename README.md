# usbkey-guard

Headless Windows tool that keeps files locked unless a specific USB stick is inserted.
Files are encrypted with AES-GCM, so even an administrator cannot read them without
the USB key **and** your passphrase.

Interactive menu: `python -m usbkey_guard` (also `usbkey-tui`)
Scriptable CLI: `usbkey`

## Quick start

```powershell
pip install -U usbkey-guard
python -m usbkey_guard
```

That is all. On first start the menu offers the one-time Administrator step —
press Enter and approve UAC; the menu waits for it and carries on in the same
window. It installs the all-users Start menu entry and the background service
that re-encrypts folders when the stick is pulled. No separate setup command.

To install from a downloaded source zip instead:

```powershell
cd <extracted source folder>
pip install .
python -m usbkey_guard
```

The menu walks you through:
1. accepting the Administrator step (once per PC),
2. selecting and enrolling a USB drive,
3. choosing a file or folder to encrypt,
4. setting a passphrase,
5. unlocking later with the stick + passphrase.

Menu option 11 removes the tool from the PC in one step; it refuses while a
vault is still registered, so encrypted data can never be stranded.

See `INSTALL.md`, `QUICKSTART.md` and `LIMITATIONS.md`.

## Safety

Encryption is written and verified before any plaintext is removed. Locking never deletes
a file that changed since unlock. State is journaled with write-ahead records and can be
reconciled after a crash.

Guard rails that refuse to run instead of guessing:

- OS-owned trees (`Windows`, `Program Files`, `ProgramData`, the profiles root), drive
  roots, registry hives and the tool's own state are never encrypted.
- Reparse points/junctions are never followed, and the vault folder may not overlap the
  data being encrypted.
- A vault manifest that points outside its own work folder, at a reserved device name,
  or at a system path is rejected before a single byte is written.
- Unlock verifies every ciphertext first and refuses to overwrite files that differ from
  the vault (`--force` to override). Lock keeps changed files and reports them.
- Unprotecting a vault decrypts and verifies every file before the encrypted copy is
  deleted; it refuses if any file was edited after unlock.
- A corrupt state file is copied aside and reported; it is never silently reset.

This is protection **at rest**. It is not a defence against keyloggers, a copied already-
unlocked file, or an attacker with your passphrase.

## Command line

If `usbkey` is not on `PATH` (common with the new Python install manager), use
`python -m usbkey_guard` with the same arguments, e.g.
`python -m usbkey_guard status`.

```powershell
usbkey status
usbkey vault convert --work-dir D:\Private --vault-dir D:\Private.vault --yes
usbkey vault unlock --vault-id <id>            # passphrase is prompted, not echoed
usbkey vault lock
usbkey vault verify
usbkey vault remove --vault-id <id> --yes      # decrypt for good, stop protecting
usbkey export-recovery D:\Recovery
```

Second PC with the same stick:

```powershell
usbkey enroll --drive E:\ --use-existing       # keeps key.dat, old vaults stay readable
usbkey vault attach --vault-dir D:\Private.vault --work-dir C:\Users\me\Private
```

`--use-existing` never writes to the stick. `OVERWRITE` (or `--replace`) creates a
new secret and makes vaults made with the old key unreadable; the old key is saved
to `%PROGRAMDATA%\usbkey\keystore-backup` on that PC first.

Prefer the hidden prompt. `--passphrase-stdin` reads one line from stdin for scripts;
`--passphrase` still works but is visible to other users in the process list.
