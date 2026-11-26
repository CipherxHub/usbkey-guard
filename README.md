# usbkey-guard

Headless Windows tool that keeps files locked unless a specific USB stick is inserted.
Files are encrypted with AES-GCM, so even an administrator cannot read them without
the USB key **and** your passphrase.

Interactive TUI: `usbkey-tui`
Scriptable CLI: `usbkey`

## Quick start

```powershell
pip install usbkey-guard
usbkey-tui
```

To install from a downloaded source zip instead:

```powershell
cd <extracted source folder>
pip install .
usbkey-tui
```

The TUI walks you through:
1. selecting and enrolling a USB drive,
2. choosing a file or folder to encrypt,
3. setting a passphrase,
4. unlocking later with the stick + passphrase.

See `INSTALL.md`, `QUICKSTART.md` and `LIMITATIONS.md`.

## Safety

Encryption is written and verified before any plaintext is removed. Locking never deletes
a file that changed since unlock. State is journaled with write-ahead records and can be
reconciled after a crash.

This is protection **at rest**. It is not a defence against keyloggers, a copied already-
unlocked file, or an attacker with your passphrase.
