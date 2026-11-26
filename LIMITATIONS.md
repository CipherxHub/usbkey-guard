# What this does and does not protect

## Protects against

- Someone opening your files when the USB stick is not plugged in
- Someone with administrator rights reading the files at rest (they get ciphertext)
- Someone copying the encrypted folder to another machine (no stick + passphrase = no data)
- Accidental data loss: verified encryption before plaintext removal, journaled metadata,
  refusal to delete edited files

## Does not protect against

- A keylogger or screen capture while the vault is unlocked
- Copying an already-decrypted file while the vault is unlocked
- Someone with your passphrase **and** your USB stick
- Deleting or formatting the encrypted vault (that destroys data, but reveals nothing)
- Hardware-level attacks, cold-boot attacks, or a compromised operating system

## Locking depends on the background service

Encrypting on demand works from the TUI alone, but re-locking after the stick is
pulled is done by `usbkey-enforcer`, a SYSTEM scheduled task installed by the
one-time Administrator step the menu offers on first start (or explicitly by
`python -m usbkey_guard.setup_app install`). Without it, an unlocked folder stays
readable. Check with `python -m usbkey_guard.setup_app status`
(`Service: running`) and `python -m usbkey_guard status`.

The task starts at boot and again at every logon, ignores battery/AC state and
has no execution time limit (1.0.11 and later). Installs before 1.0.11 inherited
Windows' "start only on AC power" default, which is why a laptop could boot
without the service; running install again repairs the task.

The task runs the Python that performed the install. If that Python is inside a
user profile, only that account can start the TUI from the Start menu; the
service itself still runs as SYSTEM. Use a machine-wide Python on a shared PC.

The installed copy is a snapshot. After `pip install -U usbkey-guard`, open
`python -m usbkey_guard` once so it can refresh the system copy; the menu
detects the version difference and offers to do it.

## Removing protection

`usbkey vault remove --vault-id <id> --yes` (TUI: *Stop protecting a vault*) decrypts
every file for good and then deletes the encrypted copy. It needs the stick and the
passphrase, and it refuses to run if a file was edited after unlock, so it can never
replace your newer work. Add `--keep-ciphertext` to keep the encrypted folder as a
backup; it can be re-attached later. Deleting the vault folder yourself has the same
effect on the ciphertext, but loses the ability to recover it.

## Why not just permissions?

NTFS permissions can always be overridden by an administrator taking ownership. Encryption
cannot: without the key, the bytes are meaningless. The optional ACL enforcement remains
available for folders that are not encrypted, but it is only a deterrent.

## Key binding

`key.dat` contains a random secret. New vaults derive their key with scrypt from
`passphrase + USB secret + volume serial`, so the same stick opens the same vault on
every PC. `key.dat` is bound to the stick's on-disk serial: copying it to a different
stick does not work. A determined attacker could clone a stick's serial; a hardware
token would be needed to prevent that.

Windows reports a different *volume GUID* for the same stick on every PC (it keeps
them in the per-machine mount-manager database), so the GUID is not used for the
binding. Vaults made before 1.0.11 mixed that GUID into the key. They still open on the
PC that created them, and on another PC when `key.dat` still carries the enrolling PC's
GUID, which is the usual case after `USE`.

Re-enrolling a stick that already holds `key.dat` is refused unless you explicitly confirm
overwriting it, because the old key is the only thing that can decrypt vaults made with it.
The previous file is copied to `%PROGRAMDATA%\usbkey\keystore-backup` first. If you chose
**OVERWRITE** by mistake, copy the newest `key-*.dat` from that folder (on the PC where you
chose it) back to the stick as `key.dat`: the old vaults become readable again.

On a second PC, **adopt** the existing key instead of overwriting it: `USE` in the TUI, or
`usbkey enroll --drive E:\ --use-existing`. That registers the stick locally without
touching `key.dat`, so vaults made on the first machine stay readable. Copying `key.dat`
to a different stick still does not work, because the key is bound to the original
volume serial.

## State folder

`%PROGRAMDATA%\usbkey` holds only metadata: volume identity, vault paths, salts, hashes and
ACL snapshots. It never holds a key or a passphrase. It is writable by local users so that a
normal, non-elevated TUI session can register, unlock and release vaults; run
`usbkey-setup harden` if you would rather trade that for admin-only vault management.

What a local user could do with that write access: change vault registrations, delete the
journal or logs, or add an ACL root that the SYSTEM enforcer would then apply. None of that
reveals plaintext, because the vault key is derived from the passphrase plus the stick and is
never stored. It is an availability and audit-trail concern, not a confidentiality one.

If an older install reports `Access is denied ... vaults.json`, its files were written by
SYSTEM or an elevated session and only administrators can modify them. Fix it once with
`usbkey-setup repair-permissions` from an Administrator prompt (1.0.6 and later).

## Vault folders you did not create

`usbkey vault attach` validates the manifest before registering it. The folder it restores
into must not be a system path, a drive root, a reparse point or the tool's own state, and
every file entry must stay inside that folder. A vault handed to you by someone else still
only contains ciphertext until you supply your own stick and passphrase, so attaching one
cannot decrypt anything by itself.
