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

## Why not just permissions?

NTFS permissions can always be overridden by an administrator taking ownership. Encryption
cannot: without the key, the bytes are meaningless. The optional ACL enforcement remains
available for folders that are not encrypted, but it is only a deterrent.

## Key binding

`key.dat` contains a random secret. The vault key is derived with scrypt from
`passphrase + USB secret + volume GUID + serial`. Copying `key.dat` to another stick
does not work because the derivation is bound to the original volume identity. A determined
attacker could clone the stick's identity; a hardware token would be needed to prevent that.

Re-enrolling a stick that already holds `key.dat` is refused unless you explicitly confirm
overwriting it, because the old key is the only thing that can decrypt vaults made with it.
The previous file is copied to `%PROGRAMDATA%\usbkey\keystore-backup` first, but that copy
only helps if you put it back on the same stick.

## State folder

`%PROGRAMDATA%\usbkey` holds only metadata: volume identity, vault paths, salts, hashes and
ACL snapshots. It never holds a key or a passphrase. It is writable by users by default so
that unprivileged users can create their own vaults; run `usbkey-setup harden` if you would
rather trade that for admin-only vault management.

## Vault folders you did not create

`usbkey vault attach` validates the manifest before registering it. The folder it restores
into must not be a system path, a drive root, a reparse point or the tool's own state, and
every file entry must stay inside that folder. A vault handed to you by someone else still
only contains ciphertext until you supply your own stick and passphrase, so attaching one
cannot decrypt anything by itself.
