r"""USB identity and key verification using stdlib scrypt (no native extension).

key.dat lives on the stick and is bound to that stick's volume GUID + serial,
so copying the file to another stick does not work. This is a presence token,
not encryption: no key material is stored on the PC.

Re-enrolling over an existing key.dat would permanently lock every vault that
was created with it, so the old file is copied into the state folder first and
overwriting requires an explicit `replace=True`.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import win32api
import win32file

from .log import get_log, redact

KEY_NAME = "key.dat"
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
_log = get_log("keystore")


def drive_identity(drive: str) -> dict[str, str]:
    root = drive.rstrip("\\") + "\\"
    serial = str(win32api.GetVolumeInformation(root)[1])
    guid = str(win32file.GetVolumeNameForVolumeMountPoint(root)).rstrip("\\")
    return {"drive": root, "volume_guid": guid, "serial": serial}


def _derive(secret: str, identity: dict[str, str], salt: bytes) -> bytes:
    material = (secret + "|" + identity["volume_guid"] + "|" + identity["serial"]).encode()
    return hashlib.scrypt(
        material, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


def _write_durable(path: Path, data: bytes) -> None:
    """Flush the key file to the stick before reporting success."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to " + str(path))
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup_existing_key(path: Path) -> Path | None:
    """Copy the current key.dat into the state folder before it is replaced."""
    try:
        from . import config
        dest = Path(config.STATE_ROOT) / "keystore-backup"
        dest.mkdir(parents=True, exist_ok=True)
        target = dest / f"key-{time.strftime('%Y%m%d-%H%M%S')}.dat"
        target.write_bytes(path.read_bytes())
        return target
    except OSError as exc:
        _log.error("could not back up existing key file: %s", exc)
        return None


def enroll(drive: str, replace: bool = False) -> dict[str, Any]:
    ident = drive_identity(drive)
    path = Path(ident["drive"]) / KEY_NAME
    backup = None
    if path.exists():
        if not replace:
            raise FileExistsError(
                "refusing to overwrite existing " + str(path)
                + " (re-enrolling would lock every vault made with the old key)"
            )
        backup = _backup_existing_key(path)
    secret = secrets.token_hex(32)
    salt = secrets.token_bytes(16)
    derived = _derive(secret, ident, salt)
    verifier = hmac.new(derived, b"usbkey-presence-v1", hashlib.sha256).hexdigest()
    payload = {
        "v": 1,
        "secret": secret,
        "salt": salt.hex(),
        "verifier": verifier,
        "volume_guid": ident["volume_guid"],
        "serial": ident["serial"],
    }
    _write_durable(path, json.dumps(payload, indent=2).encode("utf-8"))
    _log.info("enrolled stick %s serial=%s", ident["drive"], redact(ident["serial"]))
    return {"identity": ident, "key_file": str(path), "previous_key_backup": backup}


def verify(drive: str, expected: dict[str, str]) -> bool:
    try:
        ident = drive_identity(drive)
    except Exception:
        return False
    if ident["volume_guid"] != expected.get("volume_guid"):
        return False
    if ident["serial"] != expected.get("serial"):
        return False
    path = Path(ident["drive"]) / KEY_NAME
    if not path.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        derived = _derive(payload["secret"], ident, bytes.fromhex(payload["salt"]))
        computed = hmac.new(derived, b"usbkey-presence-v1", hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, payload["verifier"])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def find_key(expected: dict[str, str]) -> str | None:
    if not expected:
        return None
    raw = win32api.GetLogicalDriveStrings()
    drives = [d for d in raw.split("\x00") if d]
    for drive in drives:
        try:
            if verify(drive, expected):
                return drive
        except Exception:
            continue
    return None
