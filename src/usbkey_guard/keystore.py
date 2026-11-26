r"""USB identity and key verification using stdlib scrypt (no native extension).

key.dat lives on the stick and is bound to that stick's volume GUID + serial,
so copying the file to another stick does not work. This is a presence token,
not encryption: no key material is stored on the PC.
"""
import hashlib
import hmac
import json
import os
import secrets
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


def enroll(drive: str) -> dict[str, Any]:
    ident = drive_identity(drive)
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
    path = Path(ident["drive"]) / KEY_NAME
    if path.exists():
        raise FileExistsError("refusing to overwrite existing " + str(path))
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _log.info("enrolled stick %s serial=%s", ident["drive"], redact(ident["serial"]))
    return {"identity": ident, "key_file": str(path)}


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
    raw = win32api.GetLogicalDriveStrings()
    drives = [d for d in raw.split("\x00") if d]
    for drive in drives:
        try:
            if verify(drive, expected):
                return drive
        except Exception:
            continue
    return None
