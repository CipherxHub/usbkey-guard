r"""USB identity and key verification using stdlib scrypt (no native extension).

key.dat lives on the stick and is bound to that stick's on-disk volume serial,
so copying the file to another stick does not work. This is a presence token,
not encryption: no key material is stored on the PC.

The volume GUID is deliberately *not* part of the binding. Windows keeps volume
GUIDs in the per-machine mount-manager database (HKLM\SYSTEM\MountedDevices),
so the same stick gets a different GUID on every PC. Binding to it made `USE`
refuse a perfectly good stick on a second PC, and it made vault keys depend on
the machine that created them. Version 2 key files bind to the serial only;
version 1 files still verify because the check uses the GUID stored inside the
file instead of the one this PC happens to report.

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
KEY_VERSION = 2
PRESENCE_TAG_V1 = b"usbkey-presence-v1"
PRESENCE_TAG_V2 = b"usbkey-presence-v2"
_log = get_log("keystore")


def drive_identity(drive: str) -> dict[str, str]:
    root = drive.rstrip("\\") + "\\"
    serial = str(win32api.GetVolumeInformation(root)[1])
    guid = str(win32file.GetVolumeNameForVolumeMountPoint(root)).rstrip("\\")
    return {"drive": root, "volume_guid": guid, "serial": serial}


def _derive(secret: str, identity: dict[str, str], salt: bytes) -> bytes:
    """Version 1 material: the GUID of the PC that enrolled the stick."""
    material = (secret + "|" + identity["volume_guid"] + "|" + identity["serial"]).encode()
    return hashlib.scrypt(
        material, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


def _derive_v2(secret: str, serial: str, salt: bytes) -> bytes:
    """Version 2 material: stable on disk, identical on every PC."""
    material = (secret + "|" + serial).encode()
    return hashlib.scrypt(
        material, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


def _stored_identity(payload: dict[str, Any]) -> dict[str, str]:
    """The identity recorded in key.dat, not the one this PC reports."""
    return {"volume_guid": str(payload.get("volume_guid", "")),
            "serial": str(payload.get("serial", ""))}


def _verifier(secret: str, payload: dict[str, Any]) -> str:
    salt = bytes.fromhex(payload["salt"])
    if int(payload.get("v", 1)) >= 2:
        derived = _derive_v2(secret, str(payload.get("serial", "")), salt)
        tag = PRESENCE_TAG_V2
    else:
        derived = _derive(secret, _stored_identity(payload), salt)
        tag = PRESENCE_TAG_V1
    return hmac.new(derived, tag, hashlib.sha256).hexdigest()


def _checks_out(payload: dict[str, Any]) -> bool:
    computed = _verifier(payload["secret"], payload)
    return hmac.compare_digest(computed, str(payload.get("verifier", "")))


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
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = dest / f"key-{stamp}.dat"
        suffix = 1
        while target.exists():
            target = dest / f"key-{stamp}-{suffix}.dat"
            suffix += 1
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
        if backup is None:
            # The backup is the only way back for vaults made with the old key.
            raise PermissionError(
                "could not back up the existing " + str(path)
                + "; refusing to overwrite the only key that can open the old "
                "vaults. Free space or run as Administrator, then retry."
            )
    secret = secrets.token_hex(32)
    salt = secrets.token_bytes(16)
    payload = {
        "v": KEY_VERSION,
        "secret": secret,
        "salt": salt.hex(),
        "serial": ident["serial"],
        # Informational only: the next PC reports a different GUID for the same
        # stick, so it must never be used to accept or reject a key file.
        "volume_guid": ident["volume_guid"],
    }
    payload["verifier"] = _verifier(secret, payload)
    _write_durable(path, json.dumps(payload, indent=2).encode("utf-8"))
    _log.info("enrolled stick %s serial=%s", ident["drive"], redact(ident["serial"]))
    return {"identity": ident, "key_file": str(path), "previous_key_backup": backup}


def adopt(drive: str) -> dict[str, Any]:
    """Register a stick that already carries key.dat, without rewriting it.

    This is the second-machine path: the file was created here or on another
    PC, and overwriting it would lock every vault made with that key.
    """
    ident = drive_identity(drive)
    path = Path(ident["drive"]) / KEY_NAME
    if not path.is_file():
        raise FileNotFoundError(
            "no " + KEY_NAME + " on " + str(path)
            + "; plug in the stick you already enrolled, or enroll a new one"
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("key file is unreadable: " + str(path)) from exc
    if not isinstance(payload, dict) or payload.get("v") not in (1, KEY_VERSION):
        raise ValueError("unsupported key file format: " + str(path))
    if str(payload.get("serial", "")) != ident["serial"]:
        raise ValueError(
            "that key file belongs to a different stick (serial "
            + str(payload.get("serial")) + ", this stick is " + ident["serial"]
            + "); use the original stick"
        )
    try:
        checked = _checks_out(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("key file is damaged: " + str(path)) from exc
    if not checked:
        raise ValueError("key file failed its integrity check: " + str(path))
    _log.info("adopted existing stick %s serial=%s", ident["drive"], redact(ident["serial"]))
    return {"identity": ident, "key_file": str(path), "previous_key_backup": None}


def verify(drive: str, expected: dict[str, str]) -> bool:
    try:
        ident = drive_identity(drive)
    except Exception:
        return False
    # Serial only: the volume GUID is per-machine and would reject the same
    # stick on a second PC.
    if expected.get("serial") and str(expected["serial"]) != ident["serial"]:
        return False
    path = Path(ident["drive"]) / KEY_NAME
    if not path.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return False
        if str(payload.get("serial", "")) != ident["serial"]:
            return False
        return _checks_out(payload)
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
