r"""Adopting a stick that already carries key.dat (second PC) must not rewrite it."""
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from usbkey_guard import keystore

GUID = "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\"
SERIAL = "123456789"


@pytest.fixture
def stick(tmp_path, monkeypatch, isolated_state):
    ident = {"drive": str(tmp_path) + "\\", "volume_guid": GUID, "serial": SERIAL}
    monkeypatch.setattr(keystore, "drive_identity", lambda drive: dict(ident))
    return tmp_path, ident


def test_adopt_keeps_the_existing_key_file(stick):
    folder, ident = stick
    keystore.enroll(str(folder))
    key = folder / "key.dat"
    before = key.read_bytes()

    result = keystore.adopt(str(folder))

    assert result["identity"]["volume_guid"] == ident["volume_guid"]
    assert result["identity"]["serial"] == ident["serial"]
    assert key.read_bytes() == before, "adopt must never rewrite key.dat"
    assert result["previous_key_backup"] is None


def test_adopt_refuses_a_key_copied_from_another_stick(stick, monkeypatch):
    folder, _ = stick
    keystore.enroll(str(folder))

    other = {"drive": str(folder) + "\\", "volume_guid": GUID,
             "serial": "987654321"}
    monkeypatch.setattr(keystore, "drive_identity", lambda drive: dict(other))
    with pytest.raises(ValueError, match="different stick"):
        keystore.adopt(str(folder))


def test_adopt_accepts_the_same_stick_on_a_second_pc(stick, monkeypatch):
    """Windows reports a different volume GUID on every PC for the same stick."""
    folder, _ = stick
    keystore.enroll(str(folder))
    key = folder / "key.dat"
    before = key.read_bytes()

    second = {"drive": str(folder) + "\\",
              "volume_guid": "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\",
              "serial": SERIAL}
    monkeypatch.setattr(keystore, "drive_identity", lambda drive: dict(second))

    result = keystore.adopt(str(folder))
    assert result["identity"]["volume_guid"] == second["volume_guid"]
    assert result["identity"]["serial"] == SERIAL
    assert key.read_bytes() == before, "adopt must never rewrite key.dat"


def test_adopt_accepts_a_legacy_key_from_another_pc(stick, monkeypatch):
    """Version 1 files stored the enrolling PC's GUID; use it, not this PC's."""
    folder, _ = stick
    salt = b"0123456789abcdef"
    secret = "ab" * 32
    old = {"volume_guid": "\\\\?\\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\\",
           "serial": SERIAL}
    derived = keystore._derive(secret, old, salt)
    verifier = hmac.new(derived, keystore.PRESENCE_TAG_V1,
                        hashlib.sha256).hexdigest()
    (folder / "key.dat").write_text(json.dumps({
        "v": 1, "secret": secret, "salt": salt.hex(), "verifier": verifier,
        "volume_guid": old["volume_guid"], "serial": SERIAL,
    }), encoding="utf-8")

    assert keystore.adopt(str(folder))["key_file"].endswith("key.dat")
    assert keystore.verify(str(folder), {"serial": SERIAL, "volume_guid": GUID})


def test_verify_ignores_the_machine_specific_guid(stick):
    folder, _ = stick
    keystore.enroll(str(folder))
    assert keystore.verify(str(folder), {"serial": SERIAL,
                                         "volume_guid": "another-pc"})


def test_adopt_detects_a_tampered_key_file(stick):
    folder, _ = stick
    keystore.enroll(str(folder))
    key = folder / "key.dat"
    doc = json.loads(key.read_text(encoding="utf-8"))
    doc["secret"] = "00" * 32
    key.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(ValueError, match="integrity check"):
        keystore.adopt(str(folder))


def test_adopt_requires_a_key_file(stick):
    folder, _ = stick
    with pytest.raises(FileNotFoundError, match="key.dat"):
        keystore.adopt(str(folder))


def test_adopt_rejects_an_unknown_key_format(stick):
    folder, _ = stick
    (folder / "key.dat").write_text(json.dumps({"v": 99}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        keystore.adopt(str(folder))


def test_enroll_still_refuses_to_overwrite_without_replace(stick):
    folder, _ = stick
    keystore.enroll(str(folder))
    before = (folder / "key.dat").read_bytes()
    with pytest.raises(FileExistsError):
        keystore.enroll(str(folder))
    assert (folder / "key.dat").read_bytes() == before


def test_replace_refuses_when_the_old_key_cannot_be_backed_up(stick, monkeypatch):
    folder, _ = stick
    keystore.enroll(str(folder))
    before = (folder / "key.dat").read_bytes()
    monkeypatch.setattr(keystore, "_backup_existing_key", lambda path: None)
    with pytest.raises(PermissionError, match="refusing to overwrite"):
        keystore.enroll(str(folder), replace=True)
    assert (folder / "key.dat").read_bytes() == before


def test_replace_backs_up_the_old_key(stick):
    folder, _ = stick
    keystore.enroll(str(folder))
    old = (folder / "key.dat").read_bytes()
    result = keystore.enroll(str(folder), replace=True)
    backup = Path(result["previous_key_backup"])
    assert backup.read_bytes() == old
    assert (folder / "key.dat").read_bytes() != old
