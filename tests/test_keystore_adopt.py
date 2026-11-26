r"""Adopting a stick that already carries key.dat (second PC) must not rewrite it."""
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

    other = {"drive": str(folder) + "\\",
             "volume_guid": "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\",
             "serial": SERIAL}
    monkeypatch.setattr(keystore, "drive_identity", lambda drive: dict(other))
    with pytest.raises(ValueError, match="different stick"):
        keystore.adopt(str(folder))


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
