r"""A vault must open on every PC where the stick verifies, not only the one that
created it. Windows reports a different volume GUID for the same stick on each
machine, so the GUID must never be part of the vault key."""
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from usbkey_guard import vault

SECRET = b"stick-secret"
SERIAL = "312070887"
SALT = b"0123456789abcdef"


def _ident(guid, key_guid=None):
    ident = {"volume_guid": guid, "serial": SERIAL}
    if key_guid is not None:
        ident["key_guid"] = key_guid
    return ident


def _stick(monkeypatch, ident):
    monkeypatch.setattr(vault, "_usb_material", lambda: (SECRET, dict(ident)))


def _legacy_vault(root: Path, work: Path, key: bytes) -> None:
    """A pre-1.0.12 vault: GUID material, no "bind" marker."""
    vdir = root / "v"
    (vdir / "data").mkdir(parents=True)
    rel = "a.txt"
    data = b"hello"
    nonce = os.urandom(vault.NONCE_LEN)
    enc = nonce + AESGCM(key).encrypt(nonce, data, rel.encode("utf-8"))
    (vdir / "data" / "00000.enc").write_bytes(enc)
    manifest = {
        "v": 1, "id": "legacy1", "work_dir": str(work), "vault_dir": str(vdir),
        "salt": SALT.hex(), "created": "2026-01-01T00:00:00Z",
        "files": [{
            "rel": rel, "enc": "00000.enc", "nonce": nonce.hex(),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "enc_sha256": hashlib.sha256(enc).hexdigest(),
        }],
    }
    (vdir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    vault._write_config({"vaults": [{
        "id": "legacy1", "work_dir": str(work), "vault_dir": str(vdir),
        "source_file": None,
    }]})


def test_new_vault_key_ignores_the_machine_guid(monkeypatch, isolated_state):
    _stick(monkeypatch, _ident("PC-A"))
    a = vault.derive_key("p", SALT, vault.KDF_DEFAULT, vault.KDF_BIND)
    _stick(monkeypatch, _ident("PC-B"))
    b = vault.derive_key("p", SALT, vault.KDF_DEFAULT, vault.KDF_BIND)
    assert a == b


def test_legacy_candidates_try_this_pc_then_the_enrolling_pc(monkeypatch,
                                                              isolated_state):
    key_b = vault._derive("p", SECRET, _ident("PC-B"), SALT, None, None, "PC-B")
    key_a = vault._derive("p", SECRET, _ident("PC-A"), SALT, None, None, "PC-A")
    assert key_a != key_b
    _stick(monkeypatch, _ident("PC-B", key_guid="PC-A"))
    assert vault._candidate_keys("p", {"salt": SALT.hex()}) == [key_b, key_a]


def test_legacy_vault_opens_on_a_second_pc(monkeypatch, isolated_state, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    key_a = vault._derive("p", SECRET, _ident("PC-A"), SALT, None, None, "PC-A")
    _legacy_vault(tmp_path, work, key_a)

    _stick(monkeypatch, _ident("PC-B", key_guid="PC-A"))
    assert vault.unlock("legacy1", passphrase="p") == ["a.txt"]
    assert (work / "a.txt").read_bytes() == b"hello"


def test_legacy_vault_still_refuses_a_wrong_passphrase(monkeypatch, isolated_state,
                                                       tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    key_a = vault._derive("p", SECRET, _ident("PC-A"), SALT, None, None, "PC-A")
    _legacy_vault(tmp_path, work, key_a)

    _stick(monkeypatch, _ident("PC-B", key_guid="PC-A"))
    with pytest.raises(RuntimeError, match="wrong passphrase"):
        vault.unlock("legacy1", passphrase="nope")
    assert not (work / "a.txt").exists()


def test_new_vault_opens_after_the_guid_changes(monkeypatch, isolated_state,
                                                tmp_path):
    _stick(monkeypatch, _ident("PC-A"))
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.txt").write_text("hello", encoding="utf-8")

    manifest = vault.convert(str(work / "a.txt"), str(tmp_path / "v"),
                             passphrase="p", yes=True)
    assert manifest["bind"] == vault.KDF_BIND
    assert not (work / "a.txt").exists(), "convert removes the plaintext"

    _stick(monkeypatch, _ident("PC-B"))
    assert vault.unlock(manifest["id"], passphrase="p") == ["a.txt"]
    assert (work / "a.txt").read_text(encoding="utf-8") == "hello"
