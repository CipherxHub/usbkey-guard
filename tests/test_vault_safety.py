r"""Regression tests for the data-safety and path-traversal fixes."""
import json
import shutil
from pathlib import Path

import pytest

from usbkey_guard import enforce, paths, vault
from usbkey_guard.errors import ConfigCorrupt


@pytest.fixture
def keyed(isolated_state, monkeypatch):
    monkeypatch.setattr(
        vault, "_usb_material",
        lambda: (b"test-secret", {"volume_guid": "guid", "serial": "serial"}),
    )
    return vault


def _make(base: Path, files: dict[str, str]) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        target = base / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return base


# ---------------------------------------------------------------- path guards
def test_convert_refuses_os_owned_source(keyed, tmp_path, monkeypatch):
    windows = tmp_path / "fake-windows"
    data = _make(windows / "system32", {"kernel.dll": "x"})
    monkeypatch.setattr(paths, "_system_prefixes", lambda: [paths.norm(windows)])

    with pytest.raises(ValueError, match="protected system path"):
        keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)
    assert (data / "kernel.dll").exists(), "plaintext must be untouched"


def test_convert_refuses_drive_root(keyed, tmp_path):
    with pytest.raises(ValueError, match="drive roots"):
        keyed.convert(str(Path(tmp_path.anchor)), str(tmp_path / "v"),
                      passphrase="p", yes=True)


def test_convert_refuses_vault_inside_source(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "a"})
    with pytest.raises(ValueError, match="overlap"):
        keyed.convert(str(data), str(data / "vault"), passphrase="p", yes=True)
    assert (data / "a.txt").exists()


def test_convert_refuses_source_inside_vault(keyed, tmp_path):
    data = _make(tmp_path / "outer" / "data", {"a.txt": "a"})
    with pytest.raises(ValueError, match="overlap"):
        keyed.convert(str(data), str(tmp_path / "outer"), passphrase="p", yes=True)
    assert (data / "a.txt").exists()


def test_convert_refuses_reparse_point(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "a"})
    link = data / "link"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this account")
    with pytest.raises(ValueError, match="reparse point"):
        keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)
    assert (data / "a.txt").exists()


def test_convert_refuses_duplicate_vault_id(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "a"})
    keyed.convert(str(data), str(tmp_path / "v1"), passphrase="p", yes=True)
    # Simulate an emptied vault folder that is still registered.
    shutil.rmtree(tmp_path / "v1" / "data")
    (tmp_path / "v1" / "manifest.json").unlink()
    _make(data, {"a.txt": "a"})
    with pytest.raises(ValueError, match="already exists"):
        keyed.convert(str(data), str(tmp_path / "v1"), passphrase="p", yes=True)


# ------------------------------------------------------------- unlock safety
def test_unlock_refuses_to_overwrite_edited_plaintext(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "one", "b.txt": "two"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)
    keyed.unlock(m["id"], passphrase="p")

    (data / "a.txt").write_text("edited by the user", encoding="utf-8")
    (data / "b.txt").unlink()

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        keyed.unlock(m["id"], passphrase="p")

    assert (data / "a.txt").read_text(encoding="utf-8") == "edited by the user"
    assert not (data / "b.txt").exists(), "all-or-nothing: nothing else is written"


def test_unlock_is_all_or_nothing_on_corrupt_ciphertext(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "one", "b.txt": "two"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)
    assert not (data / "a.txt").exists()

    enc = sorted((tmp_path / "v" / "data").glob("*.enc"))[0]
    enc.write_bytes(b"corrupted" + enc.read_bytes()[9:])

    with pytest.raises(RuntimeError, match="integrity failure"):
        keyed.unlock(m["id"], passphrase="p")
    assert not (data / "a.txt").exists()
    assert not (data / "b.txt").exists()


def test_unlock_refuses_manifest_traversal(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "one"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)

    manifest_path = tmp_path / "v" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["rel"] = "../escaped.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(RuntimeError, match="escapes the work folder"):
        keyed.unlock(m["id"], passphrase="p")
    assert not (tmp_path / "escaped.txt").exists()


def test_unlock_restores_empty_directories(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "one"})
    (data / "empty" / "nested").mkdir(parents=True)
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)

    shutil.rmtree(data / "empty")
    keyed.unlock(m["id"], passphrase="p")
    assert (data / "empty" / "nested").is_dir()


# --------------------------------------------------------------- lock safety
def test_lock_keeps_edited_files_and_removes_the_rest(keyed, tmp_path):
    data = _make(tmp_path / "data", {"a.txt": "one", "b.txt": "two"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)
    keyed.unlock(m["id"], passphrase="p")

    (data / "a.txt").write_text("edited", encoding="utf-8")
    with pytest.raises(RuntimeError, match="not deleting"):
        keyed.lock(m["id"])

    assert (data / "a.txt").read_text(encoding="utf-8") == "edited"
    assert not (data / "b.txt").exists()


# ------------------------------------------------------------- state safety
def test_corrupt_vault_config_is_reported_not_reset(keyed, tmp_path):
    keyed.CONFIG.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(ConfigCorrupt):
        keyed.list_vaults()
    assert keyed.CONFIG.read_text(encoding="utf-8") == "{ this is not json"
    backups = list(tmp_path.glob("vaults.json.corrupt-*"))
    assert backups, "a copy of the corrupt file must be preserved"


def test_corrupt_enforce_config_is_reported_not_reset(isolated_state):
    enforce.CONFIG.write_text("not json at all", encoding="utf-8")
    with pytest.raises(ConfigCorrupt):
        enforce.load_config()
    assert enforce.CONFIG.read_text(encoding="utf-8") == "not json at all"


def test_remove_root_refuses_while_locked(isolated_state, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_prefixes", lambda: [])
    folder = tmp_path / "private"
    folder.mkdir()
    (folder / "x.txt").write_text("x", encoding="utf-8")
    root = enforce.add_root(str(folder))
    enforce.lock_all()
    try:
        with pytest.raises(ValueError, match="refusing to remove a locked root"):
            enforce.remove_root(root["id"])
        assert enforce.load_config()["roots"], "root must still be registered"
    finally:
        enforce.unlock_all(force=True)


def test_manifest_rejects_absolute_and_parent_paths(tmp_path):
    with pytest.raises(RuntimeError):
        vault._safe_join(tmp_path, r"C:\Windows\System32\drivers\etc\hosts")
    with pytest.raises(RuntimeError):
        vault._safe_join(tmp_path, "..\\..\\outside.txt")
    assert vault._safe_join(tmp_path, "sub\\file.txt") == tmp_path / "sub" / "file.txt"


def test_vault_destination_refuses_tool_state(keyed, tmp_path, isolated_state):
    data = _make(tmp_path / "data", {"a.txt": "a"})
    target = isolated_state / "state" / "journal" / "sneaky"
    with pytest.raises(ValueError, match="protected system path"):
        keyed.convert(str(data), str(target), passphrase="p", yes=True)
    assert (data / "a.txt").exists()


# ------------------------------------------------------------------ kdf
def test_legacy_manifests_derive_the_original_key(keyed):
    salt = b"0123456789abcdef"
    assert vault._kdf_params(None) == (2 ** 14, 8, 1)
    assert vault.derive_key("p", salt) == vault.derive_key("p", salt, vault.KDF_DEFAULT)


def test_hostile_kdf_parameters_are_clamped():
    assert vault._kdf_params({"n": 2 ** 40, "r": 4096, "p": 99}) == (2 ** 20, 32, 4)
    assert vault._kdf_params({"n": 1, "r": 1, "p": 0}) == (2 ** 14, 8, 1)
    assert vault._kdf_params("not a dict") == (2 ** 14, 8, 1)


# ------------------------------------------------------- manifest trust
def test_manifest_rejects_reserved_device_names(tmp_path):
    for name in ("CON", "nul.txt", "com1", "LPT9.log"):
        with pytest.raises(RuntimeError, match="reserved device"):
            vault._safe_join(tmp_path, name)
    assert vault._safe_join(tmp_path, "console.txt") == tmp_path / "console.txt"


def test_unlock_refuses_a_tampered_work_dir(keyed, tmp_path, monkeypatch):
    data = _make(tmp_path / "data", {"a.txt": "one"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)

    fake = tmp_path / "fake-windows"
    cfg = json.loads(keyed.CONFIG.read_text(encoding="utf-8"))
    cfg["vaults"][0]["work_dir"] = str(fake)
    keyed.CONFIG.write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setattr(paths, "_system_prefixes", lambda: [paths.norm(fake)])

    with pytest.raises(ValueError, match="protected system path"):
        keyed.unlock(m["id"], passphrase="p")
    assert not (fake / "a.txt").exists()


def _write_manifest(folder: Path, work: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "manifest.json").write_text(json.dumps({
        "v": 1,
        "id": "deadbeefdeadbeef",
        "work_dir": str(work),
        "vault_dir": str(folder),
        "salt": "00" * 16,
        "files": [{
            "rel": "a.txt", "enc": "00000.enc", "nonce": "00" * 12,
            "size": 1, "sha256": "00" * 32, "enc_sha256": "00" * 32,
        }],
    }), encoding="utf-8")
    return folder


def test_attach_requires_a_manifest(tmp_path):
    with pytest.raises(ValueError, match="not a vault"):
        vault.attach(str(tmp_path / "empty"))


def test_attach_refuses_a_manifest_pointing_at_system_paths(tmp_path, monkeypatch):
    fake = tmp_path / "fake-windows"
    vdir = _write_manifest(tmp_path / "v", fake / "system32")
    monkeypatch.setattr(paths, "_system_prefixes", lambda: [paths.norm(fake)])
    with pytest.raises(ValueError, match="protected system path"):
        vault.attach(str(vdir))


def test_safe_vault_source_refuses_all_user_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "users" / "me"))
    (tmp_path / "users").mkdir()
    with pytest.raises(ValueError, match="all user profiles"):
        paths.safe_vault_source(tmp_path / "users")


def test_vaults_made_before_1_0_2_still_unlock(keyed, tmp_path, monkeypatch):
    """A 1.0.1 manifest has no "kdf" key and used n=2**14; it must keep working."""
    monkeypatch.setattr(vault, "KDF_NEW", dict(vault.KDF_DEFAULT))
    data = _make(tmp_path / "data", {"a.txt": "one"})
    m = keyed.convert(str(data), str(tmp_path / "v"), passphrase="p", yes=True)

    manifest_path = tmp_path / "v" / "manifest.json"
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    doc.pop("kdf", None)
    manifest_path.write_text(json.dumps(doc), encoding="utf-8")

    assert keyed.unlock(m["id"], passphrase="p") == ["a.txt"]
    assert (data / "a.txt").read_text(encoding="utf-8") == "one"
