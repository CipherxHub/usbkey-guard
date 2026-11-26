r"""Single-file vaults in the same folder must not collide on vault id."""


def test_two_files_in_same_folder_get_distinct_ids(isolated_state, monkeypatch):
    from pathlib import Path

    from usbkey_guard import vault

    monkeypatch.setattr(
        vault, "_usb_material",
        lambda: (b"test-secret", {"volume_guid": "guid", "serial": "serial"}),
    )
    base = Path(isolated_state) / "work"
    base.mkdir()
    (base / "a.txt").write_text("aaa", encoding="utf-8")
    (base / "b.txt").write_text("bbb", encoding="utf-8")

    a = vault.convert(str(base / "a.txt"), str(Path(isolated_state) / "va"),
                      passphrase="p", yes=True)
    b = vault.convert(str(base / "b.txt"), str(Path(isolated_state) / "vb"),
                      passphrase="p", yes=True)

    assert a["id"] != b["id"]
    assert a["source_file"].endswith("a.txt")
    assert b["source_file"].endswith("b.txt")
    assert not (base / "a.txt").exists()
    assert not (base / "b.txt").exists()

    vault.unlock(b["id"], passphrase="p")
    assert (base / "b.txt").read_text(encoding="utf-8") == "bbb"
    assert not (base / "a.txt").exists()

