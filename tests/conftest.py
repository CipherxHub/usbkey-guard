import pytest


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """Redirect all tool state to a temp dir; no real config/journal is touched."""
    import usbkey_guard.config as config
    import usbkey_guard.enforce as enforce
    import usbkey_guard.journal as journal
    import usbkey_guard.paths as paths
    import usbkey_guard.snapshot as snapshot
    import usbkey_guard.vault as vault

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(config, "INSTALL_ROOT", tmp_path / "install")
    monkeypatch.setattr(paths, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(vault, "CONFIG", tmp_path / "vaults.json")
    monkeypatch.setattr(vault, "BACKUP", tmp_path / "vault-backup")
    monkeypatch.setattr(journal, "WAL", tmp_path / "journal" / "wal.log")
    monkeypatch.setattr(journal, "STATE", tmp_path / "journal" / "state.json")
    monkeypatch.setattr(snapshot, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(enforce, "CONFIG", tmp_path / "config.json")
    return tmp_path

