import pytest

from usbkey_guard import paths


def test_drive_roots_are_refused():
    for root in paths.drive_roots():
        assert root in paths.denylist_hits(root)


def test_windows_directories_are_refused():
    for prefix in (r"C:\Windows", r"C:\Program Files", r"C:\ProgramData"):
        hits = {paths.norm(h) for h in paths.denylist_hits(prefix)}
        assert paths.norm(prefix) in hits


def test_normal_path_passes_without_system_prefixes(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_prefixes", lambda: [])
    folder = tmp_path / "private"
    folder.mkdir()
    assert paths.denylist_hits(folder) == []
    paths.safe_target(folder)


def test_reparse_and_cloud_helpers_are_read_only(tmp_path):
    assert paths.reparse_components(tmp_path) == []
    assert paths.cloud_markers(tmp_path) == []
