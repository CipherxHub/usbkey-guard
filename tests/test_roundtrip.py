r"""ACL round-trip on a temporary folder. No machine-specific accounts needed."""
import pytest

from usbkey_guard import acl, enforce, paths, snapshot


@pytest.fixture
def protected_root(isolated_state, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_prefixes", lambda: [])
    folder = tmp_path / "private"
    folder.mkdir()
    (folder / "sample.txt").write_text("harmless test data", encoding="utf-8")
    target = str(folder)
    enforce.add_root(target)
    try:
        yield target
    finally:
        try:
            enforce.unlock_all(force=True)
        except Exception:
            snap = snapshot.load(snapshot.root_id(target))
            snapshot.restore(target, snap)


def test_lock_unlock_roundtrip(protected_root):
    assert not acl.is_locked(protected_root)
    assert enforce.lock_all() == ["LOCKED " + protected_root]
    assert acl.is_locked(protected_root)
    assert enforce.verify() == []

    assert enforce.unlock_all(force=True) == ["UNLOCKED " + protected_root]
    assert not acl.is_locked(protected_root)
    assert enforce.verify() == []


def test_lock_is_idempotent(protected_root):
    enforce.lock_all()
    assert enforce.lock_all() == []
    enforce.unlock_all(force=True)
    assert enforce.unlock_all(force=True) == []
