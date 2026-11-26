r"""Crash-recovery tests: every mutation must reconcile from the WAL."""
import pytest

from usbkey_guard import acl, enforce, journal, paths, snapshot
from usbkey_guard.errors import JournalUnreconciled


@pytest.fixture
def protected_root(isolated_state, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "protected_prefixes", lambda: [])
    folder = tmp_path / "private"
    folder.mkdir()
    (folder / "sample.txt").write_text("data", encoding="utf-8")
    target = str(folder)
    enforce.add_root(target)
    yield target
    try:
        enforce.unlock_all(force=True)
    except Exception:
        snap = snapshot.load(snapshot.root_id(target))
        snapshot.restore(target, snap)


def test_replay_rolls_forward_lock_after_crash(protected_root):
    rid = snapshot.root_id(protected_root)
    j = journal.Journal()
    j.intent("lock", rid, protected_root, snapshot.load(rid), {})
    assert not acl.is_locked(protected_root)

    notes = enforce.replay()
    assert notes and "lock" in notes[0]
    assert acl.is_locked(protected_root)
    assert j.unreconciled() == []
    assert enforce.verify() == []


def test_replay_completes_unlock_after_crash(protected_root):
    rid = snapshot.root_id(protected_root)
    j = journal.Journal()
    enforce.lock_all()
    j.intent("unlock", rid, protected_root, {}, {})

    notes = enforce.replay()
    assert notes and "unlock" in notes[0]
    assert not acl.is_locked(protected_root)
    assert j.unreconciled() == []


def test_replay_fails_closed_when_snapshot_missing(protected_root):
    rid = snapshot.root_id(protected_root)
    j = journal.Journal()
    snap = snapshot.load(rid)
    acl.apply_lock(protected_root, snap)
    (snapshot._backup_dir(rid) / "meta.json").unlink()
    j.intent("unlock", rid, protected_root, {}, {})

    with pytest.raises(JournalUnreconciled):
        enforce.replay()
    assert acl.is_locked(protected_root)
    snapshot.restore(protected_root, snap)
    assert not acl.is_locked(protected_root)
