"""Local users must be able to update the state files (they hold no keys)."""
import win32security

from usbkey_guard import acl

FILE_WRITE_DATA = 0x0002


def _explicit_users_mask(path) -> int:
    sd = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = sd.GetSecurityDescriptorDacl()
    mask = 0
    for i in range(dacl.GetAceCount()):
        (ace_type, flags), ace_mask, sid = dacl.GetAce(i)
        if flags & win32security.INHERITED_ACE:
            continue
        if ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE:
            continue
        if win32security.ConvertSidToStringSid(sid) != acl.USERS_SID:
            continue
        mask |= ace_mask
    return mask


def test_allow_state_writes_makes_existing_files_writable(tmp_path):
    sub = tmp_path / "journal"
    sub.mkdir()
    files = [tmp_path / "vaults.json", tmp_path / "config.json", sub / "state.json"]
    for f in files:
        f.write_text("{}", encoding="utf-8")

    assert acl.allow_state_writes(str(tmp_path)) is True

    for f in files:
        assert _explicit_users_mask(f) & FILE_WRITE_DATA, f.name
    # Directories need the ACE to inherit, or new files stay read-only.
    assert _explicit_users_mask(tmp_path) & FILE_WRITE_DATA
    assert _explicit_users_mask(sub) & FILE_WRITE_DATA


def test_allow_state_writes_is_idempotent(tmp_path):
    target = tmp_path / "vaults.json"
    target.write_text("{}", encoding="utf-8")
    acl.allow_state_writes(str(tmp_path))
    first = _explicit_users_mask(target)
    acl.allow_state_writes(str(tmp_path))
    assert _explicit_users_mask(target) == first


def test_allow_state_writes_leaves_a_hardened_root_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(acl, "state_is_hardened", lambda path: True)

    def boom(*args, **kwargs):
        raise AssertionError("must not touch a hardened state root")

    monkeypatch.setattr(acl.subprocess, "run", boom)
    assert acl.allow_state_writes(str(tmp_path)) is False


def test_state_is_hardened_uses_the_marker_not_the_dacl(tmp_path):
    assert acl.state_is_hardened(str(tmp_path)) is False
    (tmp_path / ".hardened").write_text("x", encoding="utf-8")
    assert acl.state_is_hardened(str(tmp_path)) is True
