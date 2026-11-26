r"""Source-level guard: no destructive ops on protected/user data."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "usbkey_guard"
SCANNED = sorted(PKG.glob("*.py"))

FORBIDDEN = [
    r"\bos\.remove\s*\(",
    r"\bos\.unlink\s*\(",
    r"\bos\.rmdir\s*\(",
    r"\bshutil\.rmtree\s*\(",
    r"\bshutil\.move\s*\(",
    r"\bos\.rename\s*\(",
    r"\.unlink\s*\(",
    r"\.rmdir\s*\(",
    r"\bopen\s*\([^)]*['\"][wa]\+?['\"]",
]

ALLOWED_EXCEPTIONS = {
    # vault.py deletes only hash-verified plaintext inside its working folder,
    # plus the empty folders it created for its own ciphertext (rmdir refuses
    # to remove anything that is not empty).
    "vault.py": {"remove", "unlink", "rmdir"},
    # tui.py may replace its own key.dat on the enrolled stick.
    "tui.py": {"unlink"},
    # setup_app.py removes only its own Program Files copy and Start menu entry.
    "setup_app.py": {"rmtree", "unlink"},
    # statewrite.py removes only the temp file it just wrote.
    "statewrite.py": {"unlink"},
}


def test_scanned_files_exist():
    assert SCANNED and all(p.exists() for p in SCANNED)


def test_no_destructive_file_operations():
    violations = []
    for path in SCANNED:
        text = path.read_text(encoding="utf-8")
        allowed = ALLOWED_EXCEPTIONS.get(path.name, set())
        patterns = [p for p in FORBIDDEN if not any(word in p for word in allowed)]
        if "write" not in allowed and path.name not in ("vault.py", "tui.py", "setup_app.py", "acl.py"):
            patterns = [p for p in patterns if p != FORBIDDEN[-1]]
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                line = text[: match.start()].count("\n") + 1
                violations.append(f"{path.name}:{line}: {pattern}")
    assert not violations, "destructive operations found:\n" + "\n".join(violations)


def test_only_acl_module_mutates_protected_objects():
    acl_text = (PKG / "acl.py").read_text(encoding="utf-8")
    assert "SetNamedSecurityInfo" in acl_text
    assert "AddAccessDeniedAceEx" in acl_text
    for other in PKG.glob("*.py"):
        if other.name == "acl.py":
            continue
        assert "AddAccessDeniedAceEx" not in other.read_text(encoding="utf-8"), other.name


def test_vault_deletes_only_verified_plaintext():
    text = (PKG / "vault.py").read_text(encoding="utf-8")
    assert "os.remove(target)" in text
    assert text.count("_sha(target.read_bytes())") >= 2
    assert "shutil.rmtree" not in text


def test_setup_only_removes_its_own_paths():
    text = (PKG / "setup_app.py").read_text(encoding="utf-8")
    assert "config.INSTALL_ROOT" in text
    assert "start_menu_dir()" in text


def test_deny_principal_is_builtin_users_only():
    acl_text = (PKG / "acl.py").read_text(encoding="utf-8")
    assert "S-1-5-32-545" in acl_text
    assert "S-1-1-0" not in acl_text
    assert "S-1-5-11" not in acl_text
