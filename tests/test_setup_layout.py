"""The installed copy must actually be importable by the SYSTEM task."""
import types
from pathlib import Path

import pytest

from usbkey_guard import setup_app as sa


@pytest.fixture
def fake_install(tmp_path, monkeypatch):
    pkg = tmp_path / "site-packages" / "usbkey_guard"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "cli.py").write_text("", encoding="utf-8")

    install = tmp_path / "Program Files" / "usbkey"
    monkeypatch.setattr(sa.config, "INSTALL_ROOT", install)
    monkeypatch.setattr(sa.config, "PACKAGE_ROOT", pkg)
    monkeypatch.setattr(sa, "is_admin", lambda: True)
    monkeypatch.setattr(sa, "start_menu_dir", lambda: tmp_path / "menu" / "usbkey")
    monkeypatch.setattr(sa.paths, "ensure_state_tree", lambda: None)
    monkeypatch.setattr(sa.acl, "allow_state_writes", lambda root: True)
    # Never touch the real desktop shortcut while testing removal.
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "user"))

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "/query" in argv:
            return types.SimpleNamespace(returncode=0, stdout="Status:        Running",
                                         stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    monkeypatch.setattr(sa.time, "sleep", lambda seconds: None)
    return install, calls


def test_install_places_the_package_in_an_importable_subfolder(fake_install):
    install, _ = fake_install
    assert sa.install() == 0
    assert (install / "usbkey_guard" / "__init__.py").is_file()
    assert (install / "usbkey_guard" / "cli.py").is_file()


def test_bootstrap_inserts_the_install_root_on_sys_path(fake_install):
    install, _ = fake_install
    sa.install()
    bootstrap = (install / sa.ENFORCER_BOOTSTRAP).read_text(encoding="utf-8")
    assert "sys.path.insert(0, " + repr(str(install)) + ")" in bootstrap
    assert "from usbkey_guard.cli import main" in bootstrap


def test_task_command_points_at_a_written_bootstrap(fake_install):
    install, calls = fake_install
    sa.install()
    assert str(install / sa.ENFORCER_BOOTSTRAP) in sa.task_command()
    assert (install / sa.ENFORCER_BOOTSTRAP).is_file()
    assert calls and "usbkey-enforcer" in calls[0]


def test_launcher_falls_back_when_the_installing_python_is_missing(fake_install):
    install, _ = fake_install
    sa.install()
    launcher = (install.parents[1] / "menu" / "usbkey" / "usbkey TUI.bat").read_text(encoding="utf-8")
    assert "where py" in launcher
    assert str(install / sa.TUI_BOOTSTRAP) in launcher


def test_uninstall_refuses_a_foreign_folder(tmp_path, monkeypatch):
    foreign = tmp_path / "not-usbkey"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sa.config, "INSTALL_ROOT", foreign)
    monkeypatch.setattr(sa, "is_admin", lambda: True)
    monkeypatch.setattr(sa, "start_menu_dir", lambda: tmp_path / "menu")
    monkeypatch.setattr(sa, "_remove_desktop_shortcut", lambda: None)
    monkeypatch.setattr(sa.subprocess, "run",
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""))
    with pytest.raises(RuntimeError, match="unexpected folder"):
        sa.uninstall()
    assert (foreign / "keep.txt").is_file()


def test_uninstall_removes_only_its_own_tree(fake_install):
    install, _ = fake_install
    sa.install()
    assert sa.uninstall() == 0
    assert not install.exists()


def test_launcher_is_not_written_with_cr_cr_lf(fake_install):
    install, _ = fake_install
    sa.install()
    raw = (install.parents[1] / "menu" / "usbkey" / "usbkey TUI.bat").read_bytes()
    assert b"\r\r\n" not in raw, "cmd.exe mis-parses CR CR LF line endings"
    assert b"\r\n" in raw


def test_start_menu_gets_a_shortcut_not_only_a_bat(fake_install):
    install, _ = fake_install
    sa.install()
    menu = install.parents[1] / "menu" / "usbkey"
    lnk = menu / "usbkey TUI.lnk"
    if not lnk.is_file():
        pytest.skip("COM shortcut creation unavailable in this environment")
    assert lnk.stat().st_size > 0


def test_install_grants_local_users_write_access_to_state(fake_install, monkeypatch):
    install, _ = fake_install
    seen = []
    monkeypatch.setattr(sa.acl, "allow_state_writes",
                        lambda root: seen.append(root) or True)
    sa.install()
    assert seen == [str(sa.config.STATE_ROOT)]


def test_repair_permissions_is_admin_only(monkeypatch):
    monkeypatch.setattr(sa, "is_admin", lambda: False)
    assert sa.repair_permissions() == 1


def test_install_starts_the_service_when_it_is_not_running(fake_install, monkeypatch):
    install, calls = fake_install
    states = iter(["Status: Ready", "Status: Running"])

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "/query" in argv:
            return types.SimpleNamespace(returncode=0, stdout=next(states), stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    assert sa.install() == 0
    assert any("/run" in call for call in calls), \
        "an onstart task does nothing until it is run once"


def test_install_warns_when_the_service_will_not_start(fake_install, monkeypatch, capsys):
    install, calls = fake_install

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "/query" in argv:
            return types.SimpleNamespace(returncode=0, stdout="Status: Ready", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    assert sa.install() == 1
    out = capsys.readouterr().out
    assert "will NOT be locked" in out


def test_interpreter_inside_a_user_profile_is_not_shared(monkeypatch):
    fake = Path.home() / "AppData" / "Local" / "Programs" / "Python312" / "python.exe"
    monkeypatch.setattr(sa.sys, "executable", str(fake))
    assert sa.interpreter_is_shared() is False


def test_machine_wide_interpreter_is_shared(monkeypatch):
    monkeypatch.setattr(sa.sys, "executable", r"C:\Program Files\Python312\python.exe")
    assert sa.interpreter_is_shared() is True


def test_uninstall_keeps_state_by_default(fake_install, tmp_path, monkeypatch):
    state = tmp_path / "ProgramData" / "usbkey"
    state.mkdir(parents=True)
    (state / "vaults.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sa.config, "STATE_ROOT", state)
    assert sa.uninstall() == 0
    assert (state / "vaults.json").is_file(), "a plain uninstall must keep the state"


def test_uninstall_purge_removes_the_state_folder(fake_install, tmp_path, monkeypatch):
    state = tmp_path / "ProgramData" / "usbkey"
    state.mkdir(parents=True)
    (state / "vaults.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sa.config, "STATE_ROOT", state)
    assert sa.uninstall(purge=True) == 0
    assert not state.exists()


def test_purge_refuses_a_shallow_folder():
    assert sa._state_is_purgeable(Path("C:\\")) is False
    assert sa._state_is_purgeable(Path("C:\\Windows")) is False
    assert sa._state_is_purgeable(Path("C:\\ProgramData\\usbkey")) is True


def test_elevate_uninstall_writes_a_helper_and_reports_a_refusal(tmp_path, monkeypatch):
    class Shell:
        def ShellExecuteW(self, *args):
            return 5  # <= 32 means the shell refused

    monkeypatch.setattr(sa.config, "INSTALL_ROOT", tmp_path / "Program Files" / "usbkey")
    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.ctypes, "windll", types.SimpleNamespace(shell32=Shell()))
    assert sa.elevate_uninstall() is False
    helper = (tmp_path / "usbkey-uninstall.py").read_text(encoding="utf-8")
    assert "uninstall" in helper and "--purge" in helper
    assert "pip" in helper, "the package must be removed too"


def test_elevate_uninstall_reports_success(tmp_path, monkeypatch):
    class Shell:
        def ShellExecuteW(self, *args):
            return 42

    monkeypatch.setattr(sa.config, "INSTALL_ROOT", tmp_path / "Program Files" / "usbkey")
    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.ctypes, "windll", types.SimpleNamespace(shell32=Shell()))
    assert sa.elevate_uninstall() is True


def test_install_writes_a_version_marker(fake_install):
    install, _ = fake_install
    sa.install()
    marker = (install / sa.VERSION_MARKER).read_text(encoding="utf-8").strip()
    assert marker == sa.__version__


def test_install_offers_elevation_when_not_admin(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sa, "is_admin", lambda: False)
    monkeypatch.setattr(sa, "elevate_install",
                        lambda: calls.append("elevate") or True)
    monkeypatch.setattr(sa.config, "INSTALL_ROOT", tmp_path / "Program Files" / "usbkey")
    assert sa.install() == 0
    assert calls == ["elevate"]
    assert not (tmp_path / "Program Files" / "usbkey").exists()


def test_install_reports_when_elevation_fails(monkeypatch, capsys):
    monkeypatch.setattr(sa, "is_admin", lambda: False)
    monkeypatch.setattr(sa, "elevate_install", lambda: False)
    assert sa.install() == 1
    assert "Administrator prompt" in capsys.readouterr().out


def test_elevate_install_writes_a_helper_that_imports_this_package(tmp_path, monkeypatch):
    class Shell:
        def ShellExecuteW(self, *args):
            return 42

    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.ctypes, "windll", types.SimpleNamespace(shell32=Shell()))
    assert sa.elevate_install() is True
    helper = (tmp_path / "usbkey-install.py").read_text(encoding="utf-8")
    assert repr(str(Path(sa.config.PACKAGE_ROOT).parent)) in helper
    assert '"install"' in helper
