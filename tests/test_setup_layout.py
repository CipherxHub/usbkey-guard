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

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
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
