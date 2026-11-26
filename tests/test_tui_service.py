"""First run must offer the Administrator step instead of printing a command."""
import pytest

from usbkey_guard import tui


def _installed(tmp_path, version):
    root = tmp_path / "Program Files" / "usbkey"
    root.mkdir(parents=True)
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")
    return root


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(tui, "pause", lambda: None)
    monkeypatch.setattr(tui, "heading", lambda title: None)
    monkeypatch.setattr(tui, "clear", lambda: None)


def test_missing_marker_means_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", tmp_path / "nope")
    assert "missing or older" in tui.service_issue()


def test_version_mismatch_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", _installed(tmp_path, "1.0.0"))
    assert "system copy is 1.0.0" in tui.service_issue()


def test_stopped_service_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", _installed(tmp_path, tui.VERSION))
    monkeypatch.setattr(tui.setup_app, "_task_running", lambda: False)
    assert "not running" in tui.service_issue()


def test_current_and_running_is_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", _installed(tmp_path, tui.VERSION))
    monkeypatch.setattr(tui.setup_app, "_task_running", lambda: True)
    assert tui.service_issue() == ""


def test_offer_is_silent_when_already_fine(monkeypatch, quiet):
    monkeypatch.setattr(tui, "service_issue", lambda: "")
    calls = []
    monkeypatch.setattr(tui.setup_app, "elevate_install",
                        lambda: calls.append(1) or True)
    assert tui.offer_service_setup() is False
    assert calls == []


def test_enter_starts_the_elevated_install(monkeypatch, quiet):
    monkeypatch.setattr(tui, "service_issue", lambda: "not installed")
    monkeypatch.setattr(tui, "ask", lambda prompt: "")
    monkeypatch.setattr(tui, "_wait_for_install", lambda timeout=0: False)
    calls = []
    monkeypatch.setattr(tui.setup_app, "elevate_install",
                        lambda: calls.append(1) or True)
    assert tui.offer_service_setup() is True
    assert calls == [1]


def test_successful_install_continues_into_the_menu(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui, "service_issue", lambda: "not installed")
    monkeypatch.setattr(tui, "ask", lambda prompt: "")
    monkeypatch.setattr(tui, "_wait_for_install", lambda timeout=0: True)
    monkeypatch.setattr(tui.setup_app, "elevate_install", lambda: True)
    assert tui.offer_service_setup() is False
    assert "Installed" in capsys.readouterr().out


def test_wait_sees_an_existing_marker(tmp_path, monkeypatch):
    root = _installed(tmp_path, tui.VERSION)
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", root)
    assert tui._wait_for_install(timeout=0.1) is True


def test_wait_gives_up_when_nothing_appears(tmp_path, monkeypatch):
    monkeypatch.setattr(tui.config, "INSTALL_ROOT", tmp_path / "nope")
    assert tui._wait_for_install(timeout=0.3) is False


def test_declining_does_not_elevate(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui, "service_issue", lambda: "not installed")
    monkeypatch.setattr(tui, "ask", lambda prompt: "n")
    calls = []
    monkeypatch.setattr(tui.setup_app, "elevate_install",
                        lambda: calls.append(1) or True)
    assert tui.offer_service_setup() is False
    assert calls == []
    assert "option 9" in capsys.readouterr().out


def test_failed_elevation_prints_the_command(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui, "service_issue", lambda: "not installed")
    monkeypatch.setattr(tui, "ask", lambda prompt: "y")
    monkeypatch.setattr(tui.setup_app, "elevate_install", lambda: False)
    assert tui.offer_service_setup() is False
    assert "Administrator PowerShell" in capsys.readouterr().out
