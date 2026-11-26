"""The TUI removal option must never strand encrypted data or run unprompted."""
import pytest

from usbkey_guard import tui


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(tui, "pause", lambda: None)
    monkeypatch.setattr(tui, "heading", lambda title: None)


def _record_elevation(monkeypatch, calls, result=True):
    def fake():
        calls.append("elevate")
        return result

    monkeypatch.setattr(tui.setup_app, "elevate_uninstall", fake)


def test_refuses_while_a_vault_is_registered(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui.vault, "list_vaults",
                        lambda: [{"id": "abc123", "work_dir": r"D:\Bank"}])
    monkeypatch.setattr(tui.enforce, "load_config", lambda: {"roots": []})
    monkeypatch.setattr(tui, "ask", lambda prompt: "REMOVE")
    calls = []
    _record_elevation(monkeypatch, calls)

    tui.do_uninstall()

    assert calls == [], "must not uninstall while a vault exists"
    out = capsys.readouterr().out
    assert "abc123" in out
    assert "Remove that protection first" in out


def test_refuses_while_a_folder_is_still_locked(monkeypatch, quiet):
    monkeypatch.setattr(tui.vault, "list_vaults", lambda: [])
    monkeypatch.setattr(tui.enforce, "load_config",
                        lambda: {"roots": [{"path": r"D:\Secret", "locked": True}]})
    monkeypatch.setattr(tui, "ask", lambda prompt: "REMOVE")
    calls = []
    _record_elevation(monkeypatch, calls)

    tui.do_uninstall()

    assert calls == []


def test_confirmation_must_be_typed(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui.vault, "list_vaults", lambda: [])
    monkeypatch.setattr(tui.enforce, "load_config", lambda: {"roots": []})
    monkeypatch.setattr(tui, "ask", lambda prompt: "yes")
    calls = []
    _record_elevation(monkeypatch, calls)

    tui.do_uninstall()

    assert calls == []
    assert "Cancelled" in capsys.readouterr().out


def test_confirming_starts_the_elevated_removal(monkeypatch, quiet):
    monkeypatch.setattr(tui.vault, "list_vaults", lambda: [])
    monkeypatch.setattr(tui.enforce, "load_config", lambda: {"roots": []})
    monkeypatch.setattr(tui, "ask", lambda prompt: "REMOVE")
    calls = []
    _record_elevation(monkeypatch, calls)

    with pytest.raises(SystemExit):
        tui.do_uninstall()

    assert calls == ["elevate"]


def test_failed_elevation_prints_the_manual_commands(monkeypatch, quiet, capsys):
    monkeypatch.setattr(tui.vault, "list_vaults", lambda: [])
    monkeypatch.setattr(tui.enforce, "load_config", lambda: {"roots": []})
    monkeypatch.setattr(tui, "ask", lambda prompt: "REMOVE")
    _record_elevation(monkeypatch, [], result=False)

    tui.do_uninstall()

    out = capsys.readouterr().out
    assert "uninstall --purge" in out
    assert "pip uninstall" in out


def test_unreadable_state_refuses_and_points_at_the_cli(monkeypatch, quiet, capsys):
    def boom():
        raise OSError("state is corrupt")

    monkeypatch.setattr(tui.vault, "list_vaults", boom)
    monkeypatch.setattr(tui.enforce, "load_config", lambda: {"roots": []})
    calls = []
    _record_elevation(monkeypatch, calls)

    tui.do_uninstall()

    assert calls == []
    assert "uninstall --purge" in capsys.readouterr().out
