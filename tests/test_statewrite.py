"""State writes must fail with the remedy, not a bare WinError 5."""
import json

import pytest

from usbkey_guard import statewrite
from usbkey_guard.errors import PermissionProblem


def _writer(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_save_reports_a_permission_problem_with_the_remedy(tmp_path, monkeypatch):
    target = tmp_path / "vaults.json"
    target.write_text("{}", encoding="utf-8")

    def deny(src, dst):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(statewrite.os, "replace", deny)
    with pytest.raises(PermissionProblem) as info:
        statewrite.save(target, {"vaults": []}, _writer)

    text = str(info.value)
    assert "access denied" in text
    assert "usbkey-setup repair-permissions" in text
    assert not (tmp_path / "vaults.json.tmp").exists()
    assert target.read_text(encoding="utf-8") == "{}", "target must stay untouched"


def test_save_succeeds_normally(tmp_path):
    target = tmp_path / "vaults.json"
    statewrite.save(target, {"vaults": [1]}, _writer)
    assert json.loads(target.read_text(encoding="utf-8")) == {"vaults": [1]}
    assert not (tmp_path / "vaults.json.tmp").exists()


def test_save_does_not_swallow_other_os_errors(tmp_path, monkeypatch):
    target = tmp_path / "vaults.json"

    def boom(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(statewrite.os, "replace", boom)
    with pytest.raises(OSError) as info:
        statewrite.save(target, {}, _writer)
    assert not isinstance(info.value, PermissionProblem)
