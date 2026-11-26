"""The enforcer task must actually run at boot, on a laptop, and keep running."""
import types
from pathlib import Path
from xml.etree import ElementTree

from usbkey_guard import cli
from usbkey_guard import setup_app as sa


def _task_xml() -> str:
    return sa.TASK_XML.format(command="C:\\Python312\\pythonw.exe",
                              arguments='"C:\\Program Files\\usbkey\\run_enforcer.py"')


def test_task_allows_battery_and_has_no_time_limit():
    xml = _task_xml()
    assert "<DisallowStartIfOnBatteries>false<" in xml
    assert "<StopIfGoingOnBatteries>false<" in xml
    assert "<ExecutionTimeLimit>PT0S<" in xml
    assert "<StartWhenAvailable>true<" in xml
    assert "<UserId>S-1-5-18<" in xml


def test_task_has_boot_and_logon_triggers():
    xml = _task_xml()
    assert "<BootTrigger>" in xml, "the service must start without a user logged on"
    assert "<LogonTrigger>" in xml, "a logon must recover a missed boot start"


def test_task_has_a_watchdog_that_restarts_a_killed_service():
    """`schtasks /end` and a task kill do not fire RestartOnFailure."""
    xml = _task_xml()
    assert "<TimeTrigger>" in xml
    assert "<Interval>PT5M<" in xml


def test_task_action_reads_the_registered_command():
    command, arguments = sa.task_action(_task_xml())
    assert command == "C:\\Python312\\pythonw.exe"
    assert arguments.endswith('run_enforcer.py"')


def test_task_action_is_empty_for_broken_xml():
    assert sa.task_action("<not xml") == ("", "")


def test_action_problems_flags_a_missing_python(tmp_path):
    problems = sa._action_problems(str(tmp_path / "gone" / "pythonw.exe"), "")
    assert any("does not exist" in problem for problem in problems)


def test_action_problems_flags_a_store_alias():
    problems = sa._action_problems(
        r"C:\Users\me\AppData\Local\Microsoft\WindowsApps\pythonw.exe", "")
    assert any("Store" in problem for problem in problems)


def test_action_problems_flags_a_missing_bootstrap(tmp_path):
    exe = tmp_path / "pythonw.exe"
    exe.write_text("", encoding="utf-8")
    problems = sa._action_problems(str(exe), f'"{tmp_path / "run_enforcer.py"}"')
    assert any("run install again" in problem for problem in problems)


def test_action_problems_is_silent_for_a_good_action(tmp_path):
    exe = tmp_path / "pythonw.exe"
    exe.write_text("", encoding="utf-8")
    script = tmp_path / "run_enforcer.py"
    script.write_text("", encoding="utf-8")
    assert sa._action_problems(str(exe), f'"{script}"') == []


def test_boot_log_tail_shows_the_last_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sa.config, "STATE_ROOT", tmp_path)
    log = tmp_path / "logs" / "enforcer-boot.log"
    log.parent.mkdir(parents=True)
    log.write_text("old\n" + "\n".join(f"line{i}" for i in range(40)),
                   encoding="utf-8")
    assert sa._boot_log_tail(5).splitlines() == [f"line{i}" for i in range(35, 40)]


def test_boot_log_tail_is_empty_without_a_log(tmp_path, monkeypatch):
    monkeypatch.setattr(sa.config, "STATE_ROOT", tmp_path)
    assert sa._boot_log_tail() == ""


def test_status_explains_a_stopped_service(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sa.config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(sa, "task_info", lambda: {
        "exists": True, "state": 3, "last_result": 0x80070002,
        "last_run": None, "xml": _task_xml(),
    })
    monkeypatch.setattr(sa, "interpreter_problem", lambda: "")
    monkeypatch.setattr(sa, "interpreter_is_shared", lambda: True)
    assert sa.status() == 1
    out = capsys.readouterr().out
    assert "Service: NOT running" in out
    assert "file not found" in out
    assert "Task command:" in out
    assert "run install again" in out


def test_diagnosis_names_a_terminated_process(tmp_path, monkeypatch, capsys):
    """`schtasks /end` leaves 0x41306; the watchdog is the way back."""
    monkeypatch.setattr(sa.config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(sa, "interpreter_is_shared", lambda: True)
    sa.print_service_diagnosis({
        "exists": True, "state": 3, "last_result": 0x41306,
        "last_run": None, "xml": _task_xml(),
    })
    out = capsys.readouterr().out
    assert "terminated" in out
    assert "watchdog" in out
    assert "never started" not in out


def test_diagnosis_shows_the_boot_log(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sa.config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(sa, "interpreter_is_shared", lambda: True)
    log = tmp_path / "logs" / "enforcer-boot.log"
    log.parent.mkdir(parents=True)
    log.write_text("ModuleNotFoundError: No module named 'win32event'",
                   encoding="utf-8")
    sa.print_service_diagnosis({
        "exists": True, "state": 3, "last_result": 1,
        "last_run": None, "xml": _task_xml(),
    })
    out = capsys.readouterr().out
    assert "win32event" in out
    assert "enforcer-boot.log" in out


def test_status_is_quiet_when_the_service_runs(monkeypatch, capsys):
    monkeypatch.setattr(sa, "task_info", lambda: {
        "exists": True, "state": sa.TASK_STATE_RUNNING, "last_result": 0x41301,
        "last_run": "2026-01-01", "xml": _task_xml(),
    })
    monkeypatch.setattr(sa, "interpreter_problem", lambda: "")
    assert sa.status() == 0
    out = capsys.readouterr().out
    assert "Service: running" in out
    assert "NOT running" not in out


def test_task_xml_is_well_formed():
    ElementTree.fromstring(_task_xml())


def test_create_task_writes_utf16_xml_and_registers_it(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["xml"] = Path(argv[argv.index("/xml") + 1]).read_text(encoding="utf-16")
        return types.SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.config, "INSTALL_ROOT",
                        tmp_path / "Program Files" / "usbkey")

    assert sa._create_task() == 0
    assert seen["argv"][:4] == ["schtasks", "/create", "/tn", sa.config.TASK_NAME]
    assert "<DisallowStartIfOnBatteries>false<" in seen["xml"]
    script = str(Path(sa.config.INSTALL_ROOT) / sa.ENFORCER_BOOTSTRAP)
    assert script in seen["xml"]
    assert not (tmp_path / "usbkey-enforcer-task.xml").exists(), \
        "the temporary task definition must not be left behind"


def test_create_task_escapes_ampersands(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["xml"] = Path(argv[argv.index("/xml") + 1]).read_text(encoding="utf-16")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.config, "INSTALL_ROOT", tmp_path / "A & B" / "usbkey")
    assert sa._create_task() == 0
    assert "A &amp; B" in seen["xml"]
    ElementTree.fromstring(seen["xml"])


def test_create_task_falls_back_when_xml_is_rejected(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "/xml" in argv:
            return types.SimpleNamespace(returncode=1, stdout="bad xml", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    monkeypatch.setattr(sa.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(sa.config, "INSTALL_ROOT", tmp_path / "usbkey")

    assert sa._create_task() == 0
    assert any("/sc" in call for call in calls)
    assert "Falling back" in capsys.readouterr().out


def test_settings_warning_is_silent_for_a_healthy_task():
    assert sa._settings_warning(_task_xml()) == ""


def test_settings_warning_flags_battery_start_block():
    bad = _task_xml().replace("<DisallowStartIfOnBatteries>false<",
                              "<DisallowStartIfOnBatteries>true<")
    assert "battery" in sa._settings_warning(bad)


def test_settings_warning_flags_stop_on_battery():
    bad = _task_xml().replace("<StopIfGoingOnBatteries>false<",
                              "<StopIfGoingOnBatteries>true<")
    assert "charger" in sa._settings_warning(bad)


def test_settings_warning_ignores_broken_xml():
    assert sa._settings_warning("<not xml") == ""


def test_explain_result_names_the_common_codes():
    assert "has not run yet" in sa._explain_result(0x41303)
    assert "file not found" in sa._explain_result(0x80070002)
    assert "0x00000005" in sa._explain_result(5)


def test_interpreter_problem_reports_a_broken_import(monkeypatch):
    monkeypatch.setattr(sa, "python_console",
                        lambda: Path(r"C:\Python312\python.exe"))

    def fake_run(argv, **kwargs):
        return types.SimpleNamespace(
            returncode=1, stdout="",
            stderr="Traceback...\nModuleNotFoundError: No module named 'win32event'")

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    message = sa.interpreter_problem()
    assert "win32event" in message
    assert "C:\\Python312\\python.exe" in message


def test_interpreter_problem_is_silent_when_imports_work(monkeypatch):
    monkeypatch.setattr(sa, "python_console", lambda: Path("python.exe"))
    monkeypatch.setattr(sa.subprocess, "run", lambda argv, **kw: types.SimpleNamespace(
        returncode=0, stdout="1.0.11\n", stderr=""))
    assert sa.interpreter_problem() == ""


def test_interpreter_problem_handles_a_missing_python(monkeypatch):
    monkeypatch.setattr(sa, "python_console", lambda: Path("gone.exe"))

    def boom(argv, **kwargs):
        raise OSError("no such file")

    monkeypatch.setattr(sa.subprocess, "run", boom)
    assert "could not run" in sa.interpreter_problem()


def test_await_identity_waits_for_enrollment():
    seq = [{"identity": None}, {"identity": {"serial": "x"}}]
    slept = []
    cfg = cli._await_identity({"identity": None}, sleep=slept.append,
                              load=lambda: seq.pop(0))
    assert cfg["identity"] == {"serial": "x"}
    assert slept == [5, 5]


def test_await_identity_survives_a_corrupt_config(monkeypatch):
    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupt state")
        return {"identity": {"serial": "x"}}

    monkeypatch.setattr(cli, "_log", types.SimpleNamespace(exception=lambda *a: None))
    cfg = cli._await_identity({"identity": None}, sleep=lambda seconds: None,
                              load=load)
    assert cfg["identity"]["serial"] == "x"


def test_monitor_once_still_reports_not_enrolled(monkeypatch, capsys):
    monkeypatch.setattr(cli.enforce, "claim_monitor", lambda: True)
    monkeypatch.setattr(cli.enforce, "load_config", lambda: {"identity": None})
    assert cli.cmd_monitor(types.SimpleNamespace(once=True)) == 2
    assert "not enrolled" in capsys.readouterr().out


def test_claim_monitor_is_exclusive(monkeypatch):
    from usbkey_guard import enforce
    import win32event

    if not enforce.claim_monitor():
        import pytest
        pytest.skip("a real enforcer is already running on this PC")
    try:
        assert enforce.claim_monitor() is False, \
            "a second monitor must not cycle alongside the first"
    finally:
        win32event.ReleaseMutex(enforce._monitor_mutex)
        enforce._monitor_mutex.Close()
        enforce._monitor_mutex = None
