r"""All-users install: Program Files copy, Start menu entry, SYSTEM task.

The scheduled task and the Start menu launcher both run bootstrap scripts that
live in the install folder, so the installed copy is what actually executes
even when pip's site-packages is per-user.
"""
import ast
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from . import acl, config, paths
from . import __version__

ENFORCER_BOOTSTRAP = "run_enforcer.py"
TUI_BOOTSTRAP = "run_tui.py"
VERSION_MARKER = "VERSION"

_ENFORCER_SOURCE = """\
import sys
sys.path.insert(0, {install!r})
try:
    from usbkey_guard.cli import main
    rc = main(["monitor"])
except BaseException:
    # pythonw has no console, so an import failure would be invisible. Leave a
    # trace file next to the normal log before exiting.
    try:
        import logging
        from pathlib import Path
        log = Path({logfile!r})
        log.parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(filename=str(log), level=logging.ERROR,
                            format="%(asctime)s %(levelname)s %(message)s")
        logging.exception("enforcer could not start")
    except Exception:
        pass
    rc = 1
sys.exit(rc)
"""

# Windows creates scheduled tasks with "start only on AC power" and
# "stop on battery" enabled, and schtasks has no switch to turn them off. A
# laptop on battery therefore never started the enforcer at boot, and unplugging
# the charger stopped it. Registering from XML is the only reliable fix.
TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>usbkey background enforcer: re-locks protected folders when the USB key is removed.</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT15S</Delay>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT10S</Delay>
    </LogonTrigger>
    <!-- Watchdog: if the process is killed (Task Manager, antivirus, a crash
         that did not restart) the task starts it again within five minutes.
         IgnoreNew above means a healthy instance is never duplicated. -->
    <TimeTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT5M</Interval>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

_TUI_SOURCE = """\
import sys
sys.path.insert(0, {install!r})
from usbkey_guard.tui import main
sys.exit(main())
"""

_UNINSTALL_HELPER = """\
import subprocess
import sys

sys.path.insert(0, {install!r})
from usbkey_guard.setup_app import main

rc = main(["uninstall", "--purge"])

print()
print("Removing the Python package usbkey-guard...")
subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "usbkey-guard"])

try:
    from pathlib import Path
    Path(__file__).unlink()
except OSError:
    pass

print()
try:
    input("Press Enter to close this window... ")
except EOFError:
    pass
sys.exit(rc)
"""

_INSTALL_HELPER = """\
import sys

sys.path.insert(0, {root!r})
from usbkey_guard.setup_app import main

rc = main(["install"])

print()
try:
    input("Press Enter to close this window... ")
except EOFError:
    pass
sys.exit(rc)
"""


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def start_menu_dir() -> Path:
    """All-users Start menu, not the installing administrator's profile."""
    root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    return root / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "usbkey"


def pythonw() -> Path:
    return Path(sys.executable).with_name("pythonw.exe")


def python_console() -> Path:
    return Path(sys.executable).with_name("python.exe")


def task_command() -> str:
    script = Path(config.INSTALL_ROOT) / ENFORCER_BOOTSTRAP
    return f'"{pythonw()}" "{script}"'


def interpreter_is_shared() -> bool:
    """True when the running Python is usable by every account on this PC.

    The Start menu launcher embeds this path, so a Python under
    `C:\\Users\\<name>` works for that one account (and for SYSTEM) but gives
    other users "Access is denied".
    """
    try:
        exe = Path(sys.executable).resolve()
        profiles = Path.home().parent
        return not exe.is_relative_to(profiles)
    except (OSError, ValueError):
        return True


TASK_STATE_NAMES = {0: "unknown", 1: "disabled", 2: "queued", 3: "ready",
                    4: "running"}
TASK_STATE_RUNNING = 4

_RESULT_TEXT = {
    0x00000000: "success",
    0x41300: "ready (not started yet)",
    0x41301: "currently running",
    0x41302: "disabled",
    0x41303: "has not run yet",
    0x41304: "no more runs scheduled",
    0x41306: "terminated",
    0x41307: "terminated: time limit exceeded",
    0x800710E0: "start skipped: already running",
    0x80070002: "file not found (check the Python path)",
    0x80070003: "path not found (check the install folder)",
    0x80070005: "access denied",
    0xC0000135: "missing DLL (Python install damaged)",
    0xC0000142: "DLL initialisation failed (Python install damaged)",
}


def task_info() -> dict:
    """Task state via the COM API, which is not translated like schtasks text."""
    try:
        import win32com.client

        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        task = service.GetFolder("\\").GetTask(config.TASK_NAME)
        return {
            "exists": True,
            "state": int(task.State),
            "last_result": int(task.LastTaskResult),
            "last_run": task.LastRunTime,
            "xml": task.Xml or "",
        }
    except Exception:
        pass
    # No COM (or no task): fall back to the text output, English only.
    query = subprocess.run(["schtasks", "/query", "/tn", config.TASK_NAME,
                            "/fo", "LIST"],
                           capture_output=True, text=True)
    if query.returncode != 0:
        return {"exists": False}
    return {"exists": True,
            "state": TASK_STATE_RUNNING if "Running" in query.stdout else 3,
            "last_result": 0, "last_run": None, "xml": ""}


def _task_running() -> bool:
    return task_info().get("state") == TASK_STATE_RUNNING


def _state_name(state: int) -> str:
    return TASK_STATE_NAMES.get(state, "state " + str(state))


def _explain_result(code: int) -> str:
    code &= 0xFFFFFFFF
    text = _RESULT_TEXT.get(code)
    return f"0x{code:08X}" + (f" ({text})" if text else "")


def _settings_warning(xml_text: str) -> str:
    """Point out task settings that would stop the enforcer from running."""
    if not xml_text:
        return ""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return ""
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

    def flag(name: str) -> bool:
        node = root.find(f"t:Settings/t:{name}", ns)
        return node is not None and (node.text or "").strip().lower() == "true"

    if flag("DisallowStartIfOnBatteries"):
        return ("WARNING: this task refuses to start on battery power, so a "
                "laptop can boot without the enforcer. Run install to repair it.")
    if flag("StopIfGoingOnBatteries"):
        return ("WARNING: this task stops when the charger is unplugged. "
                "Run install to repair it.")
    return ""


def required_modules() -> list[str]:
    """Every non-stdlib module the installed package imports, found by scanning.

    A hand-written list is how `cryptography` was missed: the package imports it
    in `cli.py`, which nothing imported during the old probe. This walks the
    source instead, so a dependency added in a later version is checked without
    anyone remembering to update a list. Lazy imports inside functions are found
    too, because the scan is static.
    """
    root = Path(config.INSTALL_ROOT) / "usbkey_guard"
    names: set[str] = set()
    for path in root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif (isinstance(node, ast.ImportFrom) and node.level == 0
                  and node.module):
                names.add(node.module)
    stdlib = set(sys.stdlib_module_names)
    return sorted(
        name for name in names
        if name.split(".")[0] not in stdlib and name.split(".")[0] != "usbkey_guard"
        and not name.startswith("_")
    )


_PROBE = """\
import importlib
import sys

sys.path.insert(0, {root!r})
bad = []
for name in {modules!r}:
    try:
        importlib.import_module(name)
    except Exception as exc:
        bad.append("{{}} ({{}}: {{}})".format(name, type(exc).__name__, exc))
try:
    import usbkey_guard.cli  # the module the enforcer bootstrap imports
except Exception as exc:
    bad.append("usbkey_guard.cli ({{}}: {{}})".format(type(exc).__name__, exc))
if bad:
    print("MISSING: " + "; ".join(bad))
    sys.exit(3)
print("OK")
"""


def _probe(isolated: bool) -> tuple[int, str]:
    """Import every dependency with the task's interpreter.

    `isolated=True` passes `-I`, which drops the per-user site folder and
    PYTHONPATH. That is what the SYSTEM task sees; without it a dependency
    installed under `%APPDATA%\\Python\\...` looks fine to the installing user and
    is invisible to the service (seen as `No module named '_cffi_backend'`).
    """
    modules = required_modules()
    code = _PROBE.format(root=str(config.INSTALL_ROOT), modules=modules)
    argv = [str(python_console())] + (["-I"] if isolated else []) + ["-c", code]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return result.returncode, (result.stdout or "") + "\n" + (result.stderr or "")


def _missing_line(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("MISSING:"):
            return line[len("MISSING:"):].strip()
    lines = [line for line in output.strip().splitlines() if line.strip()]
    return lines[-1] if lines else "unknown import error"


def dependency_fix(python: Path | None = None) -> str:
    """The command that puts the dependencies where the service can read them."""
    exe = python or python_console()
    return (f'"{exe}" -m pip install --force-reinstall '
            "pywin32 psutil cryptography cffi")


def interpreter_problem() -> str:
    """Empty when the task's Python can import everything the enforcer imports."""
    if not (Path(config.INSTALL_ROOT) / "usbkey_guard").is_dir():
        return (f"the install folder {config.INSTALL_ROOT} is missing or "
                "incomplete - run install again")
    code, output = _probe(isolated=True)
    if code == 0:
        return ""
    if code == 127:
        return f"could not run {python_console()}: {output.strip()}"
    missing = _missing_line(output)
    plain_code, _ = _probe(isolated=False)
    if plain_code == 0:
        return (f"{python_console()} can import the package only from your "
                f"user-profile folder ({missing}), and the SYSTEM service "
                "cannot read that folder")
    return f"{python_console()} is missing modules: {missing}"


def boot_log_path() -> Path:
    return Path(config.STATE_ROOT) / "logs" / "enforcer-boot.log"


def _boot_log_tail(lines: int = 20) -> str:
    try:
        text = boot_log_path().read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    kept = text.strip().splitlines()[-lines:]
    return "\n".join(kept)


def task_action(xml_text: str) -> tuple[str, str]:
    """The <Command> and <Arguments> the task actually runs."""
    if not xml_text:
        return "", ""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return "", ""
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    exec_node = root.find("t:Actions/t:Exec", ns)
    if exec_node is None:
        return "", ""
    command = exec_node.findtext("t:Command", "", ns).strip()
    arguments = exec_node.findtext("t:Arguments", "", ns).strip()
    return command, arguments


def _action_problems(command: str, arguments: str) -> list[str]:
    """Reasons the registered task cannot start at all, in plain words."""
    problems = []
    if not command:
        return ["the task has no command recorded - run install to rewrite it"]
    exe = Path(command.strip().strip('"'))
    if "WindowsApps" in str(exe):
        problems.append(
            f"the task runs the Microsoft Store alias {exe}; a SYSTEM task "
            "cannot execute Store aliases - install Python from python.org "
            "and run install again"
        )
    elif not exe.exists():
        problems.append(
            f"the task runs {exe}, which does not exist on this PC "
            "(reinstall Python, or run install from the Python you want the "
            "service to use)"
        )
    script = arguments.strip().strip('"')
    if script and script.lower().endswith(".py") and not Path(script).exists():
        problems.append(
            f"the task runs {script}, which is missing - run install again to "
            "rewrite the install folder"
        )
    return problems


def _missing_module(text: str) -> str:
    """The module named in `ModuleNotFoundError: No module named 'x'`."""
    import re
    match = re.search(r"No module named '([^']+)'", text or "")
    return match.group(1) if match else ""


def print_service_diagnosis(info: dict | None = None) -> None:
    """Explain why the enforcer is not running, from the evidence on disk."""
    info = info if info is not None else task_info()
    print("The enforcer is NOT running: pulling the stick will not re-lock "
          "anything right now.")
    command, arguments = task_action(info.get("xml", ""))
    if command:
        print("Task command:", command, arguments)
    problems = _action_problems(command, arguments)
    for problem in problems:
        print("  PROBLEM:", problem)
    code = int(info.get("last_result") or 0) & 0xFFFFFFFF
    tail = _boot_log_tail()
    if tail:
        print("Last startup failure (" + str(boot_log_path()) + "):")
        for line in tail.splitlines():
            print("  " + line)
        missing = _missing_module(tail)
        if missing:
            target = Path(command.strip().strip('"')).with_name("python.exe") \
                if command else python_console()
            print("  PROBLEM: that Python cannot import '" + missing + "'.")
            print("  Fix (elevated PowerShell):", dependency_fix(target))
            print("  A package that exists only in %APPDATA%\\Python\\... is "
                  "invisible to the")
            print("  SYSTEM task, so it must be installed machine-wide.")
            print("  Then run install again as Administrator.")
    elif code == 0x41306:
        print("The service process was terminated (Task Manager, 'End task', or "
              "antivirus). The five-minute watchdog starts it again by itself; "
              "to do it now: schtasks /run /tn usbkey-enforcer")
    elif code == 0x800710E0:
        print("Task Scheduler refused the last start. If another usbkey monitor "
              "is running, stop it (Task Manager) and run install again; "
              "otherwise a policy is blocking the task.")
    elif code in (0x41303, 0x41300):
        print("The task has not started yet. Run install again as "
              "Administrator, or start it with: schtasks /run /tn usbkey-enforcer")
    elif code == 0:
        print("The service exited cleanly instead of running. See "
              + str(Path(config.STATE_ROOT) / "logs" / "usbkey.log"))
    elif not problems:
        print("No startup failure was logged, so the task probably never "
              "started (a disabled task, or a policy that blocks it).")
    if not interpreter_is_shared():
        print("  NOTE: this Python lives in a user profile (" + str(sys.executable)
              + "); the SYSTEM service can usually read it, but other accounts "
              "cannot run the Start menu entry.")
    print("Fix: run install again as Administrator, then run status.")


def _create_task() -> int:
    """Register the enforcer task from XML, with settings that actually run."""
    script = Path(config.INSTALL_ROOT) / ENFORCER_BOOTSTRAP
    xml = TASK_XML.format(command=escape(str(pythonw())),
                          arguments=escape(f'"{script}"'))
    helper = Path(tempfile.gettempdir()) / "usbkey-enforcer-task.xml"
    try:
        helper.write_text(xml, encoding="utf-16")
    except OSError as exc:
        print("WARNING: could not write the task definition:", exc)
        return _create_task_legacy()
    result = subprocess.run(
        ["schtasks", "/create", "/tn", config.TASK_NAME, "/xml", str(helper), "/f"],
        capture_output=True, text=True,
    )
    try:
        helper.unlink()
    except OSError:
        pass
    if result.returncode == 0:
        print("Scheduled task created:", config.TASK_NAME)
        return 0
    print("WARNING: could not register the task from its XML:")
    print((result.stdout or result.stderr).strip())
    print("Falling back to the plain form; battery settings may not apply.")
    return _create_task_legacy()


def _create_task_legacy() -> int:
    result = subprocess.run(
        ["schtasks", "/create", "/tn", config.TASK_NAME, "/tr", task_command(),
         "/sc", "onstart", "/ru", "SYSTEM", "/rl", "highest", "/f"],
        capture_output=True, text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


def _start_service() -> int:
    """Start the task now: a boot trigger otherwise does nothing until reboot."""
    if _task_running():
        print("Background service already running:", config.TASK_NAME)
        return 0
    started = subprocess.run(["schtasks", "/run", "/tn", config.TASK_NAME],
                             capture_output=True, text=True)
    if started.returncode != 0:
        print("WARNING: could not start the service:",
              (started.stdout or started.stderr).strip())
        info = task_info()
        if info.get("exists"):
            print("Task state:", _state_name(info["state"]),
                  "| last result:", _explain_result(info["last_result"]))
        print("It will try again at the next boot or logon.")
        print()
        print_service_diagnosis(info)
        return 1
    for _ in range(10):
        time.sleep(1)
        if _task_running():
            print("Background service running:", config.TASK_NAME)
            return 0
    info = task_info()
    print("WARNING: the service task was started but is not running.")
    if info.get("exists"):
        print("Task state:", _state_name(info["state"]),
              "| last result:", _explain_result(info["last_result"]))
    print("Plaintext will NOT be locked when the stick is removed until it runs.")
    print()
    print_service_diagnosis(info)
    return 1


def _assert_own_install_root(path: Path) -> None:
    resolved = Path(path).resolve()
    if resolved.name.lower() != config.APP_NAME.lower():
        raise RuntimeError(f"refusing to remove unexpected folder: {resolved}")
    if len(resolved.parts) < 3:
        raise RuntimeError(f"refusing to remove shallow folder: {resolved}")


def _write_bootstrap(name: str, source: str) -> None:
    (Path(config.INSTALL_ROOT) / name).write_text(source, encoding="utf-8")


def _write_shortcut(path: Path, launcher: Path) -> Path | None:
    """Create a real .lnk next to the .bat.

    Windows 11 Start search does not reliably surface .bat files, and a shortcut
    is what users actually click. Failures are non-fatal: the .bat still works.
    """
    try:
        import win32com.client

        shell = win32com.client.Dispatch("WScript.Shell")
        link = shell.CreateShortcut(str(path))
        link.TargetPath = str(Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")))
        link.Arguments = f'/c ""{launcher}""'
        link.WorkingDirectory = str(launcher.parent)
        link.Description = "usbkey - USB-key-gated encrypted vault"
        try:
            link.IconLocation = f"{python_console()},0"
        except OSError:
            pass
        link.Save()
        return path
    except Exception as exc:  # COM missing, policy blocked, ...
        print("WARNING: could not create Start menu shortcut:", exc)
        return None


def harden_state() -> bool:
    """Create the state tree as this admin and restrict it to admins + owner."""
    if os.environ.get("USBKEY_SKIP_HARDEN") == "1":
        print("State hardening skipped (USBKEY_SKIP_HARDEN=1).")
        return False
    paths.ensure_state_tree()
    ok = acl.harden_state_root(str(config.STATE_ROOT))
    print("State folder hardened:", config.STATE_ROOT if ok else "FAILED (left unchanged)")
    return ok


def install() -> int:
    if not is_admin():
        print("Installing for all users needs Administrator rights: the Program")
        print("Files copy, the Start menu entry and the SYSTEM service.")
        if elevate_install():
            print("A separate Administrator window is finishing the install.")
            return 0
        print("Could not elevate. Run this from an Administrator prompt:")
        print("  python -m usbkey_guard.setup_app install")
        return 1
    source = Path(config.PACKAGE_ROOT).resolve()
    dest = Path(config.INSTALL_ROOT).resolve()
    # The bootstrap puts `dest` on sys.path, so the package itself must live in
    # `dest\usbkey_guard` -- copying its contents directly into `dest` would
    # make `import usbkey_guard` fail for the SYSTEM task.
    pkg_dest = dest / "usbkey_guard"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        if source == pkg_dest:
            print("Package already lives in", pkg_dest)
        else:
            shutil.copytree(source, pkg_dest, dirs_exist_ok=True)
            print("Files installed to", pkg_dest)
        _write_bootstrap(
            ENFORCER_BOOTSTRAP,
            _ENFORCER_SOURCE.format(
                install=str(dest),
                logfile=str(Path(config.STATE_ROOT) / "logs" / "enforcer-boot.log"),
            ),
        )
        _write_bootstrap(TUI_BOOTSTRAP, _TUI_SOURCE.format(install=str(dest)))
        (dest / VERSION_MARKER).write_text(__version__ + "\n", encoding="utf-8")
    except OSError as exc:
        print("ERROR copying files:", exc)
        return 1

    try:
        paths.ensure_state_tree()
        if acl.allow_state_writes(str(config.STATE_ROOT)):
            print("State folder writable by local users:", config.STATE_ROOT)
        else:
            print("State folder kept admin-only (hardened):", config.STATE_ROOT)
    except OSError as exc:
        print("WARNING: could not prepare the state folder:", exc)

    menu = start_menu_dir()
    menu.mkdir(parents=True, exist_ok=True)
    launcher = menu / "usbkey TUI.bat"
    script = dest / TUI_BOOTSTRAP
    # Bytes, not text: text mode turns the explicit CRLF into CR CR LF, which
    # cmd.exe mis-parses inside the parenthesised block (the launcher then just
    # flashes and closes).
    launcher.write_bytes(
        (
            "@echo off\r\n"
            "title usbkey\r\n"
            f'if exist "{python_console()}" (\r\n'
            f'  "{python_console()}" "{script}"\r\n'
            "  goto end\r\n"
            ")\r\n"
            "where py >nul 2>nul\r\n"
            "if %errorlevel%==0 (\r\n"
            f'  py "{script}"\r\n'
            "  goto end\r\n"
            ")\r\n"
            "where python >nul 2>nul\r\n"
            "if %errorlevel%==0 (\r\n"
            f'  python "{script}"\r\n'
            "  goto end\r\n"
            ")\r\n"
            "echo.\r\n"
            "echo Python was not found. Install Python 3.11/3.12, then run:\r\n"
            "echo   pip install usbkey-guard\r\n"
            "echo   usbkey-setup install\r\n"
            ":end\r\n"
            "echo.\r\n"
            "pause\r\n"
        ).encode("utf-8")
    )
    shortcut = _write_shortcut(menu / "usbkey TUI.lnk", launcher)
    print("Start menu entry (all users):", shortcut or launcher)
    if not interpreter_is_shared():
        print()
        print("NOTE: this Python lives in a user profile:")
        print("   ", sys.executable)
        print("The all-users Start menu entry points at it, so it works for this")
        print("account (and for the SYSTEM service) but other users get 'Access is")
        print("denied'. For a machine-wide install, use a Python installed for all")
        print("users, e.g. python.org with 'Install for all users'.")
    print("Optional: `usbkey-setup harden` restricts the state folder to admins")
    print("(non-admin users then cannot create new vaults).")

    problem = interpreter_problem()
    if problem:
        print()
        print("WARNING:", problem)
        print("The service would start and exit immediately.")
        print("Fix (elevated PowerShell):", dependency_fix())
        print("Then run install again.")
    rc = _create_task()
    if rc != 0:
        return rc
    started = _start_service()
    return 1 if (problem or started) else 0


def _state_is_purgeable(path: Path) -> bool:
    """Only a nested folder can be the state root; never a drive or a top folder."""
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    return len(resolved.parts) >= 3


def _purge_state() -> int:
    root = Path(config.STATE_ROOT)
    if not root.exists():
        print("State folder already gone:", root)
        return 0
    if not _state_is_purgeable(root):
        print("Refusing to delete an unexpectedly shallow state folder:", root)
        return 1
    try:
        shutil.rmtree(root)
    except OSError as exc:
        print("WARNING: could not remove the state folder:", exc)
        print("Delete it manually:", root)
        return 1
    print("State folder removed:", root)
    return 0


def _stop_enforcer_processes() -> None:
    """A deleted task can leave its pythonw behind; stop that one only."""
    script = str(Path(config.INSTALL_ROOT) / ENFORCER_BOOTSTRAP).lower()
    try:
        import psutil
    except ImportError:
        return
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join((proc.info or {}).get("cmdline") or []).lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        if script not in cmd:
            continue
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            try:
                proc.kill()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue


def _remove_desktop_shortcut() -> None:
    desktop = Path(os.environ.get("USERPROFILE") or Path.home()) / "Desktop"
    link = desktop / "usbkey TUI.lnk"
    if not link.is_file():
        return
    try:
        link.unlink()
        print("Desktop shortcut removed.")
    except OSError as exc:
        print("WARNING: could not remove the desktop shortcut:", exc)


def _run_elevated(source: str, name: str) -> bool:
    helper = Path(tempfile.gettempdir()) / name
    try:
        helper.write_text(source, encoding="utf-8")
    except OSError as exc:
        print("could not write the helper script:", exc)
        return False
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", str(python_console()), f'"{helper}"', None, 1)
    except Exception as exc:
        print("could not start the elevated step:", exc)
        return False
    if rc <= 32:
        print("Windows refused to elevate (code", rc, ").")
        return False
    return True


def elevate_install() -> bool:
    """Run `install` elevated, importing the package this process is using."""
    root = str(Path(config.PACKAGE_ROOT).parent)
    return _run_elevated(_INSTALL_HELPER.format(root=root), "usbkey-install.py")


def elevate_uninstall() -> bool:
    """Ask Windows for elevation and finish the removal in its own console.

    The TUI runs unelevated; deleting the SYSTEM task and Program Files needs an
    administrator. UAC keeps the same user, so the helper can also uninstall the
    pip package from that user's site-packages.
    """
    return _run_elevated(
        _UNINSTALL_HELPER.format(install=str(config.INSTALL_ROOT)),
        "usbkey-uninstall.py")


def uninstall(purge: bool = False) -> int:
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    subprocess.run(["schtasks", "/end", "/tn", config.TASK_NAME],
                   capture_output=True, text=True)
    subprocess.run(["schtasks", "/delete", "/tn", config.TASK_NAME, "/f"],
                   capture_output=True, text=True)
    print("Scheduled task removed.")
    _stop_enforcer_processes()
    menu = start_menu_dir()
    if menu.exists():
        _assert_own_install_root(menu)
        shutil.rmtree(menu)
        print("Start menu entry removed.")
    _remove_desktop_shortcut()
    if config.INSTALL_ROOT.exists():
        _assert_own_install_root(config.INSTALL_ROOT)
        shutil.rmtree(config.INSTALL_ROOT)
        print("Program Files copy removed.")
    if purge:
        return _purge_state()
    print("State in", config.STATE_ROOT, "was preserved (encrypted vaults stay safe).")
    return 0


def repair_permissions() -> int:
    """Re-grant local users write access to the state folder.

    Needed on installs made before 1.0.6, where files written by SYSTEM were
    read-only for a normal desktop session and every vault action failed with
    "Access is denied" on vaults.json.
    """
    if not is_admin():
        print("ERROR: run this as Administrator.")
        return 1
    paths.ensure_state_tree()
    ok = acl.allow_state_writes(str(config.STATE_ROOT))
    print("State folder:", config.STATE_ROOT)
    if ok:
        print("Writable by local users: yes (the TUI now works without elevation)")
        return 0
    print("Writable by local users: no")
    print("If you ran `usbkey-setup harden`, this is expected: only administrators")
    print("can change vaults then. Otherwise run this from an elevated prompt.")
    return 1


def status() -> int:
    print("Python:", sys.executable)
    print("Usable by other users:",
          "yes" if interpreter_is_shared() else "no (it is inside a user profile)")
    info = task_info()
    running = info.get("state") == TASK_STATE_RUNNING
    print("Service:", "running" if running else "NOT running")
    if not info.get("exists"):
        print("Task:", config.TASK_NAME, "not found - run install")
    else:
        print("Task state:", _state_name(info["state"]),
              "| last result:", _explain_result(info["last_result"]))
        last_run = info.get("last_run")
        if last_run:
            print("Last run:", last_run)
        warning = _settings_warning(info.get("xml", ""))
        if warning:
            print(warning)
    problem = interpreter_problem()
    if problem:
        print("WARNING:", problem)
        print("The service cannot run until that Python can import the package.")
    if not running and info.get("exists"):
        print()
        print_service_diagnosis(info)
    return 0 if running else 1


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="usbkey-setup")
    p.add_argument("action", choices=["install", "uninstall", "status", "harden",
                                      "repair-permissions"])
    p.add_argument("--purge", action="store_true",
                   help="with uninstall: also delete the state folder")
    args = p.parse_args(argv)
    if args.action == "harden":
        if not is_admin():
            print("ERROR: run this as Administrator.")
            return 1
        return 0 if harden_state() else 1
    if args.action == "uninstall":
        return uninstall(purge=args.purge)
    return {"install": install, "status": status,
            "repair-permissions": repair_permissions}[args.action]()


if __name__ == "__main__":
    sys.exit(main())
