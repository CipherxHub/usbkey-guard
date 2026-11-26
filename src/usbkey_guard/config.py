r"""Site-specific paths. All overridable by environment variables."""
import os
from pathlib import Path

APP_NAME = "usbkey"
TASK_NAME = "usbkey-enforcer"

PROGRAMDATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))

STATE_ROOT = Path(
    os.environ.get("USBKEY_STATE", str(PROGRAMDATA / APP_NAME))
).expanduser().resolve()
INSTALL_ROOT = Path(
    os.environ.get("USBKEY_INSTALL", str(PROGRAM_FILES / APP_NAME))
).expanduser().resolve()
PACKAGE_ROOT = Path(__file__).resolve().parent

KEY_FILENAME = "key.dat"
VAULT_SUFFIX = ".vault"
