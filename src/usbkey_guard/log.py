r"""Rotating file log. Never writes outside the state root.

Logging must never be the reason a command fails: an unprivileged user who can
read the state folder but not append to the log still gets a working CLI.
"""
import logging
from logging.handlers import RotatingFileHandler

from .paths import STATE_ROOT

_LOG_DIR = STATE_ROOT / "logs"
_LOG_FILE = _LOG_DIR / "usbkey.log"
_configured = False


def get_log(name: str = "usbkey") -> logging.Logger:
    global _configured
    if not _configured:
        root = logging.getLogger("usbkey")
        root.setLevel(logging.INFO)
        root.propagate = False
        handler: logging.Handler
        try:
            _LOG_DIR.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                _LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-8s %(name)s %(message)s")
            )
        except OSError:
            # Read-only or denied state folder: keep running, drop the records.
            handler = logging.NullHandler()
        root.addHandler(handler)
        _configured = True
    return logging.getLogger(f"usbkey.{name}")


def redact(value: str) -> str:
    """Keep PINs and key material out of the log."""
    if not value:
        return ""
    return value[:2] + "*" * max(0, len(value) - 4) + value[-2:] if len(value) > 4 else "****"
