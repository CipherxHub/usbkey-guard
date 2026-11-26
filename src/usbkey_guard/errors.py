r"""Typed errors and deterministic exit codes."""

EXIT_OK = 0
EXIT_NO_KEY = 2
EXIT_KEY_MISMATCH = 3
EXIT_JOURNAL_UNRECONCILED = 4
EXIT_DENIED = 5
EXIT_VERIFY_DRIFT = 6
EXIT_AUDIT_REFUSED = 7
EXIT_MUTEX_HELD = 8
EXIT_STATE_CORRUPT = 9


class UsbKeyError(Exception):
    code = 1


class KeyAbsent(UsbKeyError):
    code = EXIT_NO_KEY


class KeyMismatch(UsbKeyError):
    code = EXIT_KEY_MISMATCH


class JournalUnreconciled(UsbKeyError):
    code = EXIT_JOURNAL_UNRECONCILED


class PermissionProblem(UsbKeyError):
    code = EXIT_DENIED


class VerifyDrift(UsbKeyError):
    code = EXIT_VERIFY_DRIFT


class AuditRefused(UsbKeyError):
    code = EXIT_AUDIT_REFUSED


class MutexHeld(UsbKeyError):
    code = EXIT_MUTEX_HELD


class ConfigCorrupt(UsbKeyError):
    """A state file exists but cannot be parsed. Never silently reset it."""

    code = EXIT_STATE_CORRUPT
