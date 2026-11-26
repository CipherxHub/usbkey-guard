r"""Append-only, checksummed write-ahead journal and atomic state snapshot.

Every mutation must write an `intent` record and fsync it BEFORE touching a
protected object, then a `done` record after. Records are self-checksumming so a
torn write at the tail can be detected and discarded safely.
"""
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from . import statewrite
from .paths import STATE_ROOT, ensure_state_tree

WAL = STATE_ROOT / "journal" / "wal.log"
STATE = STATE_ROOT / "journal" / "state.json"
MAX_WAL_BYTES = 5 * 1024 * 1024
KEEP_GENERATIONS = 5


def _digest(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _fsync(path: Path) -> None:
    fd = os.open(str(path), os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    def __init__(self) -> None:
        ensure_state_tree()
        WAL.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        if not WAL.exists() or WAL.stat().st_size < MAX_WAL_BYTES:
            return
        for i in range(KEEP_GENERATIONS - 1, 0, -1):
            src = WAL.with_name(f"wal.{i}.log")
            if src.exists():
                os.replace(src, WAL.with_name(f"wal.{i + 1}.log"))
        os.replace(WAL, WAL.with_name("wal.1.log"))

    def _append(self, record: dict[str, Any]) -> dict[str, Any]:
        self._rotate_if_needed()
        payload = dict(record)
        payload["ts"] = payload.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload.setdefault("rid", uuid.uuid4().hex)
        payload["crc"] = _digest(payload)
        line = (json.dumps(payload, sort_keys=True, default=str) + "\n").encode("utf-8")
        fd = os.open(str(WAL), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return payload

    def intent(self, op: str, root_id: str, path: str, pre: dict[str, Any],
               planned: dict[str, Any]) -> dict[str, Any]:
        return self._append({
            "op": op, "phase": "intent", "root": root_id, "path": path,
            "pre": pre, "planned": planned,
        })

    def done(self, intent_rid: str, post: dict[str, Any]) -> dict[str, Any]:
        return self._append({
            "op": "done", "phase": "done", "intent": intent_rid, "post": post,
        })

    def reconciled(self, intent_rid: str, note: str = "") -> dict[str, Any]:
        return self._append({
            "op": "reconciled", "phase": "reconciled",
            "intent": intent_rid, "note": note,
        })

    def records(self) -> list[dict[str, Any]]:
        """Read records in order; stop at the first torn/corrupt line."""
        if not WAL.exists():
            return []
        out = []
        with open(WAL, "rb") as f:
            for raw in f:
                try:
                    record = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    break
                crc = record.pop("crc", None)
                if crc != _digest(record):
                    break
                out.append(record)
        return out

    def unreconciled(self) -> list[dict[str, Any]]:
        records = self.records()
        done = {r.get("intent") for r in records if r.get("phase") == "done"}
        fixed = {r.get("intent") for r in records if r.get("phase") == "reconciled"}
        return [
            r for r in records
            if r.get("phase") == "intent" and r["rid"] not in done | fixed
        ]

    def read_state(self) -> dict[str, Any]:
        if not STATE.exists():
            return {}
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def commit_state(self, state: dict[str, Any]) -> None:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(tmp, STATE)
        except PermissionError as exc:
            statewrite.discard(tmp)
            raise statewrite.permission_error(STATE, exc) from exc
        _fsync(STATE)
