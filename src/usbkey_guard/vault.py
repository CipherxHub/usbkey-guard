r"""AES-GCM encrypted vault. Admin-proof: without the USB + passphrase the
files on disk are ciphertext, so permissions are irrelevant.

Safety ordering is strict:
  1. encrypt every file and write ciphertext to the vault
  2. verify by decrypting each ciphertext in memory and comparing hashes
  3. only then remove plaintext originals, and only those that still match

Locking likewise refuses to delete any plaintext file whose hash has changed
since unlock, so edited work is never destroyed.
"""
import getpass
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keystore, paths, snapshot
from .log import get_log

_log = get_log("vault")
CONFIG = paths.STATE_ROOT / "vaults.json"
BACKUP = paths.STATE_ROOT / "vault-backup"
NONCE_LEN = 12
CHUNK = 64 * 1024 * 1024  # refuse files larger than 64 MB for whole-file AEAD


def _read_config() -> dict[str, Any]:
    paths.ensure_state_tree()
    if not CONFIG.exists():
        return {"vaults": []}
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"vaults": []}


def _write_config(cfg: dict[str, Any]) -> None:
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(CONFIG)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity() -> dict[str, str]:
    from . import enforce
    return enforce.load_config().get("identity") or {}


def _usb_material() -> tuple[bytes, dict[str, str]]:
    ident = _identity()
    drive = keystore.find_key(ident)
    if not drive:
        raise PermissionError("USB key not present")
    payload = json.loads((Path(drive) / "key.dat").read_text(encoding="utf-8"))
    return payload["secret"].encode(), ident


def derive_key(passphrase: str, salt: bytes) -> bytes:
    secret, ident = _usb_material()
    material = (
        passphrase.encode("utf-8") + b"|" + secret + b"|"
        + ident["volume_guid"].encode() + b"|" + ident["serial"].encode()
    )
    return hashlib.scrypt(material, salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def _prompt() -> str:
    return getpass.getpass("Vault passphrase: ")


def _vault_config(vault_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = _read_config()
    for v in cfg["vaults"]:
        if v["id"] == vault_id:
            return cfg, v
    raise KeyError("unknown vault: " + vault_id)


def _manifest(v: dict[str, Any]) -> dict[str, Any]:
    return json.loads((Path(v["vault_dir"]) / "manifest.json").read_text(encoding="utf-8"))


def _enc_path(v: dict[str, Any], name: str) -> Path:
    return Path(v["vault_dir"]) / "data" / name


def convert(work_dir: str, vault_dir: str, passphrase: str | None = None,
            yes: bool = False) -> dict[str, Any]:
    """Encrypt a plaintext folder into the vault and verify before removing plaintext."""
    target = Path(work_dir)
    vault = Path(vault_dir)
    if target.is_file():
        # Encrypt just this one file; the work folder is its parent.
        work = target.parent
        files = [target]
    elif target.is_dir():
        work = target
        files = sorted(p for p in work.rglob("*") if p.is_file())
    else:
        raise ValueError("path does not exist: " + str(target))
    if vault.exists():
        # An empty folder is a valid destination; a populated one is never touched.
        if not (vault.is_dir() and not any(vault.iterdir())):
            raise ValueError("vault path exists and is not empty: " + str(vault))
    if not yes:
        raise PermissionError("pass --yes to confirm conversion")
    for f in files:
        if f.stat().st_size > CHUNK:
            raise ValueError("file too large for this vault format: " + str(f))

    salt = os.urandom(16)
    key = derive_key(passphrase or _prompt(), salt)
    vault.mkdir(parents=True, exist_ok=True)
    (vault / "data").mkdir(exist_ok=True)

    manifest: dict[str, Any] = {
        "v": 1,
        "id": hashlib.sha256(
            (str(target) if target.is_file() else str(work)).encode("utf-8")
        ).hexdigest()[:16],
        "work_dir": str(work),
        "vault_dir": str(vault),
        "salt": salt.hex(),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_file": str(target) if target.is_file() else None,
        "files": [],
    }
    aead = AESGCM(key)
    for i, src in enumerate(files):
        rel = src.relative_to(work).as_posix()
        data = src.read_bytes()
        nonce = os.urandom(NONCE_LEN)
        enc = nonce + aead.encrypt(nonce, data, rel.encode("utf-8"))
        name = f"{i:05d}.enc"
        _enc_path({"vault_dir": str(vault)}, name).write_bytes(enc)
        manifest["files"].append({
            "rel": rel, "enc": name, "nonce": nonce.hex(),
            "size": len(data), "sha256": _sha(data), "enc_sha256": _sha(enc),
        })
        # Immediate in-memory verification before any plaintext is touched.
        if aead.decrypt(nonce, enc[NONCE_LEN:], rel.encode("utf-8")) != data:
            raise RuntimeError("encryption verification failed for " + rel)

    (vault / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    verify(manifest)

    # Only now remove plaintext, and only the exact files just verified.
    for entry in manifest["files"]:
        target = work / entry["rel"]
        if target.is_file() and _sha(target.read_bytes()) == entry["sha256"]:
            os.remove(target)
        else:
            raise RuntimeError("plaintext changed during conversion; refusing to delete: " + str(target))

    cfg = _read_config()
    cfg["vaults"].append({
        "id": manifest["id"], "work_dir": str(work), "vault_dir": str(vault),
        "source_file": manifest.get("source_file"),
    })
    _write_config(cfg)
    BACKUP.mkdir(parents=True, exist_ok=True)
    (BACKUP / manifest["id"]).mkdir(exist_ok=True)
    (BACKUP / manifest["id"] / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    _log.info("converted %s to vault %s (%d files)", work, vault, len(files))
    return manifest


def unlock(vault_id: str, passphrase: str | None = None) -> list[str]:
    cfg, v = _vault_config(vault_id)
    m = _manifest(v)
    key = derive_key(passphrase or _prompt(), bytes.fromhex(m["salt"]))
    aead = AESGCM(key)
    restored = []
    for entry in m["files"]:
        enc = _enc_path(v, entry["enc"]).read_bytes()
        if _sha(enc) != entry["enc_sha256"]:
            raise RuntimeError("ciphertext integrity failure: " + entry["enc"])
        data = aead.decrypt(bytes.fromhex(entry["nonce"]), enc[NONCE_LEN:],
                            entry["rel"].encode("utf-8"))
        if _sha(data) != entry["sha256"]:
            raise RuntimeError("plaintext hash failure: " + entry["rel"])
        target = Path(v["work_dir"]) / entry["rel"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        restored.append(entry["rel"])
    _log.info("unlocked vault %s (%d files)", vault_id, len(restored))
    return restored


def lock(vault_id: str) -> list[str]:
    """Remove plaintext, but only when it still matches the verified ciphertext."""
    cfg, v = _vault_config(vault_id)
    m = _manifest(v)
    removed = []
    for entry in m["files"]:
        target = Path(v["work_dir"]) / entry["rel"]
        if not target.is_file():
            continue
        if _sha(target.read_bytes()) != entry["sha256"]:
            _log.error("refusing to delete modified file: %s", target)
            raise RuntimeError(
                "file changed since unlock, not deleting to avoid data loss: " + str(target)
            )
        os.remove(target)
        removed.append(entry["rel"])
    _log.info("locked vault %s (%d files removed)", vault_id, len(removed))
    return removed


def lock_all() -> list[str]:
    out = []
    for v in _read_config()["vaults"]:
        out += [f"{v['id']}: {name}" for name in lock(v["id"])]
    return out


def verify(vault_id: str | dict[str, Any] | None = None) -> list[str]:
    problems: list[str] = []
    vaults = _read_config()["vaults"]
    if isinstance(vault_id, str):
        vaults = [v for v in vaults if v["id"] == vault_id]
    elif isinstance(vault_id, dict):
        vaults = [{"id": vault_id["id"], "work_dir": vault_id["work_dir"],
                   "vault_dir": vault_id["vault_dir"]}]
    for v in vaults:
        m = _manifest(v)
        for entry in m["files"]:
            p = _enc_path(v, entry["enc"])
            if not p.is_file():
                problems.append(f"{v['id']}: missing ciphertext {entry['enc']}")
            elif _sha(p.read_bytes()) != entry["enc_sha256"]:
                problems.append(f"{v['id']}: ciphertext hash mismatch {entry['enc']}")
            plaintext = Path(v["work_dir"]) / entry["rel"]
            if plaintext.is_file() and _sha(plaintext.read_bytes()) != entry["sha256"]:
                problems.append(f"{v['id']}: plaintext differs from vault {entry['rel']}")
    return problems


def attach(vault_dir: str) -> dict[str, Any]:
    """Register an existing encrypted folder (recovery / reinstall)."""
    m = _manifest({"vault_dir": vault_dir})
    cfg = _read_config()
    if any(v["id"] == m["id"] for v in cfg["vaults"]):
        raise ValueError("vault already registered: " + m["id"])
    cfg["vaults"].append({
        "id": m["id"],
        "work_dir": m["work_dir"],
        "vault_dir": str(vault_dir),
        "source_file": m.get("source_file"),
    })
    _write_config(cfg)
    return m


def list_vaults() -> list[dict[str, Any]]:
    """Public read-only list of configured vaults."""
    return list(_read_config()["vaults"])


def status() -> list[str]:
    lines = []
    for v in _read_config()["vaults"]:
        m = _manifest(v)
        present = sum(
            1 for e in m["files"] if (Path(v["work_dir"]) / e["rel"]).is_file()
        )
        state = "UNLOCKED" if present else "LOCKED"
        label = v.get("source_file") or v["work_dir"]
        lines.append(f"{v['id']}  {state}  {present}/{len(m['files'])} files  {label}")
    return lines or ["no vaults configured"]
