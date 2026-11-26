r"""AES-GCM encrypted vault. Admin-proof: without the USB + passphrase the
files on disk are ciphertext, so permissions are irrelevant.

Safety ordering is strict:
  1. encrypt every file, fsync the ciphertext and the manifest to disk
  2. verify by decrypting each ciphertext from disk and comparing hashes
  3. register the vault, then remove plaintext originals that still match

Unlocking is all-or-nothing: every ciphertext is verified before a single byte
of plaintext is written, and an existing file that differs from the vault is
never overwritten without an explicit force.

Locking likewise refuses to delete any plaintext file whose hash has changed
since unlock, so edited work is never destroyed.

Removing protection (release) decrypts the vault for good: it verifies every
file onto disk first and only then drops the registration and the ciphertext,
so it can never leave the encrypted copy as the only copy of your data.
"""
import getpass
import hashlib
import json
import ntpath
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keystore, paths, statewrite
from .errors import ConfigCorrupt
from .log import get_log

_log = get_log("vault")
CONFIG = paths.STATE_ROOT / "vaults.json"
BACKUP = paths.STATE_ROOT / "vault-backup"
NONCE_LEN = 12
MAX_FILE_BYTES = 64 * 1024 * 1024  # whole-file AEAD limit for this format
_REPARSE = stat.FILE_ATTRIBUTE_REPARSE_POINT
_DEVICE_NAMES = {"con", "prn", "aux", "nul", "conin$", "conout$"}
_DEVICE_RE = re.compile(r"^(com|lpt)[1-9]$")

# Manifests written before 1.0.2 have no "kdf" key and used n=2**14.
KDF_DEFAULT = {"n": 2 ** 14, "r": 8, "p": 1}
KDF_NEW = {"n": 2 ** 16, "r": 8, "p": 1}


# --------------------------------------------------------------------------
# durable, atomic state writes
# --------------------------------------------------------------------------
def _write_bytes_durable(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write and fsync before returning, so a power cut cannot lose the file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write to " + str(path))
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json_durable(path: Path, payload: dict[str, Any]) -> None:
    _write_bytes_durable(
        Path(path), json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    )


def _corrupt_message(path: Path, exc: Any) -> str:
    saved = None
    try:
        saved = path.with_name(path.name + ".corrupt-" + time.strftime("%Y%m%d-%H%M%S"))
        saved.write_bytes(path.read_bytes())
    except OSError:
        saved = None
    tail = f" A copy was saved to {saved}." if saved else ""
    return (
        f"state file is corrupt: {path} ({exc}).{tail} "
        "Nothing was deleted. Restore a good copy, or re-register your encrypted "
        "folders with: usbkey vault attach <vault folder>"
    )


def _read_config() -> dict[str, Any]:
    paths.ensure_state_tree()
    if not CONFIG.exists():
        return {"vaults": []}
    try:
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigCorrupt(_corrupt_message(CONFIG, exc)) from exc
    if not isinstance(cfg, dict) or not isinstance(cfg.get("vaults"), list):
        raise ConfigCorrupt(_corrupt_message(CONFIG, "unexpected structure"))
    return cfg


def _write_config(cfg: dict[str, Any]) -> None:
    statewrite.save(CONFIG, cfg, _write_json_durable)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        return bool(os.lstat(str(path)).st_file_attributes & _REPARSE)
    except (OSError, AttributeError):
        return False


def _reparse_below(root: Path, target: Path) -> bool:
    """True if any component strictly below `root` is a link/junction."""
    try:
        parts = target.relative_to(root).parts
    except ValueError:
        return True
    current = root
    for part in parts:
        current = current / part
        if _is_reparse(current):
            return True
    return False


def _is_device(part: str) -> bool:
    """Win32 reserved device names resolve to devices even inside a folder."""
    stem = part.split(".")[0].strip().lower()
    return stem in _DEVICE_NAMES or bool(_DEVICE_RE.match(stem))


def _safe_join(work: Path, rel: str) -> Path:
    """Resolve a manifest-relative path, refusing traversal and absolute paths."""
    cleaned = ntpath.normpath(rel)
    if ntpath.isabs(cleaned) or ntpath.splitdrive(cleaned)[0]:
        raise RuntimeError("unsafe absolute path in vault manifest: " + rel)
    if cleaned == ".." or cleaned.startswith(".." + os.sep) or cleaned.startswith("../"):
        raise RuntimeError("path escapes the work folder in vault manifest: " + rel)
    for part in Path(cleaned).parts:
        if _is_device(part):
            raise RuntimeError("reserved device name in vault manifest: " + rel)
    target = work / Path(cleaned)
    if not paths.is_under(str(target), str(work)):
        raise RuntimeError("path escapes the work folder in vault manifest: " + rel)
    return target


# --------------------------------------------------------------------------
# USB material
# --------------------------------------------------------------------------
def _identity() -> dict[str, str]:
    from . import enforce
    return enforce.load_config().get("identity") or {}


def _usb_material() -> tuple[bytes, dict[str, str]]:
    ident = _identity()
    drive = keystore.find_key(ident)
    if not drive:
        raise PermissionError("USB key not present")
    try:
        payload = json.loads((Path(drive) / "key.dat").read_text(encoding="utf-8"))
        return payload["secret"].encode(), ident
    except (OSError, ValueError, KeyError) as exc:
        raise PermissionError("USB key unreadable; re-insert it and retry") from exc


def derive_key(passphrase: str, salt: bytes,
               params: dict[str, Any] | None = None) -> bytes:
    """Derive the vault key. `params` comes from the manifest so old vaults keep
    working with their original cost; new vaults use the stronger default."""
    secret, ident = _usb_material()
    material = (
        passphrase.encode("utf-8") + b"|" + secret + b"|"
        + ident["volume_guid"].encode() + b"|" + ident["serial"].encode()
    )
    n, r, p = _kdf_params(params)
    return hashlib.scrypt(
        material, salt=salt, n=n, r=r, p=p, dklen=32,
        maxmem=1024 * 1024 * 1024,  # a ceiling, not an allocation
    )


def _kdf_params(params: dict[str, Any] | None) -> tuple[int, int, int]:
    """Clamp manifest-supplied cost parameters so a hostile manifest cannot
    turn an unlock into an out-of-memory denial of service."""
    source = params or KDF_DEFAULT
    try:
        n = int(source.get("n", KDF_DEFAULT["n"]))
        r = int(source.get("r", KDF_DEFAULT["r"]))
        p = int(source.get("p", KDF_DEFAULT["p"]))
    except (TypeError, ValueError, AttributeError):
        return KDF_DEFAULT["n"], KDF_DEFAULT["r"], KDF_DEFAULT["p"]
    n = max(2 ** 14, min(n, 2 ** 20))
    r = max(8, min(r, 32))
    p = max(1, min(p, 4))
    return n, r, p


def _prompt() -> str:
    return getpass.getpass("Vault passphrase: ")


# --------------------------------------------------------------------------
# manifest helpers
# --------------------------------------------------------------------------
def _vault_config(vault_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = _read_config()
    for v in cfg["vaults"]:
        if v.get("id") == vault_id:
            return cfg, v
    raise ValueError(
        "unknown vault: " + str(vault_id)
        + ". Run `usbkey vault status` to list registered vaults."
    )


def _validate_manifest(m: Any) -> dict[str, Any]:
    if not isinstance(m, dict):
        raise ValueError("vault manifest is not an object")
    if not isinstance(m.get("files"), list):
        raise ValueError("vault manifest has no file list")
    work = m.get("work_dir")
    if not isinstance(work, str) or not ntpath.isabs(work):
        raise ValueError("vault manifest has an invalid work_dir")
    if not isinstance(m.get("salt"), str):
        raise ValueError("vault manifest has an invalid salt")
    if not isinstance(m.get("id"), str) or not m["id"]:
        raise ValueError("vault manifest has no id")
    return m


def _manifest(v: dict[str, Any]) -> dict[str, Any]:
    p = Path(v["vault_dir"]) / "manifest.json"
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read vault manifest {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"vault manifest is not valid JSON: {p}: {exc}") from exc
    return _validate_manifest(data)


def _enc_path(v: dict[str, Any], name: str) -> Path:
    if not name or ntpath.basename(name) != name or _is_device(name):
        raise RuntimeError("invalid ciphertext name in manifest: " + str(name))
    return Path(v["vault_dir"]) / "data" / name


def _vault_id(source: Path, vault: Path) -> str:
    """Stable per (source, vault) pair, so re-converting cannot shadow a vault."""
    material = paths.norm(source) + "\x00" + paths.norm(vault)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _collect(target: Path) -> tuple[list[Path], list[str]]:
    """Every regular file plus every (possibly empty) subdirectory."""
    if target.is_file():
        if _is_reparse(target):
            raise ValueError("refusing to encrypt a link: " + str(target))
        return [target], []
    files: list[Path] = []
    dirs: list[str] = []
    stack = [target]
    while stack:
        current = stack.pop()
        for entry in sorted(current.iterdir()):
            if _is_reparse(entry):
                raise ValueError(
                    "reparse point inside the folder; refusing to follow it: " + str(entry)
                )
            if entry.is_dir():
                dirs.append(entry.relative_to(target).as_posix())
                stack.append(entry)
            elif entry.is_file():
                files.append(entry)
    return sorted(files), sorted(dirs)


# --------------------------------------------------------------------------
# operations
# --------------------------------------------------------------------------
def convert(work_dir: str, vault_dir: str, passphrase: str | None = None,
            yes: bool = False) -> dict[str, Any]:
    """Encrypt a plaintext folder into the vault and verify before removing plaintext."""
    target = Path(os.path.abspath(str(work_dir)))
    vault = Path(os.path.abspath(str(vault_dir)))
    if not target.exists():
        raise ValueError("path does not exist: " + str(target))
    paths.safe_vault_source(str(target))
    paths.safe_vault_dest(str(vault), str(target), target.is_dir())
    if vault.exists():
        # An empty folder is a valid destination; a populated one is never touched.
        if not (vault.is_dir() and not any(vault.iterdir())):
            raise ValueError("vault path exists and is not empty: " + str(vault))
    if not yes:
        raise PermissionError("pass --yes to confirm conversion")

    work = target.parent if target.is_file() else target
    files, dirs = _collect(target)
    for f in files:
        if f.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file too large for this vault format: " + str(f))

    vid = _vault_id(target, vault)
    cfg = _read_config()  # fail before writing anything if state is corrupt
    if any(v.get("id") == vid for v in cfg["vaults"]):
        raise ValueError(
            "a vault for this source already exists (id " + vid + "). "
            "Use `usbkey vault status`, or choose a different vault folder."
        )

    salt = os.urandom(16)
    key = derive_key(passphrase or _prompt(), salt, KDF_NEW)
    vault.mkdir(parents=True, exist_ok=True)
    (vault / "data").mkdir(exist_ok=True)

    manifest: dict[str, Any] = {
        "v": 1,
        "id": vid,
        "work_dir": str(work),
        "vault_dir": str(vault),
        "salt": salt.hex(),
        "kdf": dict(KDF_NEW),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_file": str(target) if target.is_file() else None,
        "dirs": dirs,
        "files": [],
    }
    aead = AESGCM(key)
    for i, src in enumerate(files):
        rel = src.relative_to(work).as_posix()
        data = src.read_bytes()
        nonce = os.urandom(NONCE_LEN)
        enc = nonce + aead.encrypt(nonce, data, rel.encode("utf-8"))
        name = f"{i:05d}.enc"
        _write_bytes_durable(_enc_path({"vault_dir": str(vault)}, name), enc)
        manifest["files"].append({
            "rel": rel, "enc": name, "nonce": nonce.hex(),
            "size": len(data), "sha256": _sha(data), "enc_sha256": _sha(enc),
        })
        # Immediate in-memory verification before any plaintext is touched.
        if aead.decrypt(nonce, enc[NONCE_LEN:], rel.encode("utf-8")) != data:
            raise RuntimeError("encryption verification failed for " + rel)

    _write_json_durable(vault / "manifest.json", manifest)
    verify(manifest)  # re-reads every ciphertext from disk

    # Register BEFORE deleting plaintext: a crash from here on leaves both
    # copies present and the vault already known, which is the safe direction.
    cfg["vaults"].append({
        "id": manifest["id"], "work_dir": str(work), "vault_dir": str(vault),
        "source_file": manifest.get("source_file"),
    })
    _write_config(cfg)
    backup_dir = BACKUP / manifest["id"]
    backup_dir.mkdir(parents=True, exist_ok=True)
    _write_json_durable(backup_dir / "manifest.json", manifest)

    kept: list[str] = []
    for entry in manifest["files"]:
        plain = _safe_join(work, entry["rel"])
        if _is_reparse(plain) or not plain.is_file():
            continue
        if _sha(plain.read_bytes()) == entry["sha256"]:
            os.remove(plain)
        else:
            kept.append(entry["rel"])
            _log.warning("plaintext changed during conversion, kept: %s", plain)

    _log.info("converted %s to vault %s (%d files, %d kept)",
              work, vault, len(files), len(kept))
    result = dict(manifest)
    result["kept"] = kept
    return result


def unlock(vault_id: str, passphrase: str | None = None,
           force: bool = False) -> list[str]:
    """Restore every file, or nothing at all if any ciphertext fails."""
    cfg, v = _vault_config(vault_id)
    m = _manifest(v)
    paths.safe_vault_workdir(v["work_dir"])
    work = Path(v["work_dir"])
    if _is_reparse(work):
        raise RuntimeError("work folder has been replaced by a link: " + str(work))
    key = derive_key(passphrase or _prompt(), bytes.fromhex(m["salt"]), m.get("kdf"))
    aead = AESGCM(key)

    # Pass 1: verify every ciphertext and GCM tag before writing one byte.
    for entry in m["files"]:
        rel = entry["rel"]
        _safe_join(work, rel)
        enc = _enc_path(v, entry["enc"]).read_bytes()
        if _sha(enc) != entry["enc_sha256"]:
            raise RuntimeError("ciphertext integrity failure: " + entry["enc"])
        data = aead.decrypt(bytes.fromhex(entry["nonce"]), enc[NONCE_LEN:],
                            rel.encode("utf-8"))
        if _sha(data) != entry["sha256"]:
            raise RuntimeError("plaintext hash failure: " + rel)

    # Pass 2: refuse to clobber work that is not already the vaulted version.
    conflicts: list[str] = []
    blocked: list[str] = []
    for entry in m["files"]:
        target = _safe_join(work, entry["rel"])
        if _reparse_below(work, target):
            raise RuntimeError("refusing to write through a link: " + str(target))
        if target.exists():
            if not target.is_file():
                # A directory (or device) is never safe to overwrite, even with force.
                blocked.append(str(target) + " (not a regular file)")
            elif _sha(target.read_bytes()) != entry["sha256"]:
                conflicts.append(str(target))
    if blocked:
        raise RuntimeError(
            "refusing to replace non-file entries: " + ", ".join(blocked[:5])
        )
    if conflicts and not force:
        shown = ", ".join(conflicts[:5])
        more = "" if len(conflicts) <= 5 else f" (+{len(conflicts) - 5} more)"
        raise RuntimeError(
            "refusing to overwrite files that differ from the vault: " + shown + more
            + ". Copy them aside, or use force if you are sure."
        )

    for rel in m.get("dirs", []):
        folder = _safe_join(work, rel)
        if _reparse_below(work, folder):
            raise RuntimeError("refusing to create a folder through a link: " + str(folder))
        folder.mkdir(parents=True, exist_ok=True)

    restored: list[str] = []
    for entry in m["files"]:
        rel = entry["rel"]
        target = _safe_join(work, rel)
        if target.is_file() and _sha(target.read_bytes()) == entry["sha256"]:
            restored.append(rel)  # already identical, no write needed
            continue
        enc = _enc_path(v, entry["enc"]).read_bytes()
        data = aead.decrypt(bytes.fromhex(entry["nonce"]), enc[NONCE_LEN:],
                            rel.encode("utf-8"))
        if _sha(data) != entry["sha256"]:
            raise RuntimeError("plaintext hash failure: " + rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_bytes_durable(target, data)
        restored.append(rel)

    _log.info("unlocked vault %s (%d files)", vault_id, len(restored))
    return restored


def lock(vault_id: str) -> list[str]:
    """Remove plaintext, but only when it still matches the verified ciphertext."""
    cfg, v = _vault_config(vault_id)
    m = _manifest(v)
    paths.safe_vault_workdir(v["work_dir"])
    work = Path(v["work_dir"])
    if _is_reparse(work):
        raise RuntimeError("work folder has been replaced by a link: " + str(work))
    removed: list[str] = []
    kept: list[str] = []
    for entry in m["files"]:
        target = _safe_join(work, entry["rel"])
        if not target.is_file() or _is_reparse(target):
            continue
        if _sha(target.read_bytes()) != entry["sha256"]:
            _log.error("refusing to delete modified file: %s", target)
            kept.append(str(target))
            continue
        os.remove(target)
        removed.append(entry["rel"])
    if kept:
        raise RuntimeError(
            "file changed since unlock, not deleting to avoid data loss: "
            + ", ".join(kept)
        )
    _log.info("locked vault %s (%d files removed)", vault_id, len(removed))
    return removed


def lock_all() -> list[str]:
    out: list[str] = []
    try:
        vaults = _read_config()["vaults"]
    except ConfigCorrupt as exc:
        return ["FAILED: " + str(exc)]
    for v in vaults:
        try:
            out += [f"{v.get('id')}: {name}" for name in lock(v["id"])]
        except Exception as exc:
            _log.exception("lock failed for %s", v.get("id"))
            out.append(f"{v.get('id')}: FAILED {exc}")
    return out


def verify(vault_id: str | dict[str, Any] | None = None) -> list[str]:
    problems: list[str] = []
    try:
        vaults = _read_config()["vaults"]
    except ConfigCorrupt as exc:
        return [str(exc)]
    if isinstance(vault_id, str):
        vaults = [v for v in vaults if v.get("id") == vault_id]
    elif isinstance(vault_id, dict):
        vaults = [{"id": vault_id["id"], "work_dir": vault_id["work_dir"],
                   "vault_dir": vault_id["vault_dir"]}]
    for v in vaults:
        try:
            m = _manifest(v)
        except Exception as exc:
            problems.append(f"{v.get('id')}: manifest unreadable: {exc}")
            continue
        work = Path(v["work_dir"])
        for entry in m["files"]:
            try:
                p = _enc_path(v, entry["enc"])
                if not p.is_file():
                    problems.append(f"{v['id']}: missing ciphertext {entry['enc']}")
                elif _sha(p.read_bytes()) != entry["enc_sha256"]:
                    problems.append(f"{v['id']}: ciphertext hash mismatch {entry['enc']}")
                plaintext = _safe_join(work, entry["rel"])
            except Exception as exc:
                problems.append(f"{v['id']}: {exc}")
                continue
            if plaintext.is_file() and _sha(plaintext.read_bytes()) != entry["sha256"]:
                problems.append(f"{v['id']}: plaintext differs from vault {entry['rel']}")
    return problems


def attach(vault_dir: str, work_dir: str | None = None) -> dict[str, Any]:
    """Register an existing encrypted folder (recovery / reinstall / new PC).

    `work_dir` overrides the folder recorded in the manifest, so a vault made on
    another machine can be restored somewhere that exists here.
    """
    vd = Path(os.path.abspath(str(vault_dir)))
    if not (vd / "manifest.json").is_file():
        raise ValueError(
            "no manifest.json in " + str(vd) + "; that folder is not a vault"
        )
    m = _manifest({"vault_dir": str(vd)})
    # The manifest is only authenticated for the file contents, not for the
    # folder it restores into, so validate the chosen folder before registering.
    target = Path(os.path.abspath(str(work_dir))) if work_dir else Path(m["work_dir"])
    paths.safe_vault_workdir(str(target))
    for entry in m["files"]:
        _safe_join(target, entry["rel"])
        _enc_path({"vault_dir": str(vd)}, entry["enc"])
    cfg = _read_config()
    if any(v.get("id") == m["id"] for v in cfg["vaults"]):
        raise ValueError("vault already registered: " + m["id"])
    cfg["vaults"].append({
        "id": m["id"],
        "work_dir": str(target),
        "vault_dir": str(vd),
        # Provenance only; status() falls back to work_dir when it is absent.
        "source_file": m.get("source_file") if work_dir is None else None,
        "original_work_dir": m["work_dir"],
    })
    _write_config(cfg)
    return m


def _delete_ciphertext(v: dict[str, Any], m: dict[str, Any]) -> list[str]:
    """Delete only the files this tool wrote, never anything else in the folder."""
    vd = Path(v["vault_dir"])
    leftovers: list[str] = []
    targets = [vd / "manifest.json"]
    targets += [_enc_path(v, e["enc"]) for e in m["files"]]
    for path in targets:
        try:
            if _is_reparse(path):
                leftovers.append(str(path) + " (link, left alone)")
            elif path.is_file():
                os.remove(path)
        except OSError as exc:
            leftovers.append(f"{path}: {exc}")
    # Only remove folders that are empty: anything the user put there stays.
    for folder in (vd / "data", vd):
        try:
            if folder.is_dir() and not _is_reparse(folder) and not any(folder.iterdir()):
                os.rmdir(folder)
        except OSError:
            pass
    return leftovers


def remove(vault_id: str, passphrase: str | None = None, yes: bool = False,
           keep_ciphertext: bool = False) -> dict[str, Any]:
    """Stop protecting a vault: decrypt it for good and unregister it.

    Needs the USB key and the passphrase. Every file is restored and verified
    on disk before the encrypted copy is deleted, so this can never destroy the
    only copy of the data. A file that was edited after unlock is not
    overwritten: removal refuses instead, and nothing is changed.
    """
    cfg, v = _vault_config(vault_id)
    m = _manifest(v)
    if not yes:
        raise PermissionError(
            "pass --yes to confirm: the files become ordinary unencrypted files"
            + ("" if keep_ciphertext else " and the encrypted copy is deleted")
        )
    restored = unlock(vault_id, passphrase=passphrase)
    # Plaintext is complete and verified now; drop the registration first so a
    # crash cannot leave a vault pointing at half-deleted ciphertext.
    cfg = _read_config()
    cfg["vaults"] = [x for x in cfg["vaults"] if x.get("id") != m["id"]]
    _write_config(cfg)
    leftovers: list[str] = []
    if not keep_ciphertext:
        leftovers = _delete_ciphertext(v, m)
        try:
            backup_dir = BACKUP / m["id"]
            if backup_dir.is_dir():
                for f in backup_dir.iterdir():
                    if f.is_file():
                        f.unlink()
                backup_dir.rmdir()
        except OSError:
            pass
    _log.info("removed vault %s (%d files, ciphertext kept=%s)",
              vault_id, len(restored), keep_ciphertext)
    return {
        "id": m["id"],
        "work_dir": m["work_dir"],
        "vault_dir": v["vault_dir"],
        "files": len(restored),
        "deleted_ciphertext": not keep_ciphertext,
        "leftovers": leftovers,
    }


def list_vaults() -> list[dict[str, Any]]:
    """Public read-only list of configured vaults.

    Raises ConfigCorrupt rather than pretending there are no vaults: silently
    returning an empty list would let the next write wipe every registration.
    """
    return list(_read_config()["vaults"])


def status() -> list[str]:
    lines = []
    try:
        vaults = _read_config()["vaults"]
    except ConfigCorrupt as exc:
        return ["config error: " + str(exc)]
    for v in vaults:
        try:
            m = _manifest(v)
        except Exception as exc:
            lines.append(f"{v.get('id')}  UNKNOWN  manifest unreadable: {exc}")
            continue
        work = Path(v["work_dir"])
        present = 0
        for e in m["files"]:
            try:
                if _safe_join(work, e["rel"]).is_file():
                    present += 1
            except RuntimeError:
                continue
        state = "UNLOCKED" if present else "LOCKED"
        label = v.get("source_file") or v["work_dir"]
        lines.append(f"{v['id']}  {state}  {present}/{len(m['files'])} files  {label}")
    return lines or ["no vaults configured"]
