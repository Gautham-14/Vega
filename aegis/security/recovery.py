"""Encrypted, authenticated offline snapshot of Aegis operational state.

Model weights and temporary workspaces are deliberately excluded. Stop the
server before a snapshot so adjacent managed files cannot race with the DB.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis import config
from aegis.control import store
from aegis.security.private_files import no_links, restrict_permissions
from aegis.storage.paths import safe_filename

MAGIC = b"AEGIS-BACKUP-1\n"
MAX_PLAINTEXT = 128 * 1024 * 1024
MANAGED_DIRS = ("knowledge", "receipts", "artifacts")


def _key(passphrase: str, salt: bytes) -> bytes:
    if not 16 <= len(passphrase) <= 256:
        raise ValueError("Backup passphrase must contain 16-256 characters")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=32768, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def _db_snapshot() -> bytes:
    no_links(config.DB_PATH)
    if not config.DB_PATH.is_file():
        raise ValueError("No Aegis database exists to back up")
    with sqlite3.connect(config.DB_PATH) as source, sqlite3.connect(":memory:") as target:
        source.backup(target)
        return target.serialize()


def _valid_database(raw: bytes, secret: bytes) -> None:
    if len(secret) != 32 or len(raw) > MAX_PLAINTEXT:
        raise ValueError("Backup key or database is invalid")
    with sqlite3.connect(":memory:") as conn:
        try:
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.deserialize(raw)
            conn.row_factory = sqlite3.Row
            schema = conn.execute("SELECT type,sql FROM sqlite_schema").fetchall()
            if any(row["type"] in {"trigger", "view"} or "CREATE VIRTUAL TABLE" in (row["sql"] or "").upper()
                   for row in schema):
                raise ValueError("Backup database contains unsupported executable schema")
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Database integrity check failed")
            rows = conn.execute("SELECT * FROM control_receipts ORDER BY sequence").fetchall()
            head = conn.execute("SELECT * FROM control_head WHERE singleton=1").fetchone()
        except sqlite3.DatabaseError as error:
            raise ValueError("Backup database is invalid") from error
    if not store.verify_rows(rows, head, secret):
        raise ValueError("Backup receipt chain is invalid")


def _managed_files() -> dict[str, dict[str, str | int]]:
    result = {}
    total = 0
    for directory in MANAGED_DIRS:
        root = no_links(config.DATA_DIR / directory)
        if not root.exists():
            continue
        for path in root.rglob("*"):
            no_links(path)
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError("Managed storage contains a non-regular file")
            size = path.stat().st_size
            total += size
            if total > MAX_PLAINTEXT:
                raise ValueError("Managed files exceed the bounded backup limit")
            with path.open("rb") as stream:
                data = stream.read(size + 1)
            if len(data) != size:
                raise ValueError("Managed file changed during backup; stop the server and retry")
            name = path.relative_to(config.DATA_DIR).as_posix()
            result[name] = {"sha256": hashlib.sha256(data).hexdigest(), "data": base64.b64encode(data).decode()}
    return result


def _payload() -> bytes:
    if not (config.DATA_DIR / "control.key").is_file() and not (config.DATA_DIR / "control.key.dpapi").is_file():
        raise ValueError("Live control key is missing; refuse to create a new key during backup")
    secret = store.secret()
    database = _db_snapshot()
    _valid_database(database, secret)
    payload = {"version": 1, "created_at": int(time.time()),
               "database_sha256": hashlib.sha256(database).hexdigest(),
               "database": base64.b64encode(database).decode(),
               "control_key": base64.b64encode(secret).decode(), "files": _managed_files()}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_PLAINTEXT:
        raise ValueError("Operational state exceeds the bounded backup limit")
    return raw


def create_backup(path: str | Path, passphrase: str) -> dict:
    destination = no_links(path)
    if destination.is_relative_to(config.DATA_DIR):
        raise ValueError("Store encrypted backups outside the live Aegis data directory")
    if not destination.parent.is_dir():
        raise ValueError("Backup destination directory does not exist")
    raw = _payload()
    salt, nonce = os.urandom(16), os.urandom(12)
    encrypted = MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, raw, MAGIC)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        restrict_permissions(destination)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        destination.unlink(missing_ok=True)
        raise
    verify_backup(destination, passphrase)
    protection = store.protect_secret()
    return {"path": str(destination), "sha256": hashlib.sha256(encrypted).hexdigest(),
            "bytes": len(encrypted), "scope": "database, control key, knowledge, receipts, artifacts",
            "live_key_protection": protection}


def _decode_backup(path: str | Path, passphrase: str) -> tuple[bytes, dict[str, bytes], int]:
    source = no_links(path)
    if not source.is_file() or source.stat().st_size > MAX_PLAINTEXT + 4096:
        raise ValueError("Backup file is absent or exceeds the bounded size")
    with source.open("rb") as stream:
        encrypted = stream.read(MAX_PLAINTEXT + 4097)
    if len(encrypted) > MAX_PLAINTEXT + 4096:
        raise ValueError("Backup exceeds the bounded size")
    if not encrypted.startswith(MAGIC) or len(encrypted) < len(MAGIC) + 16 + 12 + 16:
        raise ValueError("Unsupported or truncated backup")
    at = len(MAGIC)
    salt, nonce, ciphertext = encrypted[at:at+16], encrypted[at+16:at+28], encrypted[at+28:]
    try:
        raw = AESGCM(_key(passphrase, salt)).decrypt(nonce, ciphertext, MAGIC)
        if len(raw) > MAX_PLAINTEXT:
            raise ValueError
        payload = json.loads(raw)
        if payload["version"] != 1 or not isinstance(payload["files"], dict):
            raise ValueError
        db = base64.b64decode(payload["database"], validate=True)
        secret = base64.b64decode(payload["control_key"], validate=True)
        if hashlib.sha256(db).hexdigest() != payload["database_sha256"]:
            raise ValueError
        _valid_database(db, secret)
        files = {"db/aegis.db": db, "control.key": secret}
        portable_paths = set()
        for name, entry in payload["files"].items():
            pure = PurePosixPath(name)
            if (not isinstance(name, str) or "\\" in name or pure.is_absolute() or pure.as_posix() != name or
                    len(pure.parts) < 2 or pure.parts[0] not in MANAGED_DIRS or
                    any(part in {".", "..", ""} for part in pure.parts) or name in files):
                raise ValueError
            for part in pure.parts:
                safe_filename(part)
            normalized = name.casefold()
            if normalized in portable_paths:
                raise ValueError("Duplicate portable restore path")
            portable_paths.add(normalized)
            data = base64.b64decode(entry["data"], validate=True)
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError
            files[name] = data
        for name in portable_paths:
            if any(parent.as_posix() in portable_paths for parent in PurePosixPath(name).parents):
                raise ValueError("Restore file conflicts with a directory")
        if sum(map(len, files.values())) > MAX_PLAINTEXT:
            raise ValueError
        return encrypted, files, int(payload["created_at"])
    except (KeyError, TypeError, ValueError, OverflowError, binascii.Error) as error:
        raise ValueError("Backup authentication or contents are invalid") from error
    except Exception as error:
        from cryptography.exceptions import InvalidTag
        if isinstance(error, InvalidTag):
            raise ValueError("Backup passphrase is wrong or archive was changed") from error
        raise


def verify_backup(path: str | Path, passphrase: str) -> dict:
    encrypted, files, created_at = _decode_backup(path, passphrase)
    return {"valid": True, "sha256": hashlib.sha256(encrypted).hexdigest(),
            "created_at": created_at, "files": len(files), "scope": "operational state; model weights excluded"}


def _restore_files(files: dict[str, bytes]) -> dict[str, bytes]:
    """Restoring old state must not revive sessions or execution approvals."""
    with sqlite3.connect(":memory:") as conn:
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.deserialize(files["db/aegis.db"])
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        if "auth_sessions" in tables:
            conn.execute("DELETE FROM auth_sessions")
        if "control_objects" in tables:
            for kind, identity, raw in conn.execute("SELECT kind,id,body FROM control_objects WHERE kind IN ('approval','capsule')").fetchall():
                value = json.loads(raw)
                value.pop("seal", None)
                value["status"] = "UNAPPROVED" if kind == "capsule" else "RESTORED_REVIEW_REQUIRED"
                conn.execute("UPDATE control_objects SET body=? WHERE kind=? AND id=?", (store.canonical(value), kind, identity))
        conn.commit()
        result = {**files, "db/aegis.db": conn.serialize()}
    _valid_database(result["db/aegis.db"], result["control.key"])
    return result


def restore_backup(path: str | Path, destination: str | Path, passphrase: str) -> dict:
    encrypted, files, created_at = _decode_backup(path, passphrase)
    files = _restore_files(files)
    target = no_links(destination)
    if target.exists() or not target.parent.is_dir():
        raise ValueError("Restore requires a new directory under an existing parent")
    stage = Path(tempfile.mkdtemp(prefix=".aegis-restore-", dir=target.parent))
    try:
        restrict_permissions(stage, directory=True)
        for name, data in files.items():
            if name == "control.key" and os.name == "nt":
                from aegis.security.dpapi import protect
                name, data = "control.key.dpapi", protect(data)
            path_out = stage.joinpath(*PurePosixPath(name).parts)
            path_out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            restrict_permissions(path_out.parent, directory=True)
            fd = os.open(path_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                restrict_permissions(path_out)
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
        if target.exists():
            raise ValueError("Restore target appeared during restoration")
        stage.rename(target)
    except Exception:
        import shutil
        shutil.rmtree(stage)
        raise
    return {"restored_to": str(target), "files": len(files), "created_at": created_at,
            "archive_sha256": hashlib.sha256(encrypted).hexdigest(),
            "sessions_revoked": True, "execution_reapproval_required": True,
            "restored_database_sha256": hashlib.sha256(files["db/aegis.db"]).hexdigest(),
            "next_step": "Stop Aegis, set AEGIS_DATA_DIR to this directory, then sign in, verify receipts and request fresh Capsule approvals"}


def drill_backup(path: str | Path, destination: str | Path, passphrase: str) -> dict:
    """Restore to a new directory, then independently reread and check written bytes."""
    _, expected, _ = _decode_backup(path, passphrase)
    expected = _restore_files(expected)
    result = restore_backup(path, destination, passphrase)
    target = no_links(destination)
    for name, original in expected.items():
        actual_name = name
        if name == "control.key" and os.name == "nt":
            from aegis.security.dpapi import unprotect
            actual_name = "control.key.dpapi"
            written = unprotect(no_links(target / actual_name).read_bytes())
        else:
            written = no_links(target.joinpath(*PurePosixPath(name).parts)).read_bytes()
        if hashlib.sha256(written).digest() != hashlib.sha256(original).digest():
            raise ValueError(f"Recovery drill found a changed restored file: {actual_name}")
    key = expected["control.key"]
    _valid_database(no_links(target / "db" / "aegis.db").read_bytes(), key)
    return {**result, "post_restore_verified": True, "receipt_chain_verified": True,
            "recovery_scope": "managed operational state; model weights and user exports excluded",
            "next_step": "Keep the fresh restore for login and representative-content checks; copy archives to separate offline media"}
