"""Cross-process admission leases and bounded managed storage.

Expired leases recover after a crash. Ledger rows are never silently discarded.
Resource denial does not append another receipt and amplify an exhausted ledger.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

from fastapi import HTTPException
from aegis import config
from aegis.storage.database import get_db_connection

actor_context = ContextVar("aegis_actor", default="local")
_budget_lock = threading.RLock()
_budget = {}


def bounded_setting(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, default))
    except (ValueError, TypeError):
        raise RuntimeError("Invalid resource limit: " + name) from None
    if not minimum <= value <= maximum:
        raise RuntimeError("Resource limit outside permitted bounds: " + name)
    return value


@contextmanager
def admit(kind, actor=None, provider=""):
    actor = actor or actor_context.get()
    global_limit = 16 if kind == "http" else 4
    actor_limit = 4 if kind == "http" else 2
    identity = uuid.uuid4().hex
    now = time.time()
    with get_db_connection() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS admission_leases (id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor TEXT NOT NULL, provider TEXT NOT NULL, expires_at REAL NOT NULL)")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM admission_leases WHERE expires_at<=?", (now,))
        rows = conn.execute("SELECT actor,provider FROM admission_leases WHERE kind=?", (kind,)).fetchall()
        if (len(rows) >= global_limit or sum(row["actor"] == actor for row in rows) >= actor_limit
            or (kind == "provider" and sum(row["provider"] == provider for row in rows) >= 2)):
            raise HTTPException(429, "Resource budget exhausted; retry after active work completes", headers={"Retry-After": "5"})
        conn.execute("INSERT INTO admission_leases VALUES(?,?,?,?,?)", (identity, kind, actor, provider, now + 300))
    try:
        storage_budget()
        stopped = threading.Event()
        def renew():
            while not stopped.wait(30):
                try:
                    with get_db_connection() as conn:
                        conn.execute("UPDATE admission_leases SET expires_at=? WHERE id=?", (time.time() + 300, identity))
                except Exception:
                    # Storage failure blocks subsequent admission. Do not create
                    # recursively growing error records during disk exhaustion.
                    return
        heartbeat = threading.Thread(target=renew, daemon=True)
        heartbeat.start()
        yield
    finally:
        if "stopped" in locals():
            stopped.set()
            heartbeat.join(timeout=1)
        with get_db_connection() as conn:
            conn.execute("DELETE FROM admission_leases WHERE id=?", (identity,))


def storage_budget(*, force=False):
    # Check under one lock, with a short cache to avoid repeated directory walks.
    path = str(config.DATA_DIR)
    with _budget_lock:
        now = time.monotonic()
        if not force and _budget.get(path, 0) > now - 5:
            return
        maximum = bounded_setting("AEGIS_MANAGED_STORAGE_BYTES", 1024 ** 3, 16 * 1024 ** 2, 16 * 1024 ** 3)
        minimum_free = bounded_setting("AEGIS_MIN_FREE_BYTES", 64 * 1024 ** 2, 1024 ** 2, 1024 ** 3)
        size = entries = 0
        from aegis.security.private_files import no_links
        for root in (config.DB_DIR, config.KNOWLEDGE_DIR, config.RECEIPTS_DIR, config.ARTIFACTS_DIR):
            def unreadable(error):
                raise OSError("Cannot completely inventory managed storage") from error
            for current, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
                entries += len(dirs) + len(files)
                if entries > 20000:
                    raise HTTPException(507, "Managed storage entry quota reached")
                for name in dirs + files:
                    candidate = no_links(Path(current) / name)
                    if candidate.is_file():
                        size += candidate.stat().st_size
                        if size > maximum:
                            raise HTTPException(507, "Managed storage byte quota reached")
        if shutil.disk_usage(config.DATA_DIR).free < minimum_free:
            raise HTTPException(507, "Insufficient free disk space for durable security state")
        _budget[path] = now


def maintenance():
    storage_budget(force=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at<=?", (time.time(),))
        conn.execute("DELETE FROM auth_attempts WHERE window_start<?", (time.time() - 300,))
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        if "admission_leases" in tables:
            conn.execute("DELETE FROM admission_leases WHERE expires_at<=?", (time.time(),))
