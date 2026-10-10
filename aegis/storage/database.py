"""
Aegis Sovereign AI Runtime - Local SQLite Storage
"""

import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from aegis.config import DB_PATH
from aegis.security.private_files import no_links, restrict_permissions

LOCK = threading.RLock()
_connection = None
_identity = None
_depth = 0


class Connection(sqlite3.Connection):
    ledger_revision = 0


class ScopedConnection:
    """Context-bound handle; callers cannot reuse the shared connection unlocked."""

    def __init__(self, connection):
        self.connection = connection
        self.closed = False

    def __getattr__(self, name):
        if self.closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database handle")
        return getattr(self.connection, name)


def close_database():
    """Release the idle connection before offline recovery or storage teardown."""
    global _connection, _identity
    with LOCK:
        if _depth:
            raise RuntimeError("Cannot close an active storage transaction")
        if _connection is not None:
            _connection.close()
        _connection = _identity = None


def ledger_token(conn):
    # data_version changes on commits by OTHER connections, including direct
    # SQLite tampering. Our authorizer tracks protected writes on this connection.
    return (
        _identity,
        conn.ledger_session,
        conn.execute("PRAGMA data_version").fetchone()[0],
        conn.ledger_revision,
    )


def _open():
    global _connection, _identity
    path = no_links(DB_PATH)
    info = path.stat() if path.exists() else None
    identity = (os.getpid(), str(path), (info.st_dev, info.st_ino) if info else None)
    if _connection is not None and identity != _identity:
        close_database()
    if _connection is None:
        conn = sqlite3.connect(
            str(path), check_same_thread=False, cached_statements=0, factory=Connection
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.ledger_session = uuid.uuid4().hex
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("PRAGMA foreign_keys = ON")
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            conn.execute(f"PRAGMA max_page_count = {256 * 1024 * 1024 // page_size}")
        except BaseException:
            conn.close()
            raise

        def authorize(action, table, column, database, trigger):
            if action in {
                sqlite3.SQLITE_INSERT,
                sqlite3.SQLITE_UPDATE,
                sqlite3.SQLITE_DELETE,
                sqlite3.SQLITE_DROP_TABLE,
                sqlite3.SQLITE_ALTER_TABLE,
            } and (
                table in {"control_receipts", "control_head"}
                or column in {"control_receipts", "control_head"}
            ):
                conn.ledger_revision += 1
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorize)
        info = path.stat()
        _identity = (os.getpid(), str(path), (info.st_dev, info.st_ino))
        _connection = conn
    return _connection


@contextmanager
def get_db_connection():
    """Serialize SQLite access; nested helpers cannot commit the caller's work."""
    global _depth
    with LOCK:
        conn = _open()
        handle = ScopedConnection(conn)
        nested = _depth > 0
        savepoint = f"aegis_nested_{_depth}"
        _depth += 1
        try:
            if nested:
                conn.execute(f"SAVEPOINT {savepoint}")
                try:
                    yield handle
                except BaseException:
                    conn.execute(f"ROLLBACK TO {savepoint}")
                    raise
                finally:
                    conn.execute(f"RELEASE {savepoint}")
            else:
                with conn:
                    yield handle
        finally:
            handle.closed = True
            _depth -= 1


def init_db() -> None:
    """Initialize private storage and upgrade the schema before use."""
    from aegis import config
    from aegis.storage.migrations import migrate

    config.initialize_storage()
    path = no_links(DB_PATH)
    if path.exists():
        restrict_permissions(path)
    with get_db_connection() as conn:
        restrict_permissions(path)
        migrate(conn)


def query_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Execute query and return list of dictionaries."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def query_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Execute query and return single dictionary or None."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None


def execute_write(query: str, params: tuple = ()) -> None:
    """Execute an INSERT, UPDATE, or DELETE query."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
