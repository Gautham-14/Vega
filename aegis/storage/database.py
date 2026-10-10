"""
Aegis Sovereign AI Runtime - Local SQLite Storage
"""

import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from aegis.config import DB_PATH
from aegis.security.private_files import no_links, restrict_permissions


@contextmanager
def get_db_connection():
    """Return a configured SQLite connection with row factory."""
    conn = sqlite3.connect(str(no_links(DB_PATH)))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA trusted_schema = OFF;")
        conn.execute("PRAGMA foreign_keys = ON;")
        # Bound database growth independently of cached directory admission checks.
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        conn.execute(f"PRAGMA max_page_count = {256 * 1024 * 1024 // page_size}")
        with conn:
            yield conn
    finally:
        conn.close()


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
        conn.commit()
