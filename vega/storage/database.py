"""
Vega Sovereign AI Runtime - Local SQLite Storage
"""
import sqlite3
from contextlib import contextmanager
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from vega.config import DB_PATH

@contextmanager
def get_db_connection():
    """Return a configured SQLite connection with row factory."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        with conn:
            yield conn
    finally:
        conn.close()

def init_db() -> None:
    """Initialize all SQLite tables for Vega sovereign runtime."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Model Registry Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS models (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                architecture TEXT NOT NULL,
                parameters TEXT NOT NULL,
                quantization TEXT NOT NULL,
                capabilities TEXT NOT NULL, -- JSON array
                license TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL, -- QUARANTINED, BENCHMARKING, SHADOW_MODE, QUALIFIED, REJECTED
                memory_req_mb INTEGER NOT NULL,
                cpu_cores_req INTEGER NOT NULL,
                gpu_vram_req_mb INTEGER NOT NULL DEFAULT 0,
                qualification_score REAL DEFAULT NULL,
                shadow_agreement_score REAL DEFAULT NULL,
                benchmark_summary TEXT DEFAULT NULL, -- JSON object
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Knowledge / Documents Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                title TEXT NOT NULL,
                revision TEXT NOT NULL, -- e.g. Rev2, Rev5, Rev8
                status TEXT NOT NULL, -- CURRENT_APPROVED, SUPERSEDED, QUARANTINED, DRAFT
                equipment_id TEXT NOT NULL, -- e.g. Pump P-204, Compressor C-101, ALL
                department TEXT NOT NULL, -- Engineering, Maintenance, HR, Finance, Operations
                classification TEXT NOT NULL, -- INTERNAL, RESTRICTED, CONFIDENTIAL
                effective_date TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                content TEXT NOT NULL,
                file_path TEXT NOT NULL,
                is_quarantined BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Tasks Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                risk_level TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
                status TEXT NOT NULL, -- PENDING, INITIALIZING, SCANNING, ROUTING, EXECUTING, VERIFYING, COMPLETED, FAILED
                department TEXT NOT NULL,
                equipment_id TEXT NOT NULL,
                model_id TEXT,
                enclave_path TEXT,
                input_files TEXT, -- JSON array
                authoritative_sop TEXT,
                rejected_sops TEXT, -- JSON array
                blocked_contexts TEXT, -- JSON array
                claims TEXT, -- JSON array of claim objects
                result_artifact TEXT, -- Path or filename
                artifact_content TEXT, -- Full markdown deliverable content
                execution_log TEXT, -- JSON array of log messages
                zero_egress_metrics TEXT, -- JSON object: dns=0, http=0, api=0, egress_bytes=0
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
        """)

        # Migration: ensure artifact_content column exists if table was created previously
        cursor.execute("PRAGMA table_info(tasks)")
        columns = [row[1] for row in cursor.fetchall()]
        if "artifact_content" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN artifact_content TEXT")

        # Security Events / Context Firewall Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL, -- PROMPT_INJECTION, HIDDEN_INSTRUCTION, UNAUTHORIZED_ACCESS, TAMPERED_MODEL
                severity TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
                description TEXT NOT NULL,
                source_document TEXT,
                matched_rule TEXT,
                raw_payload TEXT,
                action_taken TEXT NOT NULL, -- QUARANTINED, BLOCKED, STRIPPED
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Sovereignty Receipts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                model_sha256 TEXT NOT NULL,
                sop_sha256 TEXT NOT NULL,
                json_content TEXT NOT NULL,
                markdown_content TEXT NOT NULL,
                json_path TEXT NOT NULL,
                markdown_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # System Hardware Config Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # Default hardware simulation mode: "REAL" or profile name
        cursor.execute("""
            INSERT OR IGNORE INTO system_config (key, value)
            VALUES ('hardware_profile', 'REAL');
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO system_config (key, value)
            VALUES ('runtime_mode', 'SIMULATION');
        """)

        conn.commit()

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
