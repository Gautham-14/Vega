"""Transactional SQLite schema upgrades, including unversioned legacy databases."""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 3

BASELINE_SQL = (
    "CREATE TABLE IF NOT EXISTS models (\n    id TEXT PRIMARY KEY,\n    name TEXT NOT NULL,\n    version TEXT NOT NULL,\n    architecture TEXT NOT NULL,\n    parameters TEXT NOT NULL,\n    quantization TEXT NOT NULL,\n    capabilities TEXT NOT NULL, -- JSON array\n    license TEXT NOT NULL,\n    sha256 TEXT NOT NULL,\n    status TEXT NOT NULL, -- QUARANTINED, BENCHMARKING, SHADOW_MODE, QUALIFIED, REJECTED\n    memory_req_mb INTEGER NOT NULL,\n    cpu_cores_req INTEGER NOT NULL,\n    gpu_vram_req_mb INTEGER NOT NULL DEFAULT 0,\n    qualification_score REAL DEFAULT NULL,\n    shadow_agreement_score REAL DEFAULT NULL,\n    benchmark_summary TEXT DEFAULT NULL, -- JSON object\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);",
    "CREATE TABLE IF NOT EXISTS documents (\n    id TEXT PRIMARY KEY,\n    filename TEXT NOT NULL,\n    title TEXT NOT NULL,\n    revision TEXT NOT NULL, -- e.g. Rev2, Rev5, Rev8\n    status TEXT NOT NULL, -- CURRENT_APPROVED, SUPERSEDED, QUARANTINED, DRAFT\n    equipment_id TEXT NOT NULL, -- e.g. Pump P-204, Compressor C-101, ALL\n    department TEXT NOT NULL, -- Engineering, Maintenance, HR, Finance, Operations\n    classification TEXT NOT NULL, -- INTERNAL, RESTRICTED, CONFIDENTIAL\n    effective_date TEXT NOT NULL,\n    sha256 TEXT NOT NULL,\n    content TEXT NOT NULL,\n    file_path TEXT NOT NULL,\n    is_quarantined BOOLEAN DEFAULT 0,\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);",
    "CREATE TABLE IF NOT EXISTS tasks (\n    id TEXT PRIMARY KEY,\n    title TEXT NOT NULL,\n    risk_level TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL\n    status TEXT NOT NULL, -- PENDING, INITIALIZING, SCANNING, ROUTING, EXECUTING, VERIFYING, COMPLETED, FAILED\n    department TEXT NOT NULL,\n    equipment_id TEXT NOT NULL,\n    model_id TEXT,\n    enclave_path TEXT,\n    input_files TEXT, -- JSON array\n    authoritative_sop TEXT,\n    rejected_sops TEXT, -- JSON array\n    blocked_contexts TEXT, -- JSON array\n    claims TEXT, -- JSON array of claim objects\n    result_artifact TEXT, -- Path or filename\n    artifact_content TEXT, -- Full markdown deliverable content\n    execution_log TEXT, -- JSON array of log messages\n    zero_egress_metrics TEXT, -- JSON object: dns=0, http=0, api=0, egress_bytes=0\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n    completed_at TIMESTAMP\n);",
    "CREATE TABLE IF NOT EXISTS security_events (\n    id TEXT PRIMARY KEY,\n    event_type TEXT NOT NULL, -- PROMPT_INJECTION, HIDDEN_INSTRUCTION, UNAUTHORIZED_ACCESS, TAMPERED_MODEL\n    severity TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL\n    description TEXT NOT NULL,\n    source_document TEXT,\n    matched_rule TEXT,\n    raw_payload TEXT,\n    action_taken TEXT NOT NULL, -- QUARANTINED, BLOCKED, STRIPPED\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);",
    "CREATE TABLE IF NOT EXISTS receipts (\n    id TEXT PRIMARY KEY,\n    task_id TEXT NOT NULL,\n    receipt_sha256 TEXT NOT NULL,\n    artifact_sha256 TEXT NOT NULL,\n    model_sha256 TEXT NOT NULL,\n    sop_sha256 TEXT NOT NULL,\n    json_content TEXT NOT NULL,\n    markdown_content TEXT NOT NULL,\n    json_path TEXT NOT NULL,\n    markdown_path TEXT NOT NULL,\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);",
    "CREATE TABLE IF NOT EXISTS system_config (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n);",
    "INSERT OR IGNORE INTO system_config (key, value)\nVALUES ('hardware_profile', 'REAL');",
    "INSERT OR IGNORE INTO system_config (key, value)\nVALUES ('runtime_mode', 'SIMULATION');",
    "CREATE TABLE IF NOT EXISTS auth_accounts (\n    actor TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL,\n    disabled INTEGER NOT NULL DEFAULT 0\n)",
    "CREATE TABLE IF NOT EXISTS auth_sessions (\n    token_hash TEXT PRIMARY KEY, actor TEXT NOT NULL, expires_at REAL NOT NULL,\n    created_at REAL NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS auth_attempts (\n    bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_start REAL NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS control_objects (\n    kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,\n    PRIMARY KEY (kind, id)\n)",
    "CREATE TABLE IF NOT EXISTS control_receipts (\n    sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,\n    body TEXT NOT NULL, hash TEXT NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS control_head (\n    singleton INTEGER PRIMARY KEY CHECK(singleton=1),\n    sequence INTEGER NOT NULL, hash TEXT NOT NULL, signature TEXT NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS telemetry_samples (\n    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, body TEXT NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS telemetry_events (\n    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, method TEXT NOT NULL,\n    route TEXT NOT NULL, status INTEGER NOT NULL, duration_ms REAL NOT NULL\n)",
    "CREATE TABLE IF NOT EXISTS admission_leases (id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor TEXT NOT NULL, provider TEXT NOT NULL, expires_at REAL NOT NULL)",
)


def migrate(connection: sqlite3.Connection) -> None:
    """Serialize upgrades, preserve rows, and reject unknown newer schemas."""
    current = connection.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError("Database schema is newer than this application; upgrade Aegis")
    if current == SCHEMA_VERSION:
        return
    connection.execute("BEGIN IMMEDIATE")
    # A concurrent initializer may have upgraded while this one waited.
    current = connection.execute("PRAGMA user_version").fetchone()[0]
    if current > SCHEMA_VERSION:
        raise RuntimeError("Database schema is newer than this application; upgrade Aegis")
    if current < 1:
        for statement in BASELINE_SQL:
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 1")
    if current < 2:
        task_columns = {row[1] for row in connection.execute("PRAGMA table_info(tasks)")}
        if "artifact_content" not in task_columns:
            connection.execute("ALTER TABLE tasks ADD COLUMN artifact_content TEXT")
        session_columns = {row[1] for row in connection.execute("PRAGMA table_info(auth_sessions)")}
        if "mfa_at" not in session_columns:
            connection.execute(
                "ALTER TABLE auth_sessions ADD COLUMN mfa_at REAL NOT NULL DEFAULT 0"
            )
        connection.execute("PRAGMA user_version = 2")
    if current < 3:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS control_archives (kind TEXT NOT NULL, id TEXT NOT NULL, "
            "body TEXT NOT NULL, PRIMARY KEY(kind,id))"
        )
        connection.execute("PRAGMA user_version = 3")
