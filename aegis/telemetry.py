"""Bounded local telemetry; never store prompts, source text, tokens or bodies."""
import json
import time
import psutil

from aegis import config
from aegis.storage.database import get_db_connection, query_all


def init_telemetry():
    with get_db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS telemetry_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, method TEXT NOT NULL,
                route TEXT NOT NULL, status INTEGER NOT NULL, duration_ms REAL NOT NULL
            );
        """)


def sample():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(config.DATA_DIR))
    process = psutil.Process()
    result = {"timestamp": time.time(), "source": "HOST_MEASURED", "cpu_percent": psutil.cpu_percent(),
              "cpu_cores": psutil.cpu_count(), "memory_used_bytes": memory.total - memory.available,
              "memory_total_bytes": memory.total, "memory_percent": round(100 * (1 - memory.available / memory.total), 2),
              "disk_used_bytes": disk.used, "disk_total_bytes": disk.total, "disk_percent": disk.percent,
              "process_rss_bytes": process.memory_info().rss, "uptime_seconds": time.time() - process.create_time(),
              "gpu_percent": None, "gpu_note": "No GPU measurement adapter configured"}
    with get_db_connection() as conn:
        conn.execute("INSERT INTO telemetry_samples(timestamp,body) VALUES(?,?)", (result["timestamp"], json.dumps(result)))
        conn.execute("DELETE FROM telemetry_samples WHERE id NOT IN (SELECT id FROM telemetry_samples ORDER BY id DESC LIMIT 1200)")
    return result


def history(limit=120):
    return [json.loads(row["body"]) for row in reversed(query_all(
        "SELECT body FROM telemetry_samples ORDER BY id DESC LIMIT ?", (limit,)))]


def event(method, route, status, duration_ms):
    with get_db_connection() as conn:
        conn.execute("INSERT INTO telemetry_events(timestamp,method,route,status,duration_ms) VALUES(?,?,?,?,?)",
                     (time.time(), method, route, status, round(duration_ms, 2)))
        conn.execute("DELETE FROM telemetry_events WHERE id NOT IN (SELECT id FROM telemetry_events ORDER BY id DESC LIMIT 2000)")


def events(limit=100):
    return [dict(row) for row in query_all("SELECT * FROM telemetry_events ORDER BY id DESC LIMIT ?", (limit,))]
