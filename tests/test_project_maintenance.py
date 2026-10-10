"""Startup purity, canonical version and transactional legacy upgrade regression tests."""

import os
import sqlite3
import subprocess
import sys

import pytest

from aegis import __version__, config
from aegis.storage import migrations


def test_configuration_import_does_not_create_storage(tmp_path):
    target = tmp_path / "absent"
    env = {**os.environ, "AEGIS_DATA_DIR": str(target)}
    subprocess.run([sys.executable, "-c", "import aegis.config"], env=env, check=True)
    assert not target.exists()


def test_versions_share_authority():
    from aegis.api.server import app

    assert app.version == config.VERSION == __version__


@pytest.mark.parametrize("version", [0, 1])
def test_upgrade_preserves_legacy_rows(version):
    conn = sqlite3.connect(":memory:")
    with conn:
        for statement in migrations.BASELINE_SQL:
            conn.execute(
                statement.replace(
                    "    artifact_content TEXT, -- Full markdown deliverable content\n", ""
                )
            )
        conn.execute("INSERT INTO auth_accounts VALUES ('alice','salt','hash',0)")
        conn.execute("INSERT INTO auth_sessions VALUES ('token','alice',100,10)")
        conn.execute(f"PRAGMA user_version = {version}")
    with conn:
        migrations.migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == migrations.SCHEMA_VERSION
    assert conn.execute("SELECT actor, mfa_at FROM auth_sessions").fetchone() == ("alice", 0)
    assert "artifact_content" in {row[1] for row in conn.execute("PRAGMA table_info(tasks)")}
    with conn:
        migrations.migrate(conn)
    assert conn.execute("SELECT COUNT(*) FROM auth_accounts").fetchone()[0] == 1
    conn.close()


def test_encoding_checker_rejects_mojibake(tmp_path, monkeypatch):
    from scripts import project_checks

    target = tmp_path / "sample.py"
    target.write_text("# 80\u00c2\u00b0C", encoding="utf-8")
    monkeypatch.setattr(project_checks, "ROOT", tmp_path)
    monkeypatch.setattr(project_checks, "source_files", lambda: ["sample.py"])
    with pytest.raises(ValueError, match="Malformed"):
        project_checks.encoding_check()
    target.write_text("# 80\u00b0C", encoding="utf-8")
    project_checks.encoding_check()


def test_coverage_gate_rejects_missing_or_low_coverage(tmp_path):
    import json

    from scripts import project_checks

    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"files": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        project_checks.coverage_check(path)
    path.write_text(
        json.dumps(
            {
                "files": {
                    name: {"summary": {"percent_covered": 0}}
                    for name in project_checks.CRITICAL_FLOORS
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="below"):
        project_checks.coverage_check(path)


def test_upgrade_rejects_newer_database():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA user_version = 999")
    with pytest.raises(RuntimeError, match="newer"), conn:
        migrations.migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 999
    conn.close()


def test_failed_upgrade_rolls_back(monkeypatch):
    conn = sqlite3.connect(":memory:")
    monkeypatch.setattr(
        migrations, "BASELINE_SQL", ("CREATE TABLE sample (id TEXT)", "INVALID SQL")
    )
    with pytest.raises(sqlite3.OperationalError), conn:
        migrations.migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    assert not conn.execute("SELECT name FROM sqlite_master WHERE name='sample'").fetchall()
    conn.close()
