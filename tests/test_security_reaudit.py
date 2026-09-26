"""Adversarial regressions for the second security review."""
import base64
import hashlib
import json
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import shutil
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.testclient import TestClient

from aegis import config
from aegis.api.server import app
from aegis.control import policy, store
from aegis.security import auth, recovery
from aegis.security.private_files import no_links
from aegis.storage.database import init_db


def initialize():
    init_db()
    store.init_control()


@pytest.mark.parametrize("path", [r"\\server\share\secret", "//server/share/secret", r"\\?\C:\secret", "C:relative", "local:stream"])
def test_network_and_device_paths_rejected_before_filesystem_access(path):
    with patch.object(Path, "lstat", side_effect=AssertionError("Network path reached filesystem")):
        with pytest.raises(ValueError):
            no_links(path)


def test_hardlinks_cannot_alias_private_storage(tmp_path):
    original, alias = tmp_path / "original", tmp_path / "alias"
    original.write_bytes(b"private fixture")
    os.link(original, alias)
    with pytest.raises(ValueError, match="Hard-linked"):
        no_links(alias)


def test_bundle_hashing_stops_when_file_grows(tmp_path):
    from aegis.security.offline_bundle import _sha256_file
    path = tmp_path / "weights.gguf"
    path.write_bytes(b"abc")
    info = path.stat()
    class GrowingFile(io.BytesIO):
        def fileno(self):
            return 123
    with patch.object(Path, "open", return_value=GrowingFile(b"abcdef")), patch("os.fstat", return_value=info):
        with pytest.raises(ValueError, match="grew"):
            _sha256_file(path, 3)


def test_bundle_hashing_stops_on_unreadable_inventory(tmp_path):
    from aegis.security.offline_bundle import verify_bundle
    from test_offline_bundle import bundle_fixture
    root, trust, *_ = bundle_fixture(tmp_path)
    def failed_walk(*args, **kwargs):
        kwargs["onerror"](PermissionError("synthetic unreadable directory"))
        return iter(())
    with patch("os.walk", side_effect=failed_walk):
        with pytest.raises(ValueError, match="completely read"):
            verify_bundle(root, trust)


@pytest.mark.parametrize("change", ["status", "binding", "decisions", "required_roles", "seal"])
def test_tampered_approval_cannot_authorize_execution(change):
    initialize()
    binding = {"artifact": "reviewed"}
    approval = policy.request_approval("export", binding, "operator")
    policy.decide(approval["id"], "data-owner", "APPROVE")
    policy.decide(approval["id"], "security-officer", "APPROVE")
    assert policy.approved(approval["id"], "export", binding)
    forged = store.require("approval", approval["id"])
    if change == "seal":
        forged.pop("seal")
    else:
        forged[change] = {"status": "PENDING", "binding": "f" * 64,
                          "decisions": [], "required_roles": []}[change]
    store.put("approval", forged["id"], forged)
    with pytest.raises(store.Denied) as error:
        policy.approved(forged["id"], "export", binding)
    assert error.value.code == "APPROVAL_INTEGRITY_FAILURE"


def test_missing_key_does_not_silently_replace_existing_trust_root():
    initialize()
    store.receipt("ORIGINAL_TRUST_ROOT")
    for name in ("control.key", "control.key.dpapi"):
        (config.DATA_DIR / name).unlink(missing_ok=True)
    with pytest.raises(RuntimeError, match="Control key is missing"):
        store.secret()
    assert not (config.DATA_DIR / "control.key").exists()
    assert not (config.DATA_DIR / "control.key.dpapi").exists()


def test_restore_rejects_database_triggers():
    initialize()
    auth.provision("operator", "synthetic-test-password")
    with sqlite3.connect(":memory:") as db:
        db.deserialize(recovery._db_snapshot())
        db.execute("CREATE TRIGGER resurrect_session AFTER DELETE ON auth_sessions BEGIN INSERT INTO auth_sessions VALUES(OLD.token_hash, OLD.actor, OLD.expires_at, OLD.created_at); END")
        with pytest.raises(ValueError, match="executable schema"):
            recovery._valid_database(db.serialize(), store.secret())


def test_restore_revokes_sessions_and_execution_approvals(tmp_path):
    initialize()
    auth.provision("operator", "synthetic-test-password")
    auth.login("operator", "synthetic-test-password", "local")
    approval = policy.request_approval("export", {"artifact": "fixture"}, "operator")
    policy.decide(approval["id"], "data-owner", "APPROVE")
    policy.decide(approval["id"], "security-officer", "APPROVE")
    store.put("capsule", "test-capsule", {"status": "APPROVED", "seal": "old"})
    archive = tmp_path.parent / (tmp_path.name + ".aegis-backup")
    recovery.create_backup(archive, "synthetic-backup-password")
    target = tmp_path.parent / (tmp_path.name + "-restored")
    result = recovery.drill_backup(archive, target, "synthetic-backup-password")
    assert result["sessions_revoked"] and result["execution_reapproval_required"]
    with sqlite3.connect(target / "db/aegis.db") as db:
        assert db.execute("SELECT count(*) FROM auth_sessions").fetchone()[0] == 0
        for kind, raw in db.execute("SELECT kind,body FROM control_objects WHERE kind IN ('approval','capsule')"):
            body = json.loads(raw)
            assert "seal" not in body and body["status"] != "APPROVED"


@pytest.mark.parametrize("names", [
    ["knowledge/C:escape"], ["knowledge/file:stream"], ["knowledge/NUL.txt"],
    ["knowledge/trailing."], ["knowledge/Case.txt", "knowledge/case.txt"],
    ["knowledge/file", "knowledge/file/child.txt"],
])
def test_authenticated_backup_cannot_authorize_unsafe_restore_paths(tmp_path, names):
    initialize()
    store.receipt("RESTORE_PATH_TEST")
    payload = json.loads(recovery._payload())
    data = b"synthetic fixture"
    payload["files"] = {name: {"data": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest()} for name in names}
    salt, nonce = os.urandom(16), os.urandom(12)
    password = "synthetic-backup-password"
    encrypted = recovery.MAGIC + salt + nonce + AESGCM(recovery._key(password, salt)).encrypt(nonce, json.dumps(payload).encode(), recovery.MAGIC)
    archive = tmp_path / "crafted.aegis-backup"
    archive.write_bytes(encrypted)
    target = tmp_path / "restored"
    with pytest.raises(ValueError, match="contents are invalid"):
        recovery.restore_backup(archive, target, password)
    assert not target.exists() and not list(tmp_path.glob(".aegis-restore-*"))


def test_api_documentation_loads_no_vendor_assets():
    with TestClient(app) as client:
        response = client.get("/docs")
        assert response.status_code == 200
        assert 'href="/openapi.json"' in response.text
        assert "https://" not in response.text and "http://" not in response.text
        assert "connect-src 'self'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"
        assert client.get("/redoc").status_code == 404


def test_wheel_install_pins_bytes_and_never_resolves_dependency_urls(tmp_path, monkeypatch):
    from scripts import setup_offline
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    item = wheels / "fixture-1.0-py3-none-any.whl"
    item.write_bytes(b"synthetic wheel")
    digest = hashlib.sha256(item.read_bytes()).hexdigest()
    manifest = tmp_path / "wheels.sha256"
    manifest.write_text(digest + "  " + item.name)
    monkeypatch.setenv("PIP_FIND_LINKS", "https://untrusted.invalid/wheels")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert "PIP_FIND_LINKS" not in kwargs["env"]
        if "install" in command:
            assert all(flag in command for flag in ("--no-index", "--no-deps", "--require-hashes", "--isolated"))
            lock = Path(command[command.index("-r") + 1]).read_text()
            assert item.as_uri() in lock and "--hash=sha256:" + digest in lock
    monkeypatch.setattr(setup_offline.subprocess, "run", run)
    assert setup_offline.install_verified_wheels(Path("python"), wheels, manifest, cwd=tmp_path) == 1
    assert calls[-1][-1] == "check"
    assert not list(tmp_path.glob(".aegis-wheel-lock-*"))


@pytest.mark.skipif(os.name != "nt", reason="Windows firewall script")
def test_firewall_preflight_rejects_partially_scoped_rules():
    subprocess.run([shutil.which("powershell"), "-NoProfile", "-NonInteractive", "-File",
                    str(Path(__file__).with_name("firewall_scope_checks.ps1"))],
                   check=True, capture_output=True, text=True, timeout=15)
