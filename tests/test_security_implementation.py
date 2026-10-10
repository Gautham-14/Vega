"""Security boundaries, migration, rollback and resource exhaustion regressions."""

import base64
import hashlib
import json
import socket
import struct
import time

import pytest
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from starlette.requests import Request

from aegis.control import store
from aegis.security import (
    audit_anchor,
    auth,
    availability,
    deployment,
    key_custody,
    local_rpc,
    lockdown,
    quiescence,
    recovery,
)
from aegis.storage.database import get_db_connection, init_db, query_one
from scripts import release_security


@pytest.fixture(autouse=True)
def setup():
    init_db()
    store.init_control()
    auth.init_auth()


def test_keyring_migration_rotation_and_restore(tmp_path):
    old_signature = store.sign({"old": True}, "source")
    old_token = store.encrypt("source:Engineering", b"synthetic-source")
    store.receipt("OLD_HEAD")
    key_custody.initialize()
    assert store.verify_signature({"old": True}, "source", old_signature)
    assert store.decrypt("source:Engineering", old_token) == b"synthetic-source"
    signature = store.sign({"new": True}, "source")
    token = store.encrypt("source:Engineering", b"new-source")
    store.receipt("NEW_HEAD")
    ring = key_custody.load(key_custody.local_path())
    original = ring.value["active"]
    ring.rotate()
    key_custody.save(key_custody.local_path(), ring)
    assert ring.value["active"] != original
    assert store.verify_signature({"new": True}, "source", signature)
    assert store.decrypt("source:Engineering", token) == b"new-source"
    assert store.verify_chain()["is_valid"]
    store.receipt("ROTATED_HEAD")
    archive = tmp_path.parent / (tmp_path.name + ".aegis-backup")
    recovery.create_backup(archive, "synthetic-backup-passphrase")
    result = recovery.drill_backup(
        archive, tmp_path.parent / (tmp_path.name + "-restore"), "synthetic-backup-passphrase"
    )
    assert result["receipt_chain_verified"] and result["sessions_revoked"]


@pytest.mark.parametrize("operation", ["export", "rotate", "secret", "derive", "decrypt-path"])
def test_broker_has_no_key_export_or_admin_rpc(operation):
    with pytest.raises(ValueError):
        key_custody.dispatch(key_custody.Keyring.new(), {"operation": operation})


@pytest.mark.parametrize("signature", [None, {}, "é" * 64, "x" * 1000, "0" * 63])
def test_invalid_signature_fails_closed(signature):
    assert not store.verify_signature({}, "source", signature)


def test_key_domain_separation():
    ring = key_custody.Keyring.new()
    signed = ring.sign({}, "source")
    assert not ring.verify({}, "account-mfa", signed)
    token = ring.encrypt("source:Engineering", b"secret")
    with pytest.raises(InvalidToken):
        ring.decrypt("source:Finance", token)


def test_missing_key_version_cannot_decrypt_or_verify():
    ring = key_custody.Keyring.new()
    signature, token = ring.sign({}, "source"), ring.encrypt("source", b"secret")
    old = ring.value["active"]
    ring.rotate()
    del ring.value["keys"][old]
    assert not ring.verify({}, "source", signature)
    with pytest.raises(KeyError):
        ring.decrypt("source", token)


def test_production_cannot_export_legacy_or_derived_keys(monkeypatch):
    monkeypatch.setenv("AEGIS_KEY_BROKER_SOCKET", "/run/example.sock")
    with pytest.raises(RuntimeError, match="cannot be exported"):
        store.secret()
    with pytest.raises(RuntimeError, match="cannot leave"):
        store.encryption_key("source")


def test_witness_detects_database_rollback(tmp_path, monkeypatch):
    witness = audit_anchor.Witness(tmp_path / "witness.db")
    installation = "a" * 32
    witness.enroll(installation)
    monkeypatch.setenv("AEGIS_AUDIT_WITNESS_SOCKET", "/run/mock.sock")

    def remote(op, **kwargs):
        return witness.dispatch({"operation": op, "installation": installation, **kwargs})

    monkeypatch.setattr(audit_anchor, "remote", remote)
    store.receipt("FIRST")
    with get_db_connection() as conn:
        saved = conn.serialize()
    store.receipt("SECOND")
    assert store.verify_chain()["independently_anchored"]
    with get_db_connection() as conn:
        conn.deserialize(saved)
        # deserialize changes only this connection's database; write the valid
        # old rows/head into live storage as a whole-ledger rollback simulation.
        old_rows = conn.execute("SELECT * FROM control_receipts").fetchall()
        old_head = conn.execute("SELECT * FROM control_head").fetchone()
    with get_db_connection() as conn:
        conn.execute("DELETE FROM control_receipts")
        conn.execute("DELETE FROM control_head")
        conn.executemany(
            "INSERT INTO control_receipts VALUES(?,?,?,?)", [tuple(row) for row in old_rows]
        )
        conn.execute("INSERT INTO control_head VALUES(?,?,?,?)", tuple(old_head))
    assert not store.verify_chain(record_failure=False)["is_valid"]
    with pytest.raises(RuntimeError, match="rolled-back"):
        store.receipt("MUST_NOT_APPEND")


@pytest.mark.parametrize("attack", ["gap", "fork", "replay"])
def test_witness_refuses_non_monotonic_updates(tmp_path, attack):
    witness = audit_anchor.Witness(tmp_path / "witness.db")
    installation = "a" * 32
    witness.enroll(installation)
    request = {
        "operation": "advance",
        "installation": installation,
        "commitments": [{"sequence": 1, "hash": "b" * 64, "previous": audit_anchor.ZERO}],
    }
    witness.dispatch(request)
    item = {"sequence": 2, "hash": "c" * 64, "previous": "b" * 64}
    if attack == "gap":
        item["sequence"] = 3
    elif attack == "fork":
        item["previous"] = "d" * 64
    else:
        item = request["commitments"][0]
    with pytest.raises(ValueError):
        witness.dispatch({**request, "commitments": [item]})


def test_witness_cannot_enroll_or_reset_over_rpc(tmp_path):
    witness = audit_anchor.Witness(tmp_path / "witness.db")
    with pytest.raises(ValueError):
        witness.dispatch({"operation": "status", "installation": "a" * 32})
    with pytest.raises(ValueError):
        witness.dispatch({"operation": "enroll", "installation": "a" * 32})


def test_mfa_login_replay_step_up_and_session_cap(monkeypatch):
    auth.provision("security-officer", "synthetic-test-password")
    seed = auth.enroll_mfa("security-officer")["secret"]
    now = float(int(time.time() // 30) * 30 + 5)
    monkeypatch.setattr(auth.time, "time", lambda: now)
    code = auth.totp(seed, int(now // 30))
    with pytest.raises(HTTPException) as absent:
        auth.login("security-officer", "synthetic-test-password", "local")
    assert absent.value.status_code == 401
    session = auth.login("security-officer", "synthetic-test-password", "local", code)
    assert session["expires_at"] == now + auth.PRIVILEGED_SESSION_SECONDS
    with pytest.raises(HTTPException):
        auth.login("security-officer", "synthetic-test-password", "local", code)
    for _ in range(4):
        now += 30
        auth.login(
            "security-officer", "synthetic-test-password", "local", auth.totp(seed, int(now // 30))
        )
    assert len(auth.session_inventory("security-officer")) == auth.MAX_SESSIONS
    assert not query_one(
        "SELECT * FROM auth_sessions WHERE token_hash=?",
        (hashlib.sha256(session["access_token"].encode()).hexdigest(),),
    )


def test_totp_standard_hotp_vector():
    # RFC 4226 test key, counter 1 -> 287082 (6 digits).
    seed = base64.b32encode(b"12345678901234567890").decode()
    assert auth.totp(seed, 1) == "287082"


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_totp_rfc6238_vectors(timestamp, expected):
    seed = base64.b32encode(b"12345678901234567890").decode()
    assert auth.totp(seed, timestamp // 30) == expected


def test_production_rejects_root_api(monkeypatch):
    monkeypatch.setenv("AEGIS_SECURITY_PROFILE", "production")
    monkeypatch.setattr(deployment.sys, "platform", "linux")
    monkeypatch.setattr(deployment.os, "geteuid", lambda: 0, raising=False)
    with pytest.raises(RuntimeError, match="never root"):
        deployment.validate()


def test_production_privileged_account_requires_mfa(monkeypatch):
    auth.provision("model-custodian", "synthetic-test-password")
    monkeypatch.setenv("AEGIS_SECURITY_PROFILE", "production")
    with pytest.raises(HTTPException) as error:
        auth.login("model-custodian", "synthetic-test-password", "local")
    assert error.value.status_code == 401


def test_fresh_step_up_required_for_privileged_mutations(monkeypatch):
    monkeypatch.setenv("AEGIS_SECURITY_PROFILE", "production")
    request = Request({"type": "http", "method": "POST", "path": "/api/providers", "headers": []})
    request.state.actor = "security-officer"
    request.state.mfa_at = time.time() - auth.STEP_UP_SECONDS - 1
    with pytest.raises(HTTPException) as error:
        auth.require_step_up(request)
    assert error.value.status_code == 403
    request.state.mfa_at = time.time()
    auth.require_step_up(request)


def test_mfa_step_up_replay_and_throttle(monkeypatch):
    auth.provision("operator", "synthetic-test-password")
    seed = auth.enroll_mfa("operator")["secret"]
    now = float(int(time.time() // 30) * 30 + 5)
    monkeypatch.setattr(auth.time, "time", lambda: now)
    session = auth.login(
        "operator", "synthetic-test-password", "local", auth.totp(seed, int(now // 30))
    )
    request = Request(
        {"type": "http", "method": "POST", "path": "/api/auth/step-up", "headers": []}
    )
    request.state.actor = "operator"
    request.state.session_token = session["access_token"]
    now += 30
    code = auth.totp(seed, int(now // 30))
    assert auth.step_up(request, code)["verified"]
    for _ in range(8):
        with pytest.raises(HTTPException) as error:
            auth.step_up(request, code)
        assert error.value.status_code == 401
    with pytest.raises(HTTPException) as error:
        auth.step_up(request, code)
    assert error.value.status_code == 429


def test_admission_limits_and_cleanup():
    with availability.admit("provider", "operator", "p"):
        with availability.admit("provider", "operator", "p"):
            with pytest.raises(HTTPException) as error:
                with availability.admit("provider", "other", "p"):
                    pytest.fail("Provider limit was bypassed")
            assert error.value.status_code == 429
    assert query_one("SELECT COUNT(*) AS count FROM admission_leases")["count"] == 0


def test_admission_releases_after_work_failure():
    with pytest.raises(ValueError):
        with availability.admit("http", "operator"):
            raise ValueError("failed work")
    assert query_one("SELECT COUNT(*) AS count FROM admission_leases")["count"] == 0


def test_disk_exhaustion_fails_before_dispatch(monkeypatch):
    monkeypatch.setattr(
        availability.shutil, "disk_usage", lambda _: type("Usage", (), {"free": 0})()
    )
    with pytest.raises(HTTPException) as error:
        availability.storage_budget(force=True)
    assert error.value.status_code == 507


def test_receipt_quota_never_prunes_audit_history(monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_RECEIPTS", "100")
    for _ in range(100):
        store.receipt("SYNTHETIC")
    with pytest.raises(ValueError, match="quota"):
        store.receipt("EXCESS")
    assert store.verify_chain()["count"] == 100


def test_backup_requires_quiescence(tmp_path):
    store.receipt("BACKUP")
    with quiescence.exclusive("test running API"):
        with pytest.raises(RuntimeError, match="Stop Aegis"):
            recovery.create_backup(
                tmp_path.parent / (tmp_path.name + ".aegis-backup"), "synthetic-backup-passphrase"
            )


def test_lockdown_stays_enabled_when_model_stop_fails(monkeypatch):
    from aegis.security import attestor

    monkeypatch.setenv("AEGIS_ATTESTOR_SOCKET", "/run/mock.sock")
    monkeypatch.setattr(attestor, "remote", lambda *args: {"stopped": False})
    with pytest.raises(store.Denied) as error:
        lockdown.change(True, "security-officer")
    assert error.value.code == "MODEL_STOP_UNCONFIRMED"
    assert lockdown.status()["enabled"] is True
    with pytest.raises(store.Denied):
        lockdown.check()
    monkeypatch.setattr(attestor, "remote", lambda *args: {"stopped": True})
    assert lockdown.change(True, "security-officer")["enabled"]


@pytest.mark.parametrize("profile", ["production", "typo"])
def test_production_cannot_start_with_missing_prerequisites(monkeypatch, profile):
    monkeypatch.setenv("AEGIS_SECURITY_PROFILE", profile)
    with pytest.raises(RuntimeError):
        deployment.validate()


def test_rpc_rejects_oversize_frame():
    a, b = socket.socketpair()
    try:
        a.sendall(struct.pack("!I", local_rpc.MAX_MESSAGE + 1))
        with pytest.raises(ValueError):
            local_rpc.receive(b)
    finally:
        a.close()
        b.close()


def test_signed_release_reproducibility_and_tamper_detection(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "aegis_cli.py").write_text("# synthetic\n")
    (source / "pyproject.toml").write_text("# synthetic\n")
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "test.private.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = tmp_path / "test.public.pem"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    fingerprint = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    policy = tmp_path / "trust.json"
    policy.write_text(
        json.dumps(
            {
                "public_key_path": str(public),
                "public_key_sha256": fingerprint,
                "minimum_version": 2,
                "expires_at": time.time() + 3600,
            }
        )
    )
    first, second = tmp_path / "release1", tmp_path / "release2"
    release_security.build(source, first, private, 2, epoch=123)
    release_security.build(source, second, private, 2, epoch=123)
    assert (first / "release.sig").read_bytes() == (second / "release.sig").read_bytes()
    assert release_security.verify(first, policy)["valid"]
    (first / "unexpected.py").write_text("# injected\n")
    with pytest.raises(ValueError, match="extra"):
        release_security.verify(first, policy)
    (first / "unexpected.py").unlink()
    (first / "aegis_cli.py").write_text("# changed\n")
    with pytest.raises(ValueError, match="changed"):
        release_security.verify(first, policy)


@pytest.mark.parametrize(
    "name",
    ["runtime.env", "signer.private.pem", "control.keys.json", "credentials.json", "state.db"],
)
def test_release_source_rejects_private_files_before_packaging(tmp_path, name):
    (tmp_path / name).write_text("synthetic private fixture")
    with pytest.raises(ValueError, match="private"):
        list(release_security.source_files(tmp_path))


def test_supervised_refresh_uses_existing_release_gate(monkeypatch):
    from aegis.security import attestor, provider_assurance

    spec = {"provider": "p"}
    request = {"synthetic": "signed attestor result"}
    monkeypatch.setattr(provider_assurance.providers, "specification", lambda _: spec)
    monkeypatch.setattr(
        attestor,
        "remote",
        lambda op, supplied: request if op == "attest" and supplied == spec else None,
    )
    observed = []
    monkeypatch.setattr(
        provider_assurance, "refresh", lambda *args: observed.append(args) or {"refreshed": True}
    )
    assert provider_assurance.refresh_supervised_attestation("p", "security-officer")["refreshed"]
    assert observed == [("p", request, "security-officer")]
