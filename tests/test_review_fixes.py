"""Adversarial regressions for restored assurance and audited weak spots."""

import base64
import hashlib
import json
import os
import socket
import threading
import time
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient
from test_offline_bundle import bundle_fixture

from aegis import cli
from aegis.api.server import app
from aegis.coding import providers, retrieval, service
from aegis.control import capsules, policy, store
from aegis.security import (
    audit_export,
    auth,
    bundle_custody,
    embedding_qualification,
    media_qualification,
    model_qualification,
    offline_bundle,
)
from aegis.security import provider_assurance as assurance
from aegis.storage import database as db
from aegis.storage.database import init_db
from aegis.storage.paths import contained_file


@pytest.fixture(autouse=True)
def database():
    init_db()
    store.init_control()
    auth.init_auth()


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    root, trust_file, *_ = bundle_fixture(tmp_path)
    custody = bundle_custody.record(root, trust_file)
    provider = providers.register(
        "model-custodian",
        name="Synthetic runtime",
        protocol="openai-compatible",
        engine="llama.cpp",
        endpoint="http://127.0.0.1:8080",
        model="fixture",
        digest="a" * 64,
        local_only=True,
        bundle_record_id=custody["id"],
    )
    spec = providers.specification(provider["id"])
    suite = {
        "schema_version": "aegis-text-qualification-v1",
        "classification": "PUBLIC",
        "cases": [{"id": "fixture", "prompt": "Say ready", "required_text": ["ready"]}],
    }
    with patch.object(model_qualification, "_text_response", return_value="ready"):
        qualified = model_qualification.run_candidate_suite(
            provider["id"], suite, "model-custodian"
        )
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "independent-attestor.pem"
    pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    fingerprint = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    trust = {
        "schema_version": "aegis-provider-trust-v1",
        "expires_at": time.time() + 3600,
        "signers": {"independent": {"public_key_path": str(pem), "public_key_sha256": fingerprint}},
    }
    path = tmp_path / "attestor-trust.json"
    path.write_text(json.dumps(trust))
    monkeypatch.setenv("AEGIS_PROVIDER_TRUST_POLICY", str(path))
    process = {
        "pid": 123,
        "created_at": 1234.0,
        "executable_sha256": custody["verification"]["runtime_sha256"],
    }
    monkeypatch.setattr(assurance, "_measure", lambda spec, pid: process)
    now = time.time()
    attestation = {
        "schema_version": "aegis-provider-attestation-v1",
        "signer_id": "independent",
        "provider_id": provider["id"],
        "provider_configuration_sha256": providers.configuration_hash(spec),
        "bundle_record_id": custody["id"],
        "manifest_sha256": custody["verification"]["manifest_sha256"],
        "weights_inventory_sha256": custody["verification"]["weights_inventory_sha256"],
        "qualification_id": qualified["id"],
        "qualification_sha256": model_qualification.qualification_hash(qualified),
        "process": process.copy(),
        "loaded_weights_verified": True,
        "network_isolation_verified": True,
        "server_retention_disabled": True,
        "issued_at": now,
        "expires_at": now + 300,
    }

    def signed(value=None):
        value = attestation if value is None else value
        return {
            "attestation": deepcopy(value),
            "signature": base64.b64encode(key.sign(offline_bundle.canonical_bytes(value))).decode(),
        }

    return spec, signed, attestation, custody, root, path, trust


def activate(spec, signed):
    candidate = assurance.import_attestation(spec["provider"], signed(), "security-officer")
    for actor in ("model-custodian", "data-owner"):
        policy.decide(candidate["approval"]["id"], actor, "APPROVE")
    release = assurance.activate(spec["provider"], candidate["approval"]["id"], "model-custodian")
    return candidate, release


def test_provider_release_requires_signed_evidence_and_independent_approvals(evidence):
    spec, signed, *_ = evidence
    with pytest.raises(store.Denied) as error:
        providers.require_sensitive_boundary(spec, "INTERNAL")
    assert error.value.code == "MODEL_ASSURANCE_REQUIRED"
    candidate = assurance.import_attestation(spec["provider"], signed(), "security-officer")
    with pytest.raises(store.Denied):
        assurance.activate(spec["provider"], candidate["approval"]["id"], "model-custodian")
    assert not store.all_objects("provider-release")
    for actor in ("model-custodian", "data-owner"):
        policy.decide(candidate["approval"]["id"], actor, "APPROVE")
    release = assurance.activate(spec["provider"], candidate["approval"]["id"], "model-custodian")
    assert providers.require_sensitive_boundary(spec, "INTERNAL")["id"] == release["id"]
    assert (
        assurance.review_candidate(spec["provider"], candidate["candidate"]["id"], "data-owner")[
            "binding"
        ]
        == candidate["candidate"]["binding"]
    )
    with pytest.raises(store.Denied):
        assurance.review_candidate(spec["provider"], candidate["candidate"]["id"], "operator")
    assurance.revoke(spec["provider"], "security-officer")
    with pytest.raises(store.Denied):
        assurance.require_active_release(spec)
    with pytest.raises(store.Denied):
        assurance.activate(spec["provider"], candidate["approval"]["id"], "model-custodian")


@pytest.mark.parametrize(
    "change", ["signature", "provider", "weights", "process", "expired", "false-isolation"]
)
def test_bad_attestation_never_creates_release_candidates(evidence, change):
    spec, signed, attestation, *_ = evidence
    request = signed()
    if change == "signature":
        request["signature"] = base64.b64encode(b"x" * 64).decode()
    elif change == "provider":
        request["attestation"]["provider_configuration_sha256"] = "f" * 64
    elif change == "weights":
        request["attestation"]["weights_inventory_sha256"] = "f" * 64
    elif change == "process":
        altered = deepcopy(attestation)
        altered["process"]["created_at"] += 1
        request = signed(altered)
    elif change == "expired":
        request = signed(
            {**attestation, "issued_at": time.time() - 600, "expires_at": time.time() - 300}
        )
    else:
        request["attestation"]["network_isolation_verified"] = False
    with pytest.raises(ValueError):
        assurance.import_attestation(spec["provider"], request, "security-officer")
    assert not store.all_objects("provider-release-candidate")


@pytest.mark.parametrize("mutation", ["weights", "trust", "custody", "runtime", "qualification"])
def test_active_release_revalidates_every_trust_boundary(evidence, monkeypatch, mutation):
    spec, signed, _, custody, root, path, trust = evidence
    candidate, _ = activate(spec, signed)
    if mutation == "weights":
        (root / "weights/model.gguf").write_bytes(b"tampered weights")
    elif mutation == "trust":
        trust["signers"] = {"other": next(iter(trust["signers"].values()))}
        path.write_text(json.dumps(trust))
    elif mutation == "custody":
        bundle_custody.revoke(custody["id"])
    elif mutation == "runtime":
        monkeypatch.setattr(assurance, "_measure", lambda *args: {"pid": 999})
    else:
        identity = candidate["candidate"]["request"]["attestation"]["qualification_id"]
        value = store.require("provider-qualification", identity)
        value["passed"] = 0
        store.put("provider-qualification", identity, value)
    with pytest.raises(ValueError):
        assurance.require_active_release(spec)


def test_refresh_keeps_same_release_and_cannot_extend_review(evidence):
    spec, signed, attestation, *_ = evidence
    _, release = activate(spec, signed)
    expiry = store.require("provider-release", spec["provider"])["review_expires_at"]
    fresh = {**attestation, "issued_at": time.time(), "expires_at": time.time() + 600}
    refreshed = assurance.refresh(spec["provider"], signed(fresh), "security-officer")
    assert refreshed["id"] == release["id"]
    assert store.require("provider-release", spec["provider"])["review_expires_at"] == expiry
    assurance.revoke(spec["provider"], "security-officer")
    with pytest.raises(store.Denied):
        assurance.refresh(spec["provider"], signed(fresh), "security-officer")


def test_bundle_publisher_cannot_also_attest_independent_isolation(evidence):
    spec, signed, _, custody, root, path, trust = evidence
    trust["signers"]["independent"] = {
        "public_key_path": str(root.parent / "trusted-publisher.pem"),
        "public_key_sha256": custody["verification"]["signer_public_key_sha256"],
    }
    path.write_text(json.dumps(trust))
    with pytest.raises(store.Denied) as error:
        assurance.import_attestation(spec["provider"], signed(), "security-officer")
    assert error.value.code == "MODEL_ASSURANCE_UNTRUSTED"


def test_native_process_measurement_requires_the_owned_loopback_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = assurance._measure({"endpoint": f"http://127.0.0.1:{port}"}, os.getpid())
        assert result["pid"] == os.getpid() and result["created_at"] > 0
        assert len(result["executable_sha256"]) == 64
    with pytest.raises(store.Denied) as error:
        assurance._measure({"endpoint": f"http://127.0.0.1:{port}"}, os.getpid())
    assert error.value.code == "PROVIDER_RUNTIME_UNVERIFIED"


def test_audit_snapshot_contains_no_receipt_content_and_fails_closed():
    store.receipt("SYNTHETIC", "operator", prompt="PRIVATE_SOURCE", access_token="PRIVATE_TOKEN")
    result = audit_export.snapshot("auditor")
    assert result["count"] == 1 and result["independently_anchored"] is False
    assert "PRIVATE_" not in json.dumps(result) and "operator" not in json.dumps(result)
    with pytest.raises(store.Denied):
        audit_export.snapshot("operator")
    from aegis.storage.database import execute_write

    execute_write("UPDATE control_receipts SET hash=?", ("f" * 64,))
    with pytest.raises(store.Denied):
        audit_export.snapshot("auditor")


def test_password_reset_revokes_leases_and_destroys_retained_tasks():
    auth.provision("operator", "initial-synthetic-password")
    repository = service.add_repository(
        "fixture", service.DEMO_FILES, "Engineering", "INTERNAL", "data-owner"
    )
    stack = service.register_capsule("reference", "operator")
    for actor in ("model-custodian", "security-officer"):
        policy.decide(stack["approval"]["id"], actor, "APPROVE")
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    lease = service.issue_lease(
        repository["id"], stack["capsule"]["id"], "operator", "PLAN", 15, False, "data-owner"
    )
    task = service.run(lease["id"], "Explain valid_port", lease["purpose"], "operator")
    assert task["status"] == "COMPLETED"
    auth.provision("operator", "replacement-synthetic-password")
    assert store.get("coding-revocation", lease["id"])
    stored = service.verified("task", task["id"])
    assert (
        stored["status"] == "REVOKED" and "ciphertext" not in stored and "wrapped_key" not in stored
    )
    with pytest.raises(store.Denied):
        service.validate_lease(lease["id"], "operator", lease["purpose"])


def test_invalid_authorization_cannot_fall_back_to_valid_cookie():
    with TestClient(app) as client:
        auth.provision("operator", "initial-synthetic-password")
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "operator", "password": "initial-synthetic-password"},
            ).status_code
            == 200
        )
        for value in ("Basic invalid", "", "Bearer ", "Bearer invalid token"):
            assert client.get("/api/auth/me", headers={"Authorization": value}).status_code == 401
        assert (
            client.get(
                "/api/auth/me",
                headers=[("Authorization", "Bearer invalid"), ("Authorization", "Bearer invalid")],
            ).status_code
            == 401
        )
        assert client.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize(
    "origins",
    [
        ["http://testserver/extra"],
        ["http://testserver?query=1"],
        ["http://testserver#fragment"],
        ["http://testserver", "https://evil.invalid"],
    ],
)
def test_ambiguous_origins_rejected_with_uncacheable_security_headers(origins):
    with TestClient(app) as client:
        response = client.post(
            "/api/auth/login", headers=[("Origin", value) for value in origins], json={}
        )
        assert response.status_code == 403
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-frame-options"] == "DENY"


def test_generated_storage_rejects_hardlink_aliases(tmp_path):
    original = tmp_path / "private.txt"
    original.write_text("private")
    alias = tmp_path / "alias.txt"
    os.link(original, alias)
    with pytest.raises(ValueError, match="Hard-linked"):
        contained_file(tmp_path, alias.name)


def test_provider_deadline_interrupts_a_stalled_response():
    connection = MagicMock()
    interrupted = threading.Event()
    connection.sock.shutdown.side_effect = lambda *args: interrupted.set()

    def stalled():
        assert interrupted.wait(3), "Total deadline did not interrupt header receive"
        raise OSError("synthetic stalled header")

    connection.getresponse.side_effect = stalled
    # Measure the transport deadline from dispatch, excluding storage admission
    # and authenticated-ledger verification performed before the HTTP request.
    dispatched = []
    connection.request.side_effect = lambda *args, **kwargs: dispatched.append(time.monotonic())
    with patch.object(providers.http.client, "HTTPConnection", return_value=connection):
        with pytest.raises(store.Denied) as error:
            providers.request_json("/api/tags", spec={"timeout_seconds": 1})
    assert error.value.code == "LOCAL_MODEL_UNAVAILABLE"
    assert len(dispatched) == 1 and time.monotonic() - dispatched[0] < 3
    connection.sock.shutdown.assert_called_once()
    connection.close.assert_called_once()


def test_model_inventory_fails_closed_on_unreadable_directories(tmp_path):
    def failed_walk(*args, **kwargs):
        kwargs["onerror"](PermissionError("synthetic"))
        return iter(())

    with patch.object(retrieval.os, "walk", side_effect=failed_walk):
        with pytest.raises(ValueError, match="completely read"):
            retrieval.model_digest(str(tmp_path))
    with patch.object(cli.os, "walk", side_effect=failed_walk):
        with pytest.raises(cli.CLIError, match="completely read"):
            cli.import_files([str(tmp_path)])


def test_database_setup_failure_closes_the_open_connection():
    connection = MagicMock()
    connection.execute.side_effect = db.sqlite3.DatabaseError("synthetic setup failure")
    with patch.object(db.sqlite3, "connect", return_value=connection):
        with pytest.raises(db.sqlite3.DatabaseError):
            with db.get_db_connection():
                pytest.fail("Invalid database configuration reached the caller")
    connection.close.assert_called_once()


def test_startup_restricts_existing_database_file_permissions():
    with patch.object(db, "restrict_permissions", wraps=db.restrict_permissions) as restrict:
        db.init_db()
    assert all(call.args == (db.DB_PATH,) for call in restrict.call_args_list)
    assert restrict.call_count >= 1


def test_embedding_qualification_ranks_pinned_local_vectors(monkeypatch, tmp_path):
    class Model:
        model = None

        def __init__(self, directory, digest):
            assert digest == "a" * 64

        def encode(self, texts):
            return [[1.0, 0.0], [0.0, 1.0], [1.0, 0.0]]

    monkeypatch.setattr(embedding_qualification, "LocalEmbeddingSystem", Model)
    suite = {
        "schema_version": "aegis-embedding-qualification-v1",
        "classification": "PUBLIC",
        "cases": [
            {
                "id": "match",
                "query": "fixture",
                "documents": ["other", "fixture"],
                "expected_index": 1,
            }
        ],
    }
    result = embedding_qualification.run(str(tmp_path), "a" * 64, suite)
    assert result["passed"] == 1 and result["production_eligible"] is False
    assert "fixture" not in json.dumps(store.all_objects("embedding-qualification"))


def test_media_qualification_observes_text_without_retaining_pixels(monkeypatch):
    from test_media import png

    profile = providers.register(
        "model-custodian",
        name="Vision fixture",
        protocol="openai-compatible",
        engine="llama.cpp",
        endpoint="http://127.0.0.1:8080",
        model="vision-fixture",
        digest="a" * 64,
        local_only=True,
        vision=True,
    )

    def understand(spec, request, *, before_send):
        before_send()
        assert request["images"][0]["mime_type"] == "image/png"
        return {"answer": "A red rectangle", "images": []}

    monkeypatch.setattr(media_qualification.inference, "understand", understand)
    suite = {
        "schema_version": "aegis-media-qualification-v1",
        "classification": "PUBLIC",
        "cases": [
            {
                "id": "shape",
                "operation": "understand",
                "prompt": "Describe shape",
                "images": [png()],
                "required_text": ["rectangle"],
            }
        ],
    }
    result = media_qualification.run(profile["id"], suite, "model-custodian")
    assert result["passed"] == 1 and result["production_eligible"] is False
    assert "rectangle" not in json.dumps(store.all_objects("provider-qualification"))
