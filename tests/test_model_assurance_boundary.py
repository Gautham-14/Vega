"""A manifest checksum and fixture benchmark must never imply production trust."""

from starlette.testclient import TestClient

from aegis.api.server import app
from aegis.models.manifest import compute_manifest_sha256
from aegis.models.registry import get_model_by_id, import_model_manifest, run_simulated_qualification, seed_model_registry
from aegis.storage.database import init_db


def _manifest():
    value = {
        "id": "CHECKSUM-ONLY", "name": "Uninstalled candidate", "version": "1",
        "architecture": "fixture", "parameters": "8B", "quantization": "Q4",
        "capabilities": ["text"], "license": "MIT", "sha256": "0" * 64,
    }
    value["sha256"] = compute_manifest_sha256(value)
    return value


def test_metadata_only_candidate_stays_ineligible_after_fixture_qualification():
    init_db()
    seed_model_registry()
    imported = import_model_manifest(_manifest())
    assert imported["manifest_checksum_matches"] is True
    assert imported["integrity_verified"] is False
    assert imported["artifact_integrity_verified"] is False

    qualified = run_simulated_qualification("CHECKSUM-ONLY")
    record = get_model_by_id("CHECKSUM-ONLY")
    assert qualified["new_status"] == record["status"] == "DEMO_QUALIFIED"
    assert record["production_eligible"] is False
    assert record["publisher_signature_verified"] is False
    assert record["runtime_binding_verified"] is False
    assert record["benchmark_summary"]["score_is_measured"] is False


def test_production_api_rejects_demo_manifest_import(monkeypatch):
    init_db()
    from aegis.control.store import init_control
    init_control()
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    from aegis.security.auth import provision
    provision("model-custodian", "test-only-password-123")
    provision("data-owner", "test-only-password-456")
    with TestClient(app) as client:
        login = client.post("/api/auth/login", json={"username": "model-custodian", "password": "test-only-password-123"})
        assert login.status_code == 200
        response = client.post("/api/models/import", json=_manifest())
        assert response.status_code == 404
        assert client.post("/api/control/self-test", json={}).status_code == 404
        assert client.post("/api/auth/login", json={"username": "data-owner", "password": "test-only-password-456"}).status_code == 200
        document = {"id": "PRIVATE-SOURCE", "filename": "private.txt", "title": "Private source",
                    "revision": "1", "status": "DRAFT", "equipment_id": "P-204",
                    "department": "Engineering", "classification": "INTERNAL",
                    "effective_date": "2026-09-25", "content": "confidential fixture"}
        assert client.post("/api/knowledge/upload", json=document).status_code == 404
        assert get_model_by_id("CHECKSUM-ONLY") is None

    from aegis.control import packages
    from aegis.control.store import Denied
    try:
        packages.executable("previously-approved-demo-package", "inspection-review-v3")
    except Denied as error:
        assert error.code == "DEMO_PACKAGE_DISABLED"
    else:
        raise AssertionError("A persisted mock package became executable outside demo mode")
