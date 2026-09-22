"""The operator site must start without synthetic records."""

from starlette.testclient import TestClient

from aegis.api.server import app


def test_fresh_workspace_has_no_seeded_data(monkeypatch):
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    with TestClient(app) as client:
        status = client.get("/api/dashboard/status").json()
        assert status["registered_models"] == 0
        assert status["registered_documents"] == 0
        assert status["recent_tasks_count"] == 0
        assert status["recent_receipts_count"] == 0
        assert client.get("/api/models").json() == []
        assert client.get("/api/knowledge").json() == []
        assert client.post("/api/tasks/demo", json={}).status_code == 404
        assert client.post("/api/security/self-test").status_code == 404
        assert len(client.get("/api/hardware/profiles").json()) == 1
