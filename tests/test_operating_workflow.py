"""Real API contracts from sign-in through reviewed export, without demo identity."""
from starlette.testclient import TestClient
from aegis.api.server import app
from aegis.coding.service import DEMO_FILES
from aegis.security.auth import provision


def test_authenticated_coding_workflow_and_dashboard(monkeypatch):
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    with TestClient(app) as client:
        actors = ("operator", "model-custodian", "security-officer", "data-owner")
        tokens = {}
        for actor in actors:
            provision(actor, "disposable-test-password")
            login = client.post("/api/auth/login", json={"username": actor, "password": "disposable-test-password"})
            assert login.status_code == 200
            tokens[actor] = {"Authorization": "Bearer " + login.json()["access_token"]}
        def post(path, actor="operator", body=None):
            response = client.post("/api/" + path, headers=tokens[actor], json=body)
            assert response.status_code in {200, 201}, response.text
            return response.json()
        repo = post("coding/repositories", "data-owner", {"name": "Reference source", "files": DEMO_FILES})
        stack = post("coding/capsules", body={"provider": "reference"})
        for actor in ("model-custodian", "security-officer"):
            post(f"control/approvals/{stack['approval']['id']}/decide", actor, {"decision": "APPROVE"})
        post(f"control/capsules/{stack['capsule']['id']}/approve", "model-custodian", {"approval_id": stack["approval"]["id"]})
        lease = post("coding/leases", "data-owner", {"repository_id": repo["id"], "capsule_id": stack["capsule"]["id"],
                     "user": "operator", "mode": "EXECUTE", "minutes": 15, "allow_export": True})
        task = post("coding/tasks", body={"lease_id": lease["id"], "prompt": "Fix valid_port", "purpose": lease["purpose"]})
        assert task["status"] == "AWAITING_REVIEW"
        post(f"coding/tasks/{task['id']}/apply", body={"diff_hash": task["diff_hash"]})
        approval = post(f"coding/tasks/{task['id']}/export-request")
        for actor in ("data-owner", "security-officer"):
            reviewed = client.get(f"/api/coding/approvals/{approval['id']}/review", headers=tokens[actor])
            assert reviewed.json()["diff_hash"] == task["diff_hash"]
            post(f"control/approvals/{approval['id']}/decide", actor, {"decision": "APPROVE"})
        exported = post(f"coding/tasks/{task['id']}/export", body={"approval_id": approval["id"]})
        assert "+    return 1 <= port" in exported["patch"]
        dashboard = client.get("/api/telemetry/workspace", headers=tokens["operator"]).json()
        assert dashboard["tasks"][0]["id"] == task["id"]
        assert "valid_port" not in str(dashboard)
        events = client.get("/api/telemetry/events", headers=tokens["security-officer"]).json()
        assert any(event["route"] == "/api/coding/tasks/{task_id}/export" for event in events)
        assert all(task["id"] not in event["route"] for event in events)
        post(f"coding/tasks/{task['id']}/close")
        assert client.get("/api/control/receipts/verify", headers=tokens["operator"]).json()["is_valid"]
