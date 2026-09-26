"""Authenticated media API smoke test over real loopback HTTP to fixture servers.

This validates wire protocols and governance, not a real model's quality.
"""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import threading

import pytest
from starlette.testclient import TestClient
from aegis.api.server import app
from aegis.security import auth

Image = pytest.importorskip("PIL.Image")


@pytest.mark.parametrize("operation", ["understand", "generate", "edit"])
def test_authenticated_media_workflow_over_loopback_http(operation, monkeypatch):
    raw = io.BytesIO()
    Image.new("RGB", (64, 64), "green").save(raw, format="PNG")
    encoded = base64.b64encode(raw.getvalue()).decode()
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send_json(self, value):
            payload = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            calls.append(self.path)
            if self.path == "/v1/models":
                self.send_json({"data": [{"id": "fixture-reviewed"}]})
            elif self.path == "/sdapi/v1/sd-models":
                self.send_json([{"model_name": "fixture-reviewed", "sha256": "a" * 64}])
            elif self.path == "/sdapi/v1/options":
                self.send_json({"sd_checkpoint_hash": "a" * 64})
            else:
                self.send_error(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(self.path)
            if self.path == "/v1/chat/completions":
                parts = body["messages"][1]["content"]
                assert parts[1]["image_url"]["url"].startswith("data:image/png;base64,")
                self.send_json({"model": "fixture-reviewed", "choices": [{"finish_reason": "stop", "message": {"content": "A green square."}}]})
            elif self.path in {"/sdapi/v1/txt2img", "/sdapi/v1/img2img"}:
                assert not body["save_images"]
                if self.path.endswith("img2img"):
                    assert len(body["init_images"]) == 1
                self.send_json({"images": [encoded], "info": json.dumps({"sd_model_hash": "a" * 10})})
            else:
                self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    try:
        with TestClient(app) as client:
            headers = {}
            for actor in ("operator", "model-custodian", "security-officer", "data-owner"):
                password = "test-only-" + actor + "-passphrase"
                auth.provision(actor, password)
                login = client.post("/api/auth/login", json={"username": actor, "password": password})
                assert login.status_code == 200
                headers[actor] = {"Authorization": "Bearer " + login.json()["access_token"]}
            client.cookies.clear()

            def post(path, body=None, actor="operator"):
                response = client.post("/api/" + path, json=body, headers=headers[actor])
                assert response.status_code in {200, 201}, response.text
                return response.json()

            def approve(approval_id, roles):
                for actor in roles:
                    post(f"control/approvals/{approval_id}/decide", {"decision": "APPROVE"}, actor)

            definition = {"name": "Loopback fixture", "model": "fixture-reviewed", "digest": "a" * 64, "local_only": True,
                          "endpoint": f"http://127.0.0.1:{server.server_port}",
                          "protocol": "openai-compatible" if operation == "understand" else "sd-webui",
                          "engine": "vllm" if operation == "understand" else "automatic1111", "vision": operation == "understand"}
            provider = post("providers", definition, "model-custodian")
            stack = post("media/capsules", {"provider": provider["id"]})
            approve(stack["approval"]["id"], ("model-custodian", "security-officer"))
            post(f"control/capsules/{stack['capsule']['id']}/approve", {"approval_id": stack["approval"]["id"]}, "model-custodian")
            prepared = post("media/tasks", {"capsule_id": stack["capsule"]["id"], "operation": operation,
                            "prompt": "Describe the shapes" if operation == "understand" else "Draw a green square",
                            "images": [] if operation == "generate" else [encoded], "width": 64, "height": 64,
                            "classification": "PUBLIC"})
            task_id = prepared["task"]["id"]
            assert not calls
            assert client.post(f"/api/media/tasks/{task_id}/run", headers=headers["operator"]).status_code == 403
            review = client.get(f"/api/media/tasks/{task_id}", headers=headers["security-officer"])
            assert review.status_code == 200
            approve(prepared["approval"]["id"], ("data-owner", "security-officer"))
            result = post(f"media/tasks/{task_id}/run")
            assert result["status"] == "COMPLETED"
            assert calls
            if operation != "understand":
                preview = client.get(f"/api/media/tasks/{task_id}/images/output/0", headers=headers["operator"])
                assert preview.status_code == 200 and preview.content.startswith(b"\x89PNG")
            approval = post(f"media/tasks/{task_id}/export-request")
            approve(approval["id"], ("data-owner", "security-officer"))
            exported = post(f"media/tasks/{task_id}/export", {"approval_id": approval["id"]})
            assert exported["result_hash"] == result["result_hash"]
            assert client.get("/api/control/receipts/verify", headers=headers["security-officer"]).json()["is_valid"]
            post(f"media/tasks/{task_id}/revoke")
            assert client.get(f"/api/media/tasks/{task_id}", headers=headers["operator"]).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
