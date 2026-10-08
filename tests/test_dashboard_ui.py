"""CLI-only startup preserves telemetry and local documentation endpoints."""
from starlette.testclient import TestClient
from aegis.api.server import app


def test_retired_frontend_is_not_advertised_or_served():
    with TestClient(app) as client:
        assert client.get("/").status_code == 404
        assert client.get("/static/js/telemetry.js").status_code == 404
        docs = client.get("/docs")
        assert docs.status_code == 200
        assert "authenticated local CLI" in docs.text
        assert "<script" not in docs.text


def test_cli_telemetry_reports_real_measurements_without_static_assets():
    with TestClient(app) as client:
        sample = client.get("/api/telemetry/latest").json()
        assert sample["source"] == "HOST_MEASURED"
        assert sample["timestamp"] > 0 and sample["memory_total_bytes"] > 0
        assert sample["gpu_percent"] is None
