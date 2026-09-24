import time
import pytest
from starlette.testclient import TestClient
from aegis.api.server import app
from aegis.security import auth
from aegis.storage.database import query_all, execute_write


def test_login_identity_cannot_be_spoofed_and_logout_revokes(monkeypatch):
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    with TestClient(app) as client:
        assert client.get("/api/auth/status").json()["configured"] is False
        assert client.get("/api/coding/state", headers={"X-Aegis-Actor": "data-owner"}).status_code == 401
        auth.provision("operator", "test-password-at-least-12")
        result = client.post("/api/auth/login", json={"username": "operator", "password": "test-password-at-least-12"})
        assert result.status_code == 200
        token = result.json()["access_token"]
        assert "HttpOnly" in result.headers["set-cookie"] and "SameSite=strict" in result.headers["set-cookie"]
        assert client.get("/api/auth/me", headers={"X-Aegis-Actor": "security-officer"}).json()["id"] == "operator"
        assert client.post("/api/coding/repositories", json={"name": "x", "files": {"x.py": "x = 1"}},
                           headers={"X-Aegis-Actor": "data-owner"}).status_code == 403
        assert client.get("/api/knowledge").status_code == 403
        assert client.get("/api/coding/state").status_code == 200
        rows = str([dict(row) for row in query_all("SELECT * FROM auth_sessions")]) + str([dict(row) for row in query_all("SELECT * FROM auth_accounts")])
        assert token not in rows and "test-password-at-least-12" not in rows
        assert client.post("/api/auth/logout").json()["signed_out"]
        assert client.get("/api/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_demo_header_disabled_as_soon_as_account_provisioned():
    with TestClient(app) as client:
        assert client.get("/api/auth/me", headers={"X-Aegis-Actor": "data-owner"}).json()["id"] == "data-owner"
        auth.provision("operator", "test-password-at-least-12")
        assert not client.get("/api/auth/status").json()["demo"]
        assert client.get("/api/auth/me", headers={"X-Aegis-Actor": "data-owner"}).status_code == 401


def test_password_reset_and_expiry_revoke_sessions():
    with TestClient(app) as client:
        auth.provision("operator", "test-password-at-least-12")
        body = {"username": "operator", "password": "test-password-at-least-12"}
        assert client.post("/api/auth/login", json=body).status_code == 200
        execute_write("UPDATE auth_sessions SET expires_at=?", (time.time() - 1,))
        assert client.get("/api/auth/me").status_code == 401
        client.post("/api/auth/login", json=body)
        auth.provision("operator", "replacement-test-password")
        assert client.get("/api/auth/me").status_code == 401
        assert client.post("/api/auth/login", json=body).status_code == 401


def test_login_rate_limit_and_cross_origin():
    with TestClient(app) as client:
        auth.provision("operator", "test-password-at-least-12")
        for _ in range(8):
            assert client.post("/api/auth/login", json={"username": "operator", "password": "wrong"}).status_code == 401
        assert client.post("/api/auth/login", json={"username": "operator", "password": "test-password-at-least-12"}).status_code == 429
        assert client.post("/api/auth/login", json={"username": "operator", "password": "wrong"},
                           headers={"Origin": "https://attacker.invalid"}).status_code == 403


def test_successful_low_role_login_does_not_reset_guess_counter():
    with TestClient(app) as client:
        auth.provision("operator", "test-password-at-least-12")
        auth.provision("model-custodian", "different-custodian-password")
        for _ in range(7):
            assert client.post("/api/auth/login", json={"username": "model-custodian", "password": "guess"}).status_code == 401
        assert client.post("/api/auth/login", json={"username": "operator", "password": "test-password-at-least-12"}).status_code == 200
        assert client.post("/api/auth/login", json={"username": "model-custodian", "password": "guess"}).status_code == 401
        assert client.post("/api/auth/login", json={"username": "model-custodian", "password": "guess"}).status_code == 429


def test_invalid_login_schema_does_not_echo_credentials():
    with TestClient(app) as client:
        password = "sensitive-rejected-input" * 20
        response = client.post("/api/auth/login", json={"username": "operator", "password": password})
        assert response.status_code == 422 and password not in response.text
