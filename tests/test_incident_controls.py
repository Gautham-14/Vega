"""Incident revocation and upload admission checks use disposable local state."""
import asyncio
from unittest.mock import Mock, patch

import pytest
from starlette.testclient import TestClient

import aegis_cli as cli
from aegis.api.limits import RequestBodyLimit
from aegis.api.server import app
from aegis.coding import providers, service, tools
from aegis.control import capsules, policy, store
from aegis.security import auth, lockdown
from aegis.storage.database import execute_write, init_db


@pytest.fixture
def storage():
    init_db()
    store.init_control()


def ready():
    repo = service.add_repository("Incident test", service.DEMO_FILES, "Engineering", "INTERNAL", "data-owner")
    stack = service.register_capsule("reference", "operator")
    for identity in ("model-custodian", "security-officer"):
        policy.decide(stack["approval"]["id"], identity, "APPROVE")
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    return lambda: service.issue_lease(repo["id"], stack["capsule"]["id"], "operator", "ASK", 15, False, "data-owner")


def cycle():
    lockdown.change(True, "security-officer")
    lockdown.change(False, "security-officer")


def test_lockdown_blocks_transport_and_survives_unlock(storage):
    create = ready()
    old = create()
    assert lockdown.check() == 0
    with pytest.raises(store.Denied, match="persona"):
        lockdown.change(True, "operator")
    lockdown.change(True, "security-officer")
    with patch.object(providers.http.client, "HTTPConnection") as transport:
        with pytest.raises(store.Denied) as error:
            providers.request_json("/api/tags")
        assert error.value.code == "EXECUTION_LOCKED"
        transport.assert_not_called()
    with pytest.raises(store.Denied):
        create()
    lockdown.change(False, "security-officer")
    with pytest.raises(store.Denied) as error:
        service.validate_lease(old["id"], "operator", old["purpose"])
    assert error.value.code == "EXECUTION_AUTHORIZATION_REVOKED"
    fresh = create()
    service.validate_lease(fresh["id"], "operator", fresh["purpose"])
    assert fresh["lockdown_generation"] == 2
    assert store.verify_chain()["is_valid"]


@pytest.mark.parametrize("attack", ["modify", "delete", "replay", "delete-history"])
def test_lockdown_state_tampering_fails_closed(storage, attack):
    lockdown.change(True, "security-officer")
    old = store.get("execution-lockdown", "global")
    cycle()
    if attack in {"delete", "delete-history"}:
        execute_write("DELETE FROM control_objects WHERE kind='execution-lockdown'")
        if attack == "delete-history":
            execute_write("DELETE FROM control_receipts WHERE json_extract(body,'$.action')=?", (lockdown.ACTION,))
    else:
        if attack == "modify":
            old["enabled"] = False
        store.put("execution-lockdown", "global", old)
    with pytest.raises(store.Denied) as error:
        lockdown.check()
    assert error.value.code == "LOCKDOWN_INTEGRITY_FAILURE"


def test_lockdown_during_inference_discards_proposal(storage):
    lease = ready()()
    def proposal(*args, **kwargs):
        cycle()
        return tools.Proposal(message="must not escape", actions=[])
    with patch.object(providers, "propose", side_effect=proposal):
        result = service.run(lease["id"], "Review the code", lease["purpose"], "operator")
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "EXECUTION_AUTHORIZATION_REVOKED"
    assert "must not escape" not in str(result)
    assert "ciphertext" not in service.verified("task", result["id"])


def test_lockdown_during_transport_discards_response(storage):
    def response(*args):
        cycle()
        return b'{"answer":"withheld"}'
    with patch.object(providers.http.client, "HTTPConnection") as transport:
        connection = transport.return_value
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.side_effect = response
        with pytest.raises(store.Denied) as error:
            providers.request_json("/api/tags")
        assert error.value.code == "EXECUTION_AUTHORIZATION_REVOKED"
        connection.close.assert_called_once()


def test_document_inference_is_revoked_and_not_retained(storage, monkeypatch):
    from aegis.control import demo
    from aegis.control.runtime import GovernedRunner
    from aegis.control.self_test import setup_fixture
    monkeypatch.setattr("aegis.hardware.detector.detect_hardware", lambda: {"available_ram_mb": 4096, "gpu": {"vram_mb": 0}})
    fixture = setup_fixture()
    original = GovernedRunner.infer
    def infer(self, sources, disclosed):
        result = original(self, sources, disclosed)
        cycle()
        return result
    with patch.object(GovernedRunner, "infer", infer):
        result = GovernedRunner().run(demo.task_request(fixture), "operator")
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "EXECUTION_AUTHORIZATION_REVOKED"
    assert not store.all_objects("artifact")
    assert "export" not in result


def test_demo_execution_disabled_during_lockdown(storage):
    from aegis.api.demo import require_demo_mode
    lockdown.change(True, "security-officer")
    with pytest.raises(store.Denied) as error:
        require_demo_mode()
    assert error.value.code == "EXECUTION_LOCKED"


def test_old_media_job_cannot_release_content_after_unlock(storage):
    from aegis.media import service as media
    from cryptography.fernet import Fernet
    import time
    job = {"id": "MEDIA-incident", "user": "operator", "status": "AWAITING_APPROVAL",
           "expires_at": time.time() + 900, "lockdown_generation": 0,
           "label": {"compartments": ["Public"], "classification": "PUBLIC"}}
    media.retain(job, {"request": {"prompt": "synthetic public request"}})
    cycle()
    with patch.object(Fernet, "decrypt", side_effect=AssertionError("Revoked content was decrypted")):
        with pytest.raises(store.Denied) as error:
            media.view(job["id"], "operator")
    assert error.value.code == "EXECUTION_AUTHORIZATION_REVOKED"


def test_api_requires_authenticated_security_officer(storage):
    password = "synthetic-only-password"
    for identity in ("operator", "security-officer"):
        auth.provision(identity, password)
    with TestClient(app) as client:
        assert client.post("/api/security/lockdown", json={"enabled": True}).status_code == 401
        operator = auth.login("operator", password, "incident-test")["access_token"]
        officer = auth.login("security-officer", password, "incident-test")["access_token"]
        assert client.post("/api/security/lockdown", json={"enabled": True},
                           headers={"Authorization": "Bearer " + operator}).status_code == 403
        headers = {"Authorization": "Bearer " + officer}
        assert client.post("/api/security/lockdown", json={"enabled": "false"}, headers=headers).status_code == 422
        result = client.post("/api/security/lockdown", json={"enabled": True}, headers=headers)
        assert result.status_code == 200, result.text
        assert result.json()["enabled"] is True
        assert client.get("/api/security/lockdown", headers=headers).json()["enabled"] is True
        assert client.post("/api/security/lockdown", json={"enabled": False}, headers=headers).json()["generation"] == 2


@pytest.mark.parametrize("action", ["status", "enable", "disable"])
def test_lockdown_cli(action):
    client = Mock()
    cli.execute(cli.build_parser().parse_args(["lockdown", action]), client)
    if action == "status":
        client.call.assert_called_once_with("/security/lockdown")
    else:
        client.call.assert_called_once_with("/security/lockdown", "POST", {"enabled": action == "enable"})


def test_public_status_does_not_measure_models(storage):
    with patch("aegis.coding.retrieval.configuration", side_effect=AssertionError("Expensive model scan")):
        with TestClient(app) as client:
            result = client.get("/api/coding/status")
    assert result.status_code == 200
    assert result.json()["semantic_search_status"] == "AUTHENTICATED_CAPABILITIES_REQUIRED"


SCOPE = {"type": "http", "method": "POST", "path": "/api/coding/tasks", "headers": []}


def test_slow_upload_timeout_releases_slot():
    async def exercise():
        messages = []
        async def send(message):
            messages.append(message)
        async def receive():
            await asyncio.Event().wait()
        async def downstream(*args):
            pytest.fail("Incomplete upload reached parser")
        limit = RequestBodyLimit(downstream)
        limit.read_timeout = 0.01
        await limit(SCOPE, receive, send)
        assert messages[0]["status"] == 408
        assert limit.readers == 0
    asyncio.run(exercise())


def test_upload_concurrency_rejects_excess_and_releases_disconnected_slots():
    async def exercise():
        started, finish = asyncio.Event(), asyncio.Event()
        responses = []
        async def receive():
            started.set()
            await finish.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            responses.append(message)
        async def downstream(*args):
            pytest.fail("Disconnected upload reached parser")
        limit = RequestBodyLimit(downstream)
        limit.max_readers = 1
        first = asyncio.create_task(limit(SCOPE, receive, send))
        await started.wait()
        await limit(SCOPE, receive, send)
        assert responses[0]["status"] == 429
        finish.set()
        await first
        assert limit.readers == 0
    asyncio.run(exercise())


def test_cancelled_upload_releases_slot():
    async def exercise():
        started = asyncio.Event()
        async def receive():
            started.set()
            await asyncio.Event().wait()
        async def unexpected(*args):
            pytest.fail("Cancelled upload must not dispatch or respond")
        limit = RequestBodyLimit(unexpected)
        pending = asyncio.create_task(limit(SCOPE, receive, unexpected))
        await started.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert limit.readers == 0
    asyncio.run(exercise())


@pytest.mark.parametrize("length,expected", [(1000, 200), (1001, 400)])
def test_tiny_chunks_are_bounded_and_declared_length_checked(length, expected):
    async def exercise():
        count = 0
        responses = []
        async def receive():
            nonlocal count
            count += 1
            return {"type": "http.request", "body": b"x", "more_body": count < 1000}
        async def send(message):
            responses.append(message)
        async def downstream(scope, receive, send):
            assert (await receive())["body"] == b"x" * 1000
            await send({"type": "http.response.start", "status": 200})
        limit = RequestBodyLimit(downstream)
        await limit({**SCOPE, "headers": [(b"content-length", str(length).encode())]}, receive, send)
        assert responses[0]["status"] == expected
        assert limit.readers == 0
    asyncio.run(exercise())
