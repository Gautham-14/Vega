"""Provider registration, local-only transport, and model identity/proposal gates."""
import json
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from aegis.api.server import app
from aegis.coding import providers, service
from aegis.control import store
from aegis.security import auth
from aegis.storage.database import init_db, query_all


def definition(**changes):
    return {"name": "Local coder", "protocol": "openai-compatible", "engine": "llama.cpp",
            "endpoint": "http://127.0.0.1:8080/v1", "model": "local-coder-Q4_K_M",
            "digest": "a" * 64, "local_only": True, **changes}


@pytest.fixture
def storage():
    init_db()
    store.init_control()
    auth.init_auth()


def registered(**changes):
    return providers.register("model-custodian", **definition(**changes))


@pytest.mark.parametrize("endpoint", [
    "https://api.openai.com/v1", "http://localhost:8080", "http://127.0.0.1.evil.test", "http://127.1:8080",
    "http://2130706433", "http://0.0.0.0:8080", "http://10.0.0.1", "http://[::ffff:127.0.0.1]",
    "http://127.0.0.1@evil.test", "http://user:password@127.0.0.1", "http://127.0.0.1:0",
    "http://127.0.0.1:65536", "http://127.0.0.1/v1?remote=1", "http://127.0.0.1/#x",
    "http://[::1%25lo0]", "http://127.0.0.1/api/pull", "file:///models/coder", " http://127.0.0.1",
    "http://127.0.0.1/\r\n", "http://127.0.0.1\\evil.test",
])
def test_profiles_reject_non_loopback_and_ambiguous_urls(storage, endpoint):
    with pytest.raises(ValueError):
        registered(endpoint=endpoint)
    assert not store.all_objects("provider-profile")


@pytest.mark.parametrize("endpoint,canonical", [
    ("http://127.0.0.1:1234/v1/", "http://127.0.0.1:1234"),
    ("http://127.0.0.2:8000/", "http://127.0.0.2:8000"),
    ("https://[::1]:8000", "https://[::1]:8000"),
])
def test_profiles_canonicalize_numeric_loopback(storage, endpoint, canonical):
    assert registered(endpoint=endpoint)["endpoint"] == canonical


@pytest.mark.parametrize("changes", [
    {"local_only": False}, {"model": "coder:latest"}, {"model": "coder-cloud:reviewed"},
    {"digest": "abc"}, {"protocol": "ollama"}, {"max_tokens": 0}, {"max_tokens": 8193},
    {"timeout_seconds": 121}, {"timeout_seconds": True}, {"max_response_bytes": 1_000_001},
    {"api_key_env": "AWS_SECRET_ACCESS_KEY"}, {"api_key_env": "sk-secret"}, {"api_key": "secret"},
])
def test_profiles_require_explicit_bounded_local_configuration(storage, changes):
    with pytest.raises(ValueError):
        registered(**changes)


def test_profiles_require_custodian_and_are_sealed(storage):
    with pytest.raises(store.Denied) as exc:
        providers.register("operator", **definition())
    assert exc.value.code == "UNAUTHORIZED_ROLE"
    value = registered()
    spec = providers.specification(value["id"])
    assert spec["provider"] == value["id"] and spec["protocol"] == "openai-compatible"
    assert spec["digest_verification"] == "CUSTODIAN_ASSERTED"
    stack = service.register_capsule(value["id"], "operator")
    assert stack["capsule"]["components"]["model"] == spec
    changed = store.require("provider-profile", value["id"])
    changed["endpoint"] = "http://evil.test"
    store.put("provider-profile", value["id"], changed)
    with pytest.raises(store.Denied) as exc:
        providers.specification(value["id"])
    assert exc.value.code == "PROVIDER_INTEGRITY_FAILURE"


def test_unverified_live_provider_cannot_receive_internal_repository(storage):
    from aegis.control import capsules, policy
    provider = registered()
    stack = service.register_capsule(provider["id"], "operator")
    for actor in ("model-custodian", "security-officer"):
        policy.decide(stack["approval"]["id"], actor, "APPROVE")
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    internal = service.add_repository("private", {"main.py": "secret = 1\n"}, "Engineering", "INTERNAL", "data-owner")
    with pytest.raises(store.Denied) as error:
        service.issue_lease(internal["id"], stack["capsule"]["id"], "operator", "PLAN", 15, False, "data-owner")
    assert error.value.code == "MODEL_ASSURANCE_REQUIRED"
    public = service.add_repository("public", {"main.py": "x = 1\n"}, "Engineering", "PUBLIC", "data-owner")
    assert service.issue_lease(public["id"], stack["capsule"]["id"], "operator", "PLAN", 15, False, "data-owner")["label"]["classification"] == "PUBLIC"


def connection_for(body, status=200):
    connection = MagicMock()
    connection.getresponse.return_value.status = status
    connection.getresponse.return_value.read.return_value = json.dumps(body).encode()
    return connection


def test_transport_direct_address_key_reference_and_bounds(storage, monkeypatch):
    secret = "local-secret-never-stored"
    monkeypatch.setenv("AEGIS_PROVIDER_LLAMA_API_KEY", secret)
    value = registered(api_key_env="AEGIS_PROVIDER_LLAMA_API_KEY", timeout_seconds=11, max_response_bytes=8192)
    spec = providers.specification(value["id"])
    connection = connection_for({"data": [{"id": spec["model"]}]})
    with patch.object(providers.http.client, "HTTPConnection", return_value=connection) as factory:
        result = providers.probe(value["id"], "operator")
    assert factory.call_args.args == ("127.0.0.1", 8080)
    assert factory.call_args.kwargs == {"timeout": 11}
    assert connection.request.call_args.args == ("GET", "/v1/models")
    assert connection.request.call_args.kwargs["headers"]["Authorization"] == "Bearer " + secret
    connection.getresponse.return_value.read.assert_called_once_with(8193)
    connection.close.assert_called_once()
    assert result["status"] == "AVAILABLE" and not result["weight_digest_independently_verified"]
    assert not result["server_digest_matches_pin"]
    assert secret not in json.dumps(result) + json.dumps(value) + json.dumps(store.receipts())
    assert secret not in " ".join(row["body"] for row in query_all("SELECT body FROM control_objects"))


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 500])
def test_transport_never_follows_redirects_or_echoes_error_body(storage, status):
    spec = providers.specification(registered()["id"])
    connection = connection_for({"error": "secret error body"}, status)
    with patch.object(providers.http.client, "HTTPConnection", return_value=connection):
        with pytest.raises(store.Denied) as exc:
            providers.request_json("/v1/models", spec=spec)
    assert connection.request.call_count == 1
    connection.getresponse.return_value.read.assert_not_called()
    connection.close.assert_called_once()
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("path,body", [("/api/pull", {}), ("/v1/models/download", {}),
                                       ("http://evil.test/v1/models", None), ("/v1/chat/completions", None)])
def test_transport_has_finite_operation_allowlist(storage, path, body):
    with patch.object(providers.http.client, "HTTPConnection") as factory:
        with pytest.raises(store.Denied):
            providers.request_json(path, body, spec=providers.specification(registered()["id"]))
        factory.assert_not_called()


@pytest.mark.parametrize("payload", [b"x" * 1_000_001, b"[]", b"null", b"not-json"],
                         ids=["oversize", "array", "null", "malformed"])
def test_transport_rejects_oversized_and_malformed_responses(storage, payload):
    connection = connection_for({})
    connection.getresponse.return_value.read.return_value = payload
    with patch.object(providers.http.client, "HTTPConnection", return_value=connection):
        with pytest.raises(store.Denied) as exc:
            providers.request_json("/api/tags")
    assert exc.value.code == "LOCAL_MODEL_UNAVAILABLE"


def test_transport_fails_closed_on_missing_key_and_timeout(storage, monkeypatch):
    monkeypatch.delenv("AEGIS_PROVIDER_MISSING_API_KEY", raising=False)
    spec = providers.specification(registered(api_key_env="AEGIS_PROVIDER_MISSING_API_KEY")["id"])
    with patch.object(providers.http.client, "HTTPConnection") as factory:
        with pytest.raises(store.Denied) as exc:
            providers.request_json("/v1/models", spec=spec)
        assert exc.value.code == "PROVIDER_CREDENTIAL_UNAVAILABLE"
        factory.assert_not_called()
    spec = providers.specification(registered()["id"])
    connection = MagicMock()
    connection.request.side_effect = TimeoutError("sensitive exception text")
    with patch.object(providers.http.client, "HTTPConnection", return_value=connection):
        with pytest.raises(store.Denied) as exc:
            providers.request_json("/v1/models", spec=spec)
        assert "sensitive" not in str(exc.value)
        connection.close.assert_called_once()


def test_compatible_proposal_is_pinned_and_structured(storage):
    spec = providers.specification(registered(max_tokens=512)["id"])
    response = {"model": spec["model"], "choices": [{"finish_reason": "stop", "message": {
        "role": "assistant", "content": '{"message":"Ready for review","actions":[]}'}}]}
    with patch.object(providers, "request_json", side_effect=[{"data": [{"id": spec["model"]}]}, response]) as request:
        assert providers.propose(spec, [], "PLAN", 0).message == "Ready for review"
    path, body = request.call_args.args
    assert path == "/v1/chat/completions" and body["max_tokens"] == 512 and body["stream"] is False
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert request.call_args.kwargs["spec"] == spec


@pytest.mark.parametrize("response", [
    {"choices": []}, {"choices": [{"finish_reason": "length", "message": {"content": '{"message":"partial"}'}}]},
    {"model": "another-model", "choices": [{"finish_reason": "stop", "message": {"content": '{"message":"wrong"}'}}]},
    {"model": "local-coder-Q4_K_M", "choices": [{"finish_reason": "stop", "message": {"content": '{"message":"x","authority":"root"}'}}]},
    {"model": "local-coder-Q4_K_M", "choices": [{"finish_reason": "stop", "message": {"content": '{"message":5}'}}]},
    {"model": "local-coder-Q4_K_M", "choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]},
    {"model": "local-coder-Q4_K_M", "choices": [{"finish_reason": "stop", "message": {"tool_calls": [{"name": "shell"}], "content": '{"message":"x"}'}}]},
])
def test_compatible_proposal_fails_closed(storage, response):
    spec = providers.specification(registered()["id"])
    with patch.object(providers, "request_json", side_effect=[{"data": [{"id": spec["model"]}]}, response]):
        with pytest.raises(store.Denied) as exc:
            providers.propose(spec, [], "ASK", 0)
        assert exc.value.code == "INVALID_MODEL_PROPOSAL"


def test_no_generation_when_pinned_model_missing_or_ollama_digest_changed(storage):
    for config, listing, code in [
        (definition(), {"data": []}, "MODEL_NOT_INSTALLED"),
        (definition(protocol="ollama", engine="ollama", endpoint="http://127.0.0.1:11434", model="coder:reviewed"),
         {"models": [{"name": "coder:reviewed", "digest": "b" * 64}]}, "MODEL_DIGEST_MISMATCH"),
    ]:
        spec = providers.specification(providers.register("model-custodian", **config)["id"])
        with patch.object(providers, "request_json", return_value=listing) as request:
            with pytest.raises(store.Denied) as exc:
                providers.propose(spec, [], "ASK", 0)
            assert exc.value.code == code
            assert request.call_count == 1


def test_provider_api_authenticated_registration_inventory_and_probe(storage, monkeypatch):
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    auth.provision("operator", "operator-password-123")
    auth.provision("model-custodian", "custodian-password-123")
    operator = {"Authorization": "Bearer " + auth.login("operator", "operator-password-123", "provider-test")["access_token"]}
    custodian = {"Authorization": "Bearer " + auth.login("model-custodian", "custodian-password-123", "provider-test")["access_token"]}
    with TestClient(app) as client:
        assert client.get("/api/providers").status_code == 401
        assert client.post("/api/providers", json=definition(), headers=operator).status_code == 403
        response = client.post("/api/providers", json=definition(), headers=custodian)
        assert response.status_code == 201, response.text
        value = response.json()
        assert "seal" not in value
        listing = client.get("/api/providers", headers=operator).json()
        assert listing["providers"] == [value] and listing["automatic_downloads"] is False
        assert client.get("/api/providers/" + value["id"], headers=operator).json() == value
        with patch.object(providers, "request_json", return_value={"data": [{"id": value["model"]}]}):
            probe = client.post("/api/providers/" + value["id"] + "/probe", headers=operator)
        assert probe.status_code == 200 and probe.json()["digest_verification"] == "CUSTODIAN_ASSERTED"
