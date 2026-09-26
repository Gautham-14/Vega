"""Actual image codecs and governed media flows; inference servers are test doubles."""
import base64
import io
import json
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient
from aegis.api.server import app
from aegis.coding import providers
from aegis.control import capsules, policy, store
from aegis.media import images, inference, service
from aegis.security import auth
from aegis.storage.database import init_db, query_all

Image = pytest.importorskip("PIL.Image")


def png(width=64, height=64, **kwargs):
    raw = io.BytesIO()
    Image.new("RGB", (width, height), "navy").save(raw, format="PNG", **kwargs)
    return base64.b64encode(raw.getvalue()).decode()


@pytest.fixture(autouse=True)
def storage():
    init_db()
    store.init_control()
    auth.init_auth()


def approve(approval, roles=("data-owner", "security-officer")):
    for role in roles:
        policy.decide(approval["id"], role, "APPROVE")


def setup_provider(protocol="openai-compatible"):
    definition = {"name": "Local media", "protocol": protocol,
        "engine": {"openai-compatible": "vllm", "ollama": "ollama", "sd-webui": "automatic1111"}[protocol],
        "endpoint": "http://127.0.0.1:7860" if protocol == "sd-webui" else "http://127.0.0.1:8080",
        "model": "fixture:reviewed", "digest": "a" * 64, "local_only": True, "vision": protocol != "sd-webui",
        "max_response_bytes": 12_000_000 if protocol == "sd-webui" else 1_000_000}
    provider = providers.register("model-custodian", **definition)
    stack = service.register_capsule(provider["id"], "operator")
    approve(stack["approval"], ("model-custodian", "security-officer"))
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    return provider, stack["capsule"]["id"]


def prepare(operation="understand", protocol="openai-compatible"):
    provider, capsule_id = setup_provider(protocol)
    request = {"capsule_id": capsule_id, "operation": operation, "prompt": "Describe the geometric shapes.",
               "images": [] if operation == "generate" else [png()], "width": 64, "height": 64,
               "classification": "PUBLIC"}
    prepared = service.prepare(request, "operator")
    return provider, prepared, request


def fake_vision(protocol):
    def call(path, body=None, **kwargs):
        if path == "/v1/models":
            return {"data": [{"id": "fixture:reviewed"}]}
        if path == "/api/tags":
            return {"models": [{"name": "fixture:reviewed", "digest": "a" * 64}]}
        assert kwargs["media"] is True
        user = body["messages"][1]
        if protocol == "openai-compatible":
            encoded = user["content"][1]["image_url"]["url"]
            assert encoded.startswith("data:image/png;base64,")
            return {"model": "fixture:reviewed", "choices": [{"finish_reason": "stop", "message": {"content": "A navy square."}}]}
        assert base64.b64decode(user["images"][0]).startswith(b"\x89PNG")
        assert body["keep_alive"] == 0
        return {"model": "fixture:reviewed", "done": True, "message": {"content": "A navy square."}}
    return call


@pytest.mark.parametrize("protocol", ["openai-compatible", "ollama"])
def test_vision_sends_real_image_pixels_and_retains_encrypted(protocol, monkeypatch):
    provider, prepared, _ = prepare(protocol=protocol)
    task = prepared["task"]
    call = Mock(side_effect=fake_vision(protocol))
    monkeypatch.setattr(providers, "request_json", call)
    with pytest.raises(store.Denied, match="must approve"):
        service.run(task["id"], "operator")
    assert not call.called
    approve(prepared["approval"])
    result = service.run(task["id"], "operator")
    assert result["status"] == "COMPLETED" and result["result"]["answer"] == "A navy square."
    assert result["external_model_calls"] == 0
    stored = store.require("media-job", task["id"])
    assert "A navy square" not in json.dumps(stored)
    assert "Describe the geometric" not in json.dumps(stored)
    receipts = json.dumps([dict(row) for row in query_all("SELECT body FROM control_receipts")])
    assert "A navy square" not in receipts and "Describe the geometric" not in receipts
    with pytest.raises(store.Denied, match="another account"):
        service.view(task["id"], "finance-operator")
    with pytest.raises(store.Denied, match="new reviewed task"):
        service.run(task["id"], "operator")
    approval = service.request_export(task["id"], "operator")
    with pytest.raises(store.Denied, match="Export requires"):
        service.export(task["id"], approval["id"], "operator")
    approve(approval)
    assert service.export(task["id"], approval["id"], "operator")["result"]["answer"] == "A navy square."
    service.revoke(task["id"], "operator")
    assert "ciphertext" not in store.require("media-job", task["id"])
    with pytest.raises(store.Denied):
        service.export(task["id"], approval["id"], "operator")


@pytest.mark.parametrize("operation", ["generate", "edit"])
def test_diffusion_bounded_generation_edit_and_checkpoint_verification(operation, monkeypatch):
    _, prepared, _ = prepare(operation, "sd-webui")
    approve(prepared["approval"])
    def call(path, body=None, **kwargs):
        if path.endswith("sd-models"):
            return [{"model_name": "fixture:reviewed", "sha256": "a" * 64}]
        if path.endswith("options"):
            assert body is None
            return {"sd_checkpoint_hash": "a" * 64}
        assert path.endswith("img2img" if operation == "edit" else "txt2img")
        assert body["batch_size"] == body["n_iter"] == 1
        assert not body["save_images"] and body["do_not_save_samples"] and not body["alwayson_scripts"]
        assert "override_settings" not in body
        if operation == "edit":
            assert len(body["init_images"]) == 1 and body["denoising_strength"] == 0.6
        return {"images": [png()], "info": json.dumps({"sd_model_hash": "a" * 10})}
    monkeypatch.setattr(providers, "request_json", call)
    result = service.run(prepared["task"]["id"], "operator")
    assert result["status"] == "COMPLETED" and result["result"]["images"][0]["width"] == 64


@pytest.mark.parametrize("failure", ["revoke", "expire", "wrong-model", "malformed", "checkpoint-change"])
def test_no_output_released_after_inflight_change_or_bad_response(failure, monkeypatch):
    _, prepared, _ = prepare()
    approve(prepared["approval"])
    task_id = prepared["task"]["id"]
    normal = fake_vision("openai-compatible")
    def call(path, body=None, **kwargs):
        if body:
            if failure == "revoke":
                service.revoke(task_id, "data-owner")
            elif failure == "expire":
                job = service.read(task_id)
                job["expires_at"] = 0
                service.save(job)
            elif failure == "wrong-model":
                return {"model": "wrong"}
            elif failure == "malformed":
                return {"model": "fixture:reviewed", "choices": []}
            else:
                profile = store.require("provider-profile", prepared["task"]["provider"])
                profile["model"] = "tampered"
                store.put("provider-profile", profile["id"], profile)
        return normal(path, body, **kwargs)
    monkeypatch.setattr(providers, "request_json", call)
    with pytest.raises(store.Denied):
        service.run(task_id, "operator")
    assert "ciphertext" not in store.require("media-job", task_id)
    assert not service.BUSY.locked()


def test_image_metadata_removed_and_real_decoding():
    from PIL.PngImagePlugin import PngInfo
    metadata = PngInfo()
    metadata.add_text("Comment", "private-description")
    result = images.sanitize(png(pnginfo=metadata))
    decoded = base64.b64decode(result["data"])
    assert b"private-description" not in decoded
    with Image.open(io.BytesIO(decoded)) as image:
        assert image.size == (64, 64) and image.getpixel((0, 0)) == (0, 0, 128)


@pytest.mark.parametrize("encoded", ["https://evil.invalid/img.png", "file:///C:/secret.png", "C:\\image.png", "@@@", base64.b64encode(b"not-an-image").decode()])
def test_image_rejects_urls_files_and_fake_bytes(encoded):
    with pytest.raises(ValueError):
        images.sanitize(encoded)


def test_image_pixel_limit_and_animated_input():
    with pytest.raises(ValueError):
        images.sanitize(png(width=2049, height=2049))
    raw = io.BytesIO()
    first, second = Image.new("RGB", (10, 10), "red"), Image.new("RGB", (10, 10), "blue")
    first.save(raw, format="PNG", save_all=True, append_images=[second])
    with pytest.raises(ValueError):
        images.sanitize(base64.b64encode(raw.getvalue()).decode())


def test_task_schema_and_provider_capability_fail_closed():
    for change in [{"operation": "generate", "images": [png()]}, {"operation": "edit", "images": []},
                   {"operation": "understand", "images": []}, {"operation": "generate", "steps": 999},
                   {"operation": "generate", "width": 65}, {"operation": "generate", "script_name": "arbitrary"}]:
        with pytest.raises(ValueError):
            service.MediaRequest.model_validate({"capsule_id": "x", "prompt": "draw a square", **change})
    with pytest.raises(store.Denied):
        inference.require_capability({"protocol": "openai-compatible", "vision": False}, "understand")
    with pytest.raises(store.Denied):
        inference.require_capability({"protocol": "ollama", "vision": True}, "generate")


def test_media_review_and_preview_require_auth_and_own_compartment(monkeypatch):
    _, prepared, _ = prepare()
    task_id = prepared["task"]["id"]
    with TestClient(app) as client:
        response = client.get(f"/api/media/tasks/{task_id}/images/input/0")
        assert response.status_code == 200 and response.headers["content-type"] == "image/png"
        assert response.headers["cache-control"] == "no-store"
        assert client.get(f"/api/media/tasks/{task_id}", headers={"X-Aegis-Actor": "finance-operator"}).status_code == 403
        assert client.post("/api/media/tasks", json={"prompt": "x", "images": ["private-image"]}).status_code == 422
        assert "private-image" not in client.post("/api/media/tasks", json={"images": ["private-image"]}).text
        monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
        assert client.get(f"/api/media/tasks/{task_id}").status_code == 401


def test_prepare_does_not_connect_until_bound_approval(monkeypatch):
    call = Mock(side_effect=AssertionError("No provider access before approval"))
    monkeypatch.setattr(providers, "request_json", call)
    _, prepared, request = prepare()
    review = service.view(prepared["task"]["id"], "security-officer")
    assert review["request"]["prompt"] == request["prompt"]
    assert review["request"]["images"][0]["sha256"] == prepared["task"]["input_images"][0]["sha256"]
    assert not call.called


def test_separate_media_tasks_cannot_overwrite_receipt_ids():
    _, prepared, request = prepare()
    service.prepare(request, "operator")
    assert store.verify_chain()["is_valid"] is True
    rows = query_all("SELECT id FROM control_receipts")
    assert all(row["id"].startswith("GREC-") for row in rows)


def test_revocation_during_listing_stops_image_disclosure(monkeypatch):
    _, prepared, _ = prepare()
    approve(prepared["approval"])
    task_id = prepared["task"]["id"]
    def call(path, body=None, **kwargs):
        assert body is None, "Image bytes must not be sent after revocation"
        service.revoke(task_id, "operator")
        return {"data": [{"id": "fixture:reviewed"}]}
    monkeypatch.setattr(providers, "request_json", call)
    with pytest.raises(store.Denied):
        service.run(task_id, "operator")
    assert not service.BUSY.locked()


def test_audit_chain_failure_withholds_existing_media():
    _, prepared, _ = prepare()
    from aegis.storage.database import execute_write
    execute_write("UPDATE control_receipts SET hash=? WHERE sequence=1", ("f" * 64,))
    with pytest.raises(store.Denied, match="audit chain"):
        service.view(prepared["task"]["id"], "operator")


def test_failed_completion_receipt_cannot_leave_readable_output(monkeypatch):
    _, prepared, _ = prepare()
    approve(prepared["approval"])
    monkeypatch.setattr(providers, "request_json", fake_vision("openai-compatible"))
    original = store.receipt
    def receipt(action, *args, **kwargs):
        if action == "MEDIA_COMPLETED":
            raise ValueError("simulated audit write failure")
        return original(action, *args, **kwargs)
    monkeypatch.setattr(store, "receipt", receipt)
    with pytest.raises(store.Denied):
        service.run(prepared["task"]["id"], "operator")
    assert "ciphertext" not in service.read(prepared["task"]["id"])


def test_media_quota_and_concurrent_execution_fail_closed(monkeypatch):
    _, prepared, request = prepare()
    for _ in range(3):
        service.prepare(request, "operator")
    with pytest.raises(store.Denied, match="Close existing"):
        service.prepare(request, "operator")
    approve(prepared["approval"])
    call = Mock()
    monkeypatch.setattr(providers, "request_json", call)
    service.BUSY.acquire()
    try:
        with pytest.raises(store.Denied, match="One media"):
            service.run(prepared["task"]["id"], "operator")
    finally:
        service.BUSY.release()
    assert not call.called


def test_transparency_is_composited_before_model_disclosure():
    buffer = io.BytesIO()
    Image.new("RGBA", (16, 16), (255, 0, 0, 0)).save(buffer, format="PNG")
    result = images.sanitize(base64.b64encode(buffer.getvalue()).decode())
    with Image.open(io.BytesIO(base64.b64decode(result["data"]))) as decoded:
        assert decoded.getpixel((0, 0)) == (255, 255, 255)
