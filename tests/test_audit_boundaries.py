"""Regression tests for startup credentials, bounded bodies and media CLI exports."""
import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient
import aegis_cli as cli
from aegis.api.limits import RequestBodyLimit
from aegis.api.server import app
from aegis.control import store


def test_environment_cannot_create_a_default_account(monkeypatch):
    monkeypatch.setenv("AEGIS_AUTO_PROVISION", "1")
    with TestClient(app) as client:
        assert client.get("/api/auth/status").json()["configured"] is False


def test_shell_never_attempts_silent_login(monkeypatch):
    client = Mock(url=cli.BASE_URL, session=SimpleNamespace(value={}))
    monkeypatch.setattr(cli, "has_rich", False)
    monkeypatch.setattr("builtins.input", lambda prompt: "/exit")
    assert cli.shell(client, cli.build_parser()) == 0
    client.login.assert_not_called()


@pytest.mark.parametrize("headers,chunks,status", [
    ([(b"content-length", b"4000001")], [], 413),
    ([(b"content-length", b"-1")], [], 400),
    ([(b"content-length", b"1"), (b"content-length", b"2")], [], 400),
    ([], [b"x" * 2_000_000, b"y" * 2_000_001], 413),
])
def test_body_limits_cover_chunked_and_declared_sizes(headers, chunks, status):
    messages = [{"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1} for i, chunk in enumerate(chunks)]
    responses = []
    async def receive():
        return messages.pop(0)
    async def send(message):
        responses.append(message)
    async def downstream(*args):
        pytest.fail("Oversized body reached the JSON parser")
    asyncio.run(RequestBodyLimit(downstream)({"type": "http", "method": "POST", "path": "/api/coding/tasks", "headers": headers}, receive, send))
    assert responses[0]["status"] == status


def test_media_cli_attaches_only_explicit_files(tmp_path):
    metadata = tmp_path / "request.json"
    metadata.write_text(json.dumps({"capsule_id": "capsule-x", "operation": "understand", "prompt": "Describe it"}))
    image = tmp_path / "image.png"
    image.write_bytes(b"image bytes validated by the server")
    client = Mock()
    args = cli.build_parser().parse_args(["media-prepare", str(metadata), "--image", str(image)])
    cli.execute(args, client)
    endpoint, method, body = client.call.call_args.args
    assert endpoint == "/media/tasks" and method == "POST"
    assert base64.b64decode(body["images"][0]) == image.read_bytes()


def test_media_cli_review_displays_preview_links_without_base64():
    client = Mock(url=cli.BASE_URL)
    client.call.return_value = {"request": {"images": [{"data": "private-pixel-bytes", "sha256": "a" * 64}]}}
    result = cli.execute(cli.build_parser().parse_args(["media-review", "MEDIA-test"]), client)
    assert "private-pixel-bytes" not in json.dumps(result)
    assert result["request"]["images"][0]["preview_url"].endswith("/media/tasks/MEDIA-test/images/input/0")


def test_media_export_hash_no_overwrite_and_permissions(tmp_path):
    client = Mock()
    result = {"answer": "A geometric shape.", "images": []}
    client.call.return_value = {"result": result, "result_hash": store.digest(result)}
    path = tmp_path / "answer.txt"
    exported = cli.export_media(client, "MEDIA-test", "APR-test", str(path))
    assert path.read_text() == result["answer"] and exported["result_hash"] == store.digest(result)
    with pytest.raises(cli.CLIError, match="new export"):
        cli.export_media(client, "MEDIA-test", "APR-test", str(path))
    client.call.return_value["result_hash"] = "f" * 64
    missing = tmp_path / "bad.txt"
    with pytest.raises(cli.CLIError, match="hash"):
        cli.export_media(client, "MEDIA-test", "APR-test", str(missing))
    assert not missing.exists()


@pytest.mark.parametrize("field", ["id", "sequence", "timestamp", "previous_receipt_hash", "receipt_hash"])
def test_receipt_metadata_cannot_replace_chain_fields(field):
    with pytest.raises(ValueError, match="chain identity"):
        store.receipt("FIXTURE", **{field: "bad"})


def test_capacity_command_does_not_read_or_modify_session(monkeypatch, capsys):
    def client(*args, **kwargs):
        pytest.fail("Pure capacity arithmetic must not open account/session storage")
    monkeypatch.setattr(cli, "Client", client)
    assert cli.main(["capacity", "1000", "--bits", "4"]) == 0
    assert json.loads(capsys.readouterr().out)["raw_weights_gb"] == 500
