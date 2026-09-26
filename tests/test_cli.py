import io
import json
from pathlib import Path
import subprocess
import time
from unittest.mock import Mock

import pytest
import aegis_cli as cli


@pytest.mark.parametrize("url", ["https://example.com/api", "http://localhost:8000/api", "http://127.0.0.1:0/api",
    "http://127.0.0.1:8000/api?x=1", "http://user:pass@127.0.0.1/api", "http://127.0.0.1/elsewhere"])
def test_client_refuses_untrusted_origins(url):
    with pytest.raises(cli.CLIError):
        cli.canonical_url(url)


def test_transport_includes_api_prefix_and_never_sends_identity_header_with_token(tmp_path):
    session = cli.SessionStore(cli.BASE_URL, tmp_path / "session")
    session.value = {"access_token": "x" * 32, "expires_at": time.time() + 100, "demo_persona": "security-officer"}
    opener = Mock()
    opener.open.return_value = io.BytesIO(b'{"ok":true}')
    client = cli.Client(session=session, opener=opener)
    assert client.call("/coding/tasks", "POST", {"prompt": "hello"})["ok"]
    req = opener.open.call_args.args[0]
    assert req.full_url == "http://127.0.0.1:8000/api/coding/tasks"
    assert req.get_header("Authorization") == "Bearer " + "x" * 32
    assert req.get_header("X-aegis-actor") is None
    assert opener.open.call_args.kwargs["timeout"] == 120


def test_sessions_are_origin_bound_and_persist_selected_lease(tmp_path):
    folder = tmp_path / "private"
    session = cli.SessionStore(cli.BASE_URL, folder)
    session.value = {"access_token": "x" * 32, "expires_at": time.time() + 100, "actor": "operator"}
    session.save()
    assert cli.SessionStore(cli.BASE_URL, folder).value["actor"] == "operator"
    assert cli.SessionStore("http://127.0.0.1:8765/api", folder).value == {}
    session.clear()
    assert not session.path.exists()


def test_login_saves_session_but_never_returns_token(tmp_path, monkeypatch):
    session = cli.SessionStore(cli.BASE_URL, tmp_path / "private")
    client = cli.Client(session=session)
    monkeypatch.setattr(cli, "getpass", lambda prompt: "not-real-password")
    client.call = Mock(return_value={"access_token": "x" * 32, "actor": "operator", "role": "Operator", "expires_at": time.time() + 100})
    result = client.login("operator")
    assert "access_token" not in result and "not-real-password" not in session.path.read_text()
    assert session.value["actor"] == "operator"
    assert client.call.call_args.args == ("/auth/login", "POST", {"username": "operator", "password": "not-real-password"})


def test_command_payloads_match_backend_contracts():
    parser = cli.build_parser()
    client = Mock()
    cli.execute(parser.parse_args(["lease", "--repo", "REPO-1", "--capsule", "capsule-1"]), client)
    assert client.call.call_args.args == ("/coding/leases", "POST", {"repository_id": "REPO-1", "capsule_id": "capsule-1",
        "user": "operator", "mode": "PLAN", "minutes": 15, "allow_export": False})
    cli.execute(parser.parse_args(["activate", "capsule-1", "APPROVAL-1"]), client)
    assert client.call.call_args.args == ("/control/capsules/capsule-1/approve", "POST", {"approval_id": "APPROVAL-1"})
    cli.execute(parser.parse_args(["receipts"]), client)
    assert client.call.call_args.args == ("/control/receipts",)
    for result in ({"status": "BLOCKED"}, {"all_passed": False}, {"is_valid": False}):
        assert cli.failed_result(result)


def test_import_reports_skips_and_rejects_secrets_large_and_binary_files(tmp_path):
    (tmp_path / "main.py").write_bytes(b"print('hello')\n")
    (tmp_path / ".env").write_text("PRIVATE=never-import\n")
    (tmp_path / "node_modules").mkdir()
    files, skipped = cli.import_files([str(tmp_path)])
    assert files == {"main.py": "print('hello')\n"}
    assert ".env" in skipped and "node_modules/" in skipped
    (tmp_path / "main.py").write_text('password = "private-value-12345"')
    with pytest.raises(cli.CLIError, match="Secret-like"):
        cli.import_files([str(tmp_path / "main.py")])
    (tmp_path / "main.py").write_bytes(b"\x00")
    with pytest.raises(cli.CLIError, match="Binary"):
        cli.import_files([str(tmp_path / "main.py")])
    (tmp_path / "main.py").write_bytes(b"x" * 128001)
    with pytest.raises(cli.CLIError, match="128 KB"):
        cli.import_files([str(tmp_path / "main.py")])


def test_export_never_overwrites_existing_file(tmp_path):
    destination = tmp_path / "approved.patch"
    client = Mock()
    client.call.return_value = {"patch": "sample patch", "classification": "INTERNAL"}
    result = cli.export_patch(client, "TASK-1", "APPROVAL-1", destination)
    assert result["bytes"] == 12 and destination.read_text() == "sample patch"
    with pytest.raises(cli.CLIError, match="already exists"):
        cli.export_patch(client, "TASK-1", "APPROVAL-1", destination)
    assert client.call.call_count == 1


def test_run_requires_current_owned_live_lease(tmp_path):
    session = cli.SessionStore(cli.BASE_URL, tmp_path / "private")
    session.value = {"actor": "operator", "selected_lease": {"id": "LEASE-1", "actor": "operator"}}
    client = cli.Client(session=session)
    client.call = Mock(side_effect=[{"id": "operator"}, {"id": "LEASE-1", "user": "operator", "mode": "PLAN",
        "purpose": "code-planning", "expires_at": time.time() + 100},
        {"enabled": False, "generation": 0}, {"status": "COMPLETED"}])
    assert client.run("Plan change")["status"] == "COMPLETED"
    assert client.call.call_args.args == ("/coding/tasks", "POST", {"lease_id": "LEASE-1", "prompt": "Plan change", "purpose": "code-planning"})
    client.call = Mock(side_effect=[{"id": "operator"}, {"user": "finance-operator"}])
    with pytest.raises(cli.CLIError, match="different account"):
        client.run("Plan change")
