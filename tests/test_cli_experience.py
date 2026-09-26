"""Operator UX must preserve authorization, explicit submission and clean output."""
import http.client
import io
import json
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import aegis_cli as cli


def test_help_is_available_without_opening_session_or_server(monkeypatch, capsys):
    monkeypatch.setattr(cli, "Client", Mock(side_effect=AssertionError("No session access for help")))
    assert cli.main(["help", "security"]) == 0
    assert "lockdown enable" in capsys.readouterr().out
    assert cli.main(["--json", "help", "lease"]) == 0
    assert "--capsule" in json.loads(capsys.readouterr().out)["reference"]


def test_json_errors_and_redaction(monkeypatch, capsys):
    assert cli.main(["--json", "help", "unknown-command"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "FAILED"
    cli.print_result({"access_token": "secret-token", "nested": {"password": "secret-password"}}, json_output=True)
    output = capsys.readouterr().out
    assert "secret-token" not in output and "secret-password" not in output
    assert len(output.splitlines()) == 1
    monkeypatch.setattr(cli, "Client", Mock(side_effect=AssertionError("No session for invalid shell mode")))
    assert cli.main(["--json", "shell"]) == 1


def doctor_client(signed_in=True):
    answers = {
        "/auth/status": {"configured": True}, "/coding/status": {"enabled": True},
        "/auth/me": {"id": "operator", "role": "Operator"},
        "/security/lockdown": {"enabled": False, "generation": 0},
        "/control/receipts/verify": {"is_valid": True, "status": "VALID"},
        "/media/capabilities": {"image_decoder": "synthetic-version"},
    }
    client = SimpleNamespace(url=cli.BASE_URL, timeout=120,
                             session=SimpleNamespace(value={"access_token": "synthetic"} if signed_in else {}))
    client.call = Mock(side_effect=lambda endpoint, **kwargs: answers[endpoint])
    return client, answers


def test_doctor_only_uses_read_endpoints_and_restores_timeout():
    client, _ = doctor_client()
    report = cli.execute(cli.build_parser().parse_args(["doctor"]), client)
    assert report["status"] == "PASS" and report["model_calls"] == 0
    assert client.timeout == 120
    for call in client.call.call_args_list:
        assert len(call.args) == 1  # implicit GET, no data or mutation
        assert call.args[0] not in {"/providers", "/coding/capabilities"}
    assert "production" in report["scope"]


def test_doctor_reports_partial_failure_and_missing_images():
    client, answers = doctor_client()
    answers["/media/capabilities"] = {"image_decoder": None}
    answers["/security/lockdown"] = {"enabled": True, "generation": 1}
    report = cli.execute(cli.build_parser().parse_args(["doctor"]), client)
    assert cli.failed_result(report)
    checks = {item["check"]: item for item in report["checks"]}
    assert checks["lockdown"]["status"] == "BLOCKED"
    assert checks["image_decoder"]["status"] == "ATTENTION"
    client.call.side_effect = cli.CLIError("Server offline")
    report = cli.execute(cli.build_parser().parse_args(["doctor"]), client)
    assert all(item["status"] == "UNAVAILABLE" for item in report["checks"])
    assert client.timeout == 120


def test_signed_out_doctor_never_attempts_authentication():
    client, _ = doctor_client(signed_in=False)
    report = cli.execute(cli.build_parser().parse_args(["doctor"]), client)
    assert report["status"] == "NEEDS_ATTENTION"
    assert [call.args[0] for call in client.call.call_args_list] == ["/auth/status", "/coding/status"]
    assert all(call.kwargs["public"] for call in client.call.call_args_list)


def test_context_reads_authorization_without_submitting_work():
    client = Mock(session=SimpleNamespace(value={"selected_lease": {"id": "LEASE-1", "mode": "EXECUTE"}}))
    client.call.side_effect = [{"id": "operator", "role": "Operator"}, {"enabled": False, "generation": 2}]
    client.select_lease.return_value = {"id": "LEASE-1", "mode": "PLAN", "purpose": "code-planning",
                                       "lockdown_generation": 2, "allow_export": False}
    result = cli.execute(cli.build_parser().parse_args(["context"]), client)
    assert result["lease"]["mode"] == "PLAN"
    assert result["lockdown"]["generation"] == 2
    client.select_lease.assert_called_once_with("LEASE-1", save=False)
    client.run.assert_not_called()


@pytest.mark.parametrize("incident", [{"enabled": True, "generation": 1}, {"enabled": False, "generation": 2}, {}])
def test_cli_will_not_select_or_run_a_locked_or_stale_lease(tmp_path, incident):
    client = cli.Client(session=cli.SessionStore(cli.BASE_URL, tmp_path / "session"))
    client.call = Mock(side_effect=[{"id": "operator"}, {
        "id": "LEASE-1", "user": "operator", "purpose": "code-planning", "mode": "PLAN",
        "expires_at": time.time() + 100, "lockdown_generation": 0}, incident])
    with pytest.raises(cli.CLIError, match="locked|incident-control"):
        client.run("Synthetic prompt", "LEASE-1")
    assert len(client.call.call_args_list) == 3
    assert not client.session.path.exists()


def lines(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr("builtins.input", lambda prompt: next(iterator))


def test_multiline_requires_send_and_preserves_lines(monkeypatch):
    lines(monkeypatch, ["First line", "", "  indented code", "/preview", "/send"])
    client = Mock()
    cli.compose(client)
    client.run.assert_called_once_with("First line\n\n  indented code")


@pytest.mark.parametrize("ending", ["/cancel", EOFError, KeyboardInterrupt])
def test_multiline_cancel_never_calls_model(monkeypatch, ending):
    client = Mock()
    if isinstance(ending, str):
        lines(monkeypatch, ["Never sent", ending])
    else:
        monkeypatch.setattr("builtins.input", Mock(side_effect=ending))
    assert cli.compose(client)["status"] == "CANCELLED"
    client.run.assert_not_called()


def test_multiline_enforces_budget_and_clear(monkeypatch, capsys):
    lines(monkeypatch, ["/send", "x" * 8001, "discard", "/clear", "keep", "/send"])
    client = Mock()
    cli.compose(client)
    client.run.assert_called_once_with("keep")
    output = capsys.readouterr().out
    assert "Prompt is empty" in output and "was not added" in output


def test_shell_help_and_compose_preserve_dispatch_and_do_not_save_history(monkeypatch, capsys):
    client = Mock(url=cli.BASE_URL, session=SimpleNamespace(value={}))
    client.run.return_value = {"status": "COMPLETED"}
    lines(monkeypatch, ["/help coding", "/compose", "hello", "/send", "/exit"])
    assert cli.shell(client, cli.build_parser(), plain=True) == 0
    client.run.assert_called_once_with("hello")
    client.call.assert_not_called()
    assert "Data Owner" in capsys.readouterr().out


def test_rich_output_neutralizes_terminal_and_bidi_controls(monkeypatch):
    if not cli.has_rich:
        pytest.skip("Rich is optional")
    from rich.console import Console
    output = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, force_terminal=False, width=120))
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    cli.print_result({"answer": "normal\x1b[2J\u202e[link=https://external.invalid]click[/link]"})
    text = output.getvalue()
    assert "\x1b" not in text and "\u202e" not in text
    assert "\\u001b" in text and "[link=" in text


def test_incomplete_http_response_is_a_clean_cli_error(tmp_path):
    opener = Mock()
    opener.open.side_effect = http.client.IncompleteRead(b"partial", 100)
    client = cli.Client(session=cli.SessionStore(cli.BASE_URL, tmp_path / "session"), opener=opener)
    with pytest.raises(cli.CLIError, match="Cannot reach"):
        client.call("/auth/status", public=True)
    with pytest.raises(cli.CLIError, match="may still complete"):
        client.call("/auth/login", "POST", {}, public=True)


def test_doctor_contract_with_actual_api(monkeypatch):
    from starlette.testclient import TestClient
    from aegis.api.server import app
    from aegis.security.auth import provision
    monkeypatch.delenv("AEGIS_ENABLE_DEMO_ENDPOINTS", raising=False)
    with TestClient(app) as api:
        provision("operator", "synthetic-test-password")
        token = api.post("/api/auth/login", json={"username": "operator", "password": "synthetic-test-password"}).json()["access_token"]
        requests = []
        def call(endpoint, *, public=False):
            requests.append(endpoint)
            response = api.get("/api" + endpoint, headers={} if public else {"Authorization": "Bearer " + token})
            assert response.status_code == 200, response.text
            return response.json()
        client = SimpleNamespace(url=cli.BASE_URL, timeout=120, call=call,
                                 session=SimpleNamespace(value={"access_token": token}))
        report = cli.execute(cli.build_parser().parse_args(["doctor"]), client)
        assert len(requests) == 6
        assert all(c["status"] == "PASS" for c in report["checks"] if c["check"] != "image_decoder")
