"""No implicit demos, revocation replay or unauthorized automatic model work."""
from unittest.mock import Mock
from types import SimpleNamespace
import sys
import pytest
from aegis import cli
from aegis.control import demo, leases, store
from aegis.control.self_test import setup_fixture
from aegis.control.runtime import GovernedRunner
from aegis.storage.database import init_db
from aegis.security import supply_chain


def test_cli_model_failure_does_not_run_demo_or_change_storage(monkeypatch):
    monkeypatch.setitem(sys.modules, "prompt_toolkit", None)
    client = Mock(url=cli.BASE_URL, session=SimpleNamespace(value={}))
    client.run.side_effect = cli.CLIError("No valid selected lease")
    inputs = iter(["Review actual equipment", "/exit"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))
    demo_runner = Mock(side_effect=AssertionError("No fallback allowed"))
    monkeypatch.setattr(cli, "run_sovereign_pipeline_ui", demo_runner)
    assert cli.shell(client, cli.build_parser(), plain=True) == 0
    client.run.assert_called_once_with("Review actual equipment")
    demo_runner.assert_not_called()


def test_explicit_demo_uses_server_security_gates():
    client = Mock()
    cli.execute(cli.build_parser().parse_args(["demo"]), client)
    client.call.assert_called_once_with("/control/demo/run", "POST", {"scenario": "success"})
    with pytest.raises(cli.CLIError, match="fixed fixture"):
        cli.run_sovereign_pipeline_ui("Custom request", client=client)
    assert client.call.call_count == 1


@pytest.mark.parametrize("operation,arguments,code", [
    (supply_chain.verify_slsa_provenance, ("missing-artifact", "claimed-builder"), "SLSA_VERIFICATION_UNAVAILABLE"),
    (supply_chain.verify_cosign_signature, ("missing-artifact", "missing-key"), "COSIGN_VERIFICATION_UNAVAILABLE"),
    (supply_chain.generate_tuf_metadata, ({"artifact": {"sha256": "a" * 64, "size": 1}},), "TUF_SIGNING_UNAVAILABLE"),
])
def test_unconfigured_supply_chain_interfaces_cannot_report_success(operation, arguments, code):
    init_db()
    with pytest.raises(store.Denied) as error:
        operation(*arguments)
    assert error.value.code == code


def test_control_lease_revocation_cannot_be_undone_by_replaying_signed_lease(monkeypatch):
    init_db()
    store.init_control()
    monkeypatch.setattr("aegis.hardware.detector.detect_hardware", lambda: {"available_ram_mb": 4096, "gpu": {"vram_mb": 0}})
    ready = setup_fixture()
    old = store.require("lease", ready["lease_id"])
    leases.revoke(old["id"], "data-owner")
    store.put("lease", old["id"], old)
    result = GovernedRunner().run(demo.task_request(ready), "operator")
    assert result["reason"] == "REVOKED_PURPOSE_LEASE" and result["key_release_state"] == "NOT_RELEASED"
