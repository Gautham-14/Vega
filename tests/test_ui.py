"""The current operator interface is the authenticated CLI."""
from aegis.cli_support import GUIDES
from aegis import cli


def test_quickstart_covers_roles_approvals_and_returned_ids():
    guide = "\n".join(GUIDES["quickstart"])
    assert "--like operator" in guide
    assert "Data Owner" in guide and "Model Custodian and Security Officer" in guide
    assert "--repo <repository-id>" in guide
    assert "activate <capsule-id> <approval-id>" in guide
    assert "INTERNAL" in guide and "approved release" in guide
    cli.build_parser().parse_args(["lease", "--repo", "REPO-fixture", "--capsule", "CAP-fixture",
                                  "--recipient", "operator", "--mode", "PLAN"])


def test_role_and_lease_help_remain_available_without_a_server(monkeypatch, capsys):
    def no_client(*args, **kwargs):
        raise AssertionError("Guidance must not open session storage or contact the API")
    monkeypatch.setattr(cli, "Client", no_client)
    assert cli.main(["help", "quickstart"]) == 0
    assert "repository-id" in capsys.readouterr().out
    assert cli.main(["help", "lease"]) == 0
    assert "--mode" in capsys.readouterr().out
