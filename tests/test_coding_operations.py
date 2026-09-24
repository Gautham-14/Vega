from unittest.mock import patch

import pytest
from aegis.coding import sandbox, service, tools
from aegis.control import capsules, policy, store
from aegis.storage.database import init_db


@pytest.fixture
def lease():
    init_db()
    store.init_control()
    repo = service.add_repository("Example", service.DEMO_FILES, "Engineering", "INTERNAL", "data-owner")
    stack = service.register_capsule("reference", "operator")
    for actor in ("model-custodian", "security-officer"):
        policy.decide(stack["approval"]["id"], actor, "APPROVE")
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    return service.issue_lease(repo["id"], stack["capsule"]["id"], "operator", "EXECUTE", 15, True, "data-owner")


def test_checkpoint_continuation_and_revert(lease):
    task = service.run(lease["id"], "Fix valid_port", lease["purpose"], "operator")
    denied = service.run(lease["id"], "Continue", lease["purpose"], "operator", task["id"])
    assert denied["reason"] == "SESSION_MISMATCH"
    service.apply(task["id"], task["diff_hash"], "operator")
    followup = service.run(lease["id"], "Review fixed boundary", lease["purpose"], "operator", task["id"])
    assert followup["status"] == "COMPLETED" and followup["diff"] == ""
    assert followup["parent_task_id"] == task["id"]
    reverted = service.revert(task["id"], task["diff_hash"], "operator")
    assert reverted["status"] == "REVERTED" and reverted["diff"] == ""
    with pytest.raises(store.Denied):
        service.export(task["id"], "operator", request=True)
    assert store.verify_chain()["is_valid"]


def test_file_creation_deletion_are_staged_and_paths_checked(lease):
    files = dict(service.DEMO_FILES)
    original = dict(files)
    create = tools.Action(tool="repository.create", arguments={"path": "new.py", "content": "x = 1\n"})
    tools.dispatch(create, files, original, "EXECUTE", ["Engineering"])
    assert "--- /dev/null\n+++ b/new.py" in tools.diff(original, files)
    tools.dispatch(tools.Action(tool="repository.delete", arguments={"path": "validation.py"}), files, original, "EXECUTE", ["Engineering"])
    assert "--- a/validation.py\n+++ /dev/null" in tools.diff(original, files)
    with pytest.raises(store.Denied):
        tools.dispatch(create, files, original, "PLAN", ["Engineering"])
    create.arguments["path"] = "../private.py"
    with pytest.raises(store.Denied):
        tools.dispatch(create, files, original, "EXECUTE", ["Engineering"])


def test_empty_file_structural_changes_need_review():
    assert "new file mode 100644" in tools.diff({}, {"empty.py": ""})
    assert "deleted file mode 100644" in tools.diff({"empty.py": ""}, {})


def test_structural_patch_is_applicable_with_spaces(tmp_path):
    import shutil
    import subprocess
    if not shutil.which("git"):
        pytest.skip("Git is not installed")
    patch_text = tools.diff({"old empty.py": "", "removed.py": "old\n"}, {"new empty.py": "", "added.py": "new\n"})
    (tmp_path / "old empty.py").write_bytes(b"")
    (tmp_path / "removed.py").write_bytes(b"old\n")
    subprocess.run(["git", "apply", "--check", "-"], input=patch_text.encode(), cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "apply", "-"], input=patch_text.encode(), cwd=tmp_path, check=True, capture_output=True)
    assert (tmp_path / "new empty.py").exists() and not (tmp_path / "old empty.py").exists()
    assert (tmp_path / "added.py").read_text() == "new\n" and not (tmp_path / "removed.py").exists()


def test_edits_after_tests_invalidate_pass(lease):
    from aegis.coding import providers
    proposal = tools.Proposal(message="Test then edit", actions=[
        {"tool": "sandbox.test", "arguments": {}},
        {"tool": "repository.edit", "arguments": {"path": "validation.py", "before": "0 <=", "after": "1 <="}}])
    with patch.object(providers, "propose", side_effect=[proposal, tools.Proposal(message="Done")]), \
         patch.object(sandbox, "execute", return_value={"status": "PASS", "exit_code": 0, "runtime": "runsc", "image": "test"}):
        task = service.run(lease["id"], "Fix valid_port", lease["purpose"], "operator")
    assert task["tests"] == "STALE_CODE_CHANGED_AFTER_TEST"
    assert "tested_snapshot_hash" not in task


def test_sandbox_disabled_never_runs_host_code(lease, monkeypatch):
    monkeypatch.delenv("AEGIS_SANDBOX_ENABLED", raising=False)
    with patch.object(sandbox.subprocess, "Popen") as process:
        with pytest.raises(store.Denied) as denied:
            sandbox.execute(service.DEMO_FILES, "test")
        assert denied.value.code == "SANDBOX_UNAVAILABLE"
        process.assert_not_called()


def test_sandbox_requires_linux_digest_and_installed_engine(monkeypatch):
    monkeypatch.setenv("AEGIS_SANDBOX_ENABLED", "1")
    monkeypatch.setenv("AEGIS_SANDBOX_IMAGE", "python:latest")
    with patch.object(sandbox.platform, "system", return_value="Linux"), patch.object(sandbox.shutil, "which", return_value="/usr/bin/docker"):
        assert not sandbox.configuration()["enabled"]
        monkeypatch.setenv("AEGIS_SANDBOX_IMAGE", "sha256:" + "a" * 64)
        assert sandbox.configuration()["enabled"]
        assert sandbox.configuration()["verified_isolation"] is False
    with patch.object(sandbox.platform, "system", return_value="Windows"):
        assert not sandbox.configuration()["enabled"]
