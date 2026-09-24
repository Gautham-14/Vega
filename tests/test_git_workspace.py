import os
from pathlib import Path
import shutil

import pytest

from aegis import config
from aegis.coding.git_workspace import Workspace, WorkspaceError
from aegis.coding import service
from aegis.control import store, capsules, policy
from aegis.storage.database import init_db

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="Git is not installed")


def test_isolated_worktree_checkpoint_revert_and_cleanup(monkeypatch, tmp_path):
    # Inherited attacker-controlled Git configuration must not run in the new repo.
    poison = tmp_path / "gitconfig"
    poison.write_text('[core]\n hooksPath = /untrusted/hooks\n[commit]\n gpgsign = true\n', encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(poison))
    original = {"src/main.py": "value = 1\n", ".gitignore": "*.py\n", ".gitattributes": "*.py filter=evil\n"}
    with Workspace(original) as workspace:
        root = workspace._root
        baseline = workspace.checkpoint()
        result = workspace.stage({**original, "src/main.py": "value = 2\n", "new.txt": ""})
        assert "+value = 2" in result["diff"]
        assert "new file mode" in result["diff"]
        assert "src/main.py" in workspace._run(workspace._tree, "ls-files")
        updated = workspace.checkpoint()
        assert baseline["checkpoint"] != updated["checkpoint"]
        restored = workspace.revert(baseline["checkpoint"])
        assert restored["diff"] == ""
        assert (workspace._tree / "src/main.py").read_text() == "value = 1\n"
        assert not (workspace._tree / "new.txt").exists()
        with pytest.raises(WorkspaceError):
            workspace.revert("HEAD~2")
    assert not root.exists()
    assert not list(config.WORKSPACES_DIR.iterdir())


def test_reviewed_apply_records_and_cleans_git_checkpoint(monkeypatch):
    monkeypatch.setenv("AEGIS_GIT_WORKTREES", "1")
    init_db()
    store.init_control()
    repo = service.add_repository("Port fixture", service.DEMO_FILES, "Engineering", "INTERNAL", "data-owner")
    stack = service.register_capsule("reference", "operator")
    for actor in ("model-custodian", "security-officer"):
        policy.decide(stack["approval"]["id"], actor, "APPROVE")
    capsules.approve(stack["capsule"]["id"], stack["approval"]["id"], "model-custodian")
    lease = service.issue_lease(repo["id"], stack["capsule"]["id"], "operator", "EXECUTE", 15, False, "data-owner")
    task = service.run(lease["id"], "Fix valid_port", lease["purpose"], "operator")
    applied = service.apply(task["id"], task["diff_hash"], "operator")
    assert applied["git_checkpoint"]["worktree"] == "DESTROYED"
    assert applied["git_checkpoint"]["content_hash"] == applied["applied_snapshot_hash"]
    assert not list(config.WORKSPACES_DIR.iterdir())
