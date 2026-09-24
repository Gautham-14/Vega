"""Verify the execution boundary without running untrusted code on the host."""
import io
import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from aegis.coding import sandbox
from aegis.control import store


class Input(io.BytesIO):
    def close(self):
        self.payload = self.getvalue()
        super().close()


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_fixed_container_boundary_and_required_cleanup(cleanup_fails):
    process = Mock()
    process.stdin = Input()
    process.stdout = io.BytesIO(json.dumps({"exit_code": 0, "output": "1 passed"}).encode())
    process.returncode = 0
    process.poll.return_value = 0
    settings = {"enabled": True, "image": "sha256:" + "a" * 64}
    cleanup = subprocess.CompletedProcess([], 1 if cleanup_fails else 0, b"", b"engine unavailable")
    with patch.object(sandbox, "configuration", return_value=settings), \
         patch.object(sandbox.shutil, "which", return_value="/usr/bin/docker"), \
         patch.object(sandbox.subprocess, "Popen", return_value=process) as start, \
         patch.object(sandbox.subprocess, "run", return_value=cleanup) as remove, \
         patch.object(store, "event"):
        if cleanup_fails:
            with pytest.raises(store.Denied) as failure:
                sandbox.execute({"test_example.py": "def test_ok(): assert True\n"}, "test")
            assert failure.value.code == "SANDBOX_CLEANUP_FAILED"
        else:
            result = sandbox.execute({"test_example.py": "def test_ok(): assert True\n"}, "test")
            assert result["status"] == "PASS"
        args = start.call_args.args[0]
        for flag in ("--runtime=runsc", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--user=65534:65534"):
            assert flag in args
        assert args[:3] == ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
        assert not any(arg == "-v" or arg.startswith("--mount") for arg in args)
        assert not start.call_args.kwargs.get("shell", False)
        payload = json.loads(process.stdin.payload)
        assert payload["command"] == sandbox.COMMANDS["test"]
        assert "rm" in remove.call_args.args[0] and "--force" in remove.call_args.args[0]
        process.wait.assert_any_call(timeout=55)
