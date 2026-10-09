"""Real model-free launcher startup using disposable server/client state."""
from pathlib import Path
import socket
import os
import subprocess
import sys
import pytest
from scripts.runtime_support import offline_environment
from aegis.security import private_files


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows process token and ACLs")
def test_windows_private_permissions_use_native_token_without_process_launch(tmp_path, monkeypatch):
    target = tmp_path / "native-private.txt"
    target.write_text("synthetic fixture", encoding="utf-8")
    def forbidden(*args, **kwargs):
        raise AssertionError("Permission checks must not spawn account lookup processes")
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert private_files.windows_user_sid().startswith("S-1-")
    private_files.restrict_permissions(target)


def test_dedicated_launcher_starts_api_and_cli_then_exits_without_models(tmp_path):
    if Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
        pytest.skip("Integration requires the dedicated project environment")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = offline_environment()
    environment["AEGIS_DATA_DIR"] = str(tmp_path / "server")
    environment["AEGIS_CLIENT_DIR"] = str(tmp_path / "client")
    result = subprocess.run([sys.executable, str(ROOT / "aegis.py"), "start", "--port", str(port), "--plain"],
                            cwd=ROOT, env=environment, input="/exit\n", text=True,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "Ready. Local API:" in result.stdout
    assert (tmp_path / "server" / "db" / "aegis.db").is_file()
    assert list((tmp_path / "server" / "models").iterdir()) == []
