import sys
import os
import subprocess

import pytest
from starlette.testclient import TestClient

import run_aegis
from aegis.api.server import app


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "example.com", "192.168.1.10"])
def test_launcher_rejects_non_loopback_binding(monkeypatch, host):
    monkeypatch.setattr(sys, "argv", ["run_aegis.py", "--host", host])
    monkeypatch.setattr(run_aegis.uvicorn, "run", lambda *args, **kwargs: pytest.fail("server started"))
    with pytest.raises(SystemExit) as result:
        run_aegis.main()
    assert result.value.code == 2


def test_api_rejects_non_loopback_network_peer():
    with TestClient(app, client=("192.0.2.9", 43000)) as client:
        assert client.get("/api/auth/status").status_code == 403
        assert client.get("/").status_code == 403


def test_hosted_environment_flag_cannot_disable_local_security(tmp_path):
    env = os.environ.copy()
    env["VERCEL"] = "1"
    env.pop("AEGIS_ENABLE_DEMO_ENDPOINTS", None)
    env["AEGIS_DATA_DIR"] = str(tmp_path / "hosted-flag")
    script = """
from starlette.testclient import TestClient
from aegis.api.server import app
with TestClient(app, client=('192.0.2.9', 43000)) as client:
    assert client.get('/api/auth/status').status_code == 403
with TestClient(app) as client:
    assert client.get('/health').json()['deployment_mode'] == 'LOCAL'
    assert client.get('/api/coding/state').status_code == 401
"""
    subprocess.run([sys.executable, "-c", script], env=env, check=True, capture_output=True, text=True)
