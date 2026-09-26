"""The offline installer must reject changed or unlisted local inputs."""

import hashlib
import importlib.util
from pathlib import Path
import runpy

import pytest


verify_wheelhouse = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "setup_offline.py"))["verify_wheelhouse"]


def test_wheelhouse_manifest_requires_exact_matching_hashes(tmp_path):
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    item = wheels / "example-1.0-py3-none-any.whl"
    item.write_bytes(b"reviewed wheel bytes")
    manifest = tmp_path / "wheelhouse.sha256"
    manifest.write_text(hashlib.sha256(item.read_bytes()).hexdigest() + "  " + item.name + "\n")
    assert verify_wheelhouse(wheels, manifest) == [item]

    item.write_bytes(b"changed wheel bytes")
    with pytest.raises(ValueError, match="mismatch"):
        verify_wheelhouse(wheels, manifest)
    item.write_bytes(b"reviewed wheel bytes")

    (wheels / "unlisted-1.0-py3-none-any.whl").write_bytes(b"extra")
    with pytest.raises(ValueError, match="every wheel"):
        verify_wheelhouse(wheels, manifest)


def test_local_session_stops_its_server_when_cli_exits(monkeypatch):
    source = Path(__file__).resolve().parents[1] / "scripts" / "start_offline.py"
    spec = importlib.util.spec_from_file_location("aegis_start_offline_test", source)
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)

    class Server:
        stopped = False

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def wait(self, timeout=None):
            return 0

    server = Server()
    monkeypatch.setattr(launcher, "require_environment", lambda: None)
    monkeypatch.setattr(launcher, "require_free_port", lambda: None)
    monkeypatch.setattr(launcher, "wait_for_server", lambda process: None)
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *args, **kwargs: server)
    monkeypatch.setattr(launcher.subprocess, "call", lambda *args, **kwargs: 7)
    assert launcher.main([]) == 7
    assert server.stopped
