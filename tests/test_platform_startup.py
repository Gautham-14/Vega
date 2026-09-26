"""Portable startup contracts; native OS tests are explicitly marked."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import Mock

import pytest

from scripts import runtime_support as support, start_offline, setup_offline

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("aegis_entry_test", ROOT / "aegis.py")
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


@pytest.mark.parametrize("platform_name,suffix", [("nt", "Scripts/python.exe"), ("posix", "bin/python")])
def test_interpreter_layout(tmp_path, platform_name, suffix):
    assert support.environment_python(tmp_path, platform_name) == tmp_path / ".venv" / suffix


def test_system_interpreter_cannot_impersonate_posix_venv(tmp_path, monkeypatch):
    shared = str(tmp_path / "system")
    monkeypatch.setattr(support.sys, "prefix", shared)
    monkeypatch.setattr(support.sys, "base_prefix", shared)
    with pytest.raises(RuntimeError, match="dedicated"):
        support.require_environment(tmp_path)


def test_core_start_does_not_import_optional_ml_packages(tmp_path, monkeypatch):
    monkeypatch.setattr(support.sys, "prefix", str(tmp_path / ".venv"))
    monkeypatch.setattr(support.sys, "base_prefix", str(tmp_path / "base"))
    imported = []
    monkeypatch.setattr(support.importlib, "import_module", imported.append)
    support.require_environment(tmp_path)
    assert set(imported) == set(support.CORE_MODULES)
    assert not {"PIL", "tokenizers", "sentence_transformers"} & set(imported)


def test_offline_children_drop_ambient_python_and_pip_configuration(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "untrusted-location")
    monkeypatch.setenv("PIP_FIND_LINKS", "https://external.invalid")
    monkeypatch.setenv("AEGIS_DATA_DIR", "explicit-local-storage")
    env = support.offline_environment()
    assert "PYTHONPATH" not in env and "PIP_FIND_LINKS" not in env
    assert env["AEGIS_DATA_DIR"] == "explicit-local-storage"
    assert env["PIP_NO_INDEX"] == env["HF_HUB_OFFLINE"] == "1"


def test_missing_environment_has_actionable_setup_and_never_falls_back(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(entry, "ROOT", tmp_path)
    call = Mock(side_effect=AssertionError("No shared runtime fallback"))
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main([]) == 1
    assert "setup" in capsys.readouterr().err
    call.assert_not_called()


def test_frontend_preserves_paths_and_arguments_without_shell(tmp_path, monkeypatch):
    root = tmp_path / "Aegis with spaces"
    python = support.environment_python(root)
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(entry, "ROOT", root)
    call = Mock(return_value=7)
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main(["cli", "import", "folder with spaces", "--name", "My project"]) == 7
    command = call.call_args.args[0]
    assert command[:2] == [str(python), "-I"]
    assert command[-4:] == ["import", "folder with spaces", "--name", "My project"]
    assert "shell" not in call.call_args.kwargs


def test_setup_without_paths_is_actionable_in_noninteractive_mode(monkeypatch, capsys):
    monkeypatch.setattr(entry.sys.stdin, "isatty", lambda: False)
    call = Mock()
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main(["setup"]) == 1
    call.assert_not_called()
    assert "wheelhouse" in capsys.readouterr().err


@pytest.mark.parametrize("arguments", [["--json", "doctor"], ["--url", "http://127.0.0.1:8001/api", "doctor"], ["--help"]])
def test_cli_global_flags_forward_to_cli_parser(tmp_path, monkeypatch, arguments):
    python = support.environment_python(tmp_path)
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(entry, "ROOT", tmp_path)
    call = Mock(return_value=0)
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main(["cli", *arguments]) == 0
    assert call.call_args.args[0][3:] == arguments


def test_guided_setup_eof_cancels_without_installation(monkeypatch):
    monkeypatch.setattr(entry.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", Mock(side_effect=EOFError))
    call = Mock()
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main(["setup"]) == 130
    call.assert_not_called()


def test_setup_resolves_input_paths_before_changing_directory(monkeypatch):
    call = Mock(return_value=0)
    monkeypatch.setattr(entry.subprocess, "call", call)
    assert entry.main(["setup", "my wheels", "reviewed.sha256", "--profile", "media"]) == 0
    command = call.call_args.args[0]
    assert command[-4:] == [os.path.abspath("my wheels"), os.path.abspath("reviewed.sha256"), "--profile", "media"]


def test_busy_port_is_rejected_instead_of_attaching_to_another_service(monkeypatch):
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        monkeypatch.setattr(start_offline, "PORT", occupied.getsockname()[1])
        with pytest.raises(RuntimeError, match="busy"):
            start_offline.require_free_port()


def test_port_and_offline_mode_reach_both_child_processes(monkeypatch):
    monkeypatch.setattr(start_offline, "require_environment", lambda: None)
    monkeypatch.setattr(start_offline, "require_free_port", lambda: None)
    monkeypatch.setattr(start_offline, "wait_for_server", lambda process: None)
    monkeypatch.setenv("AEGIS_API_URL", "http://127.0.0.1:9999/api")
    monkeypatch.setenv("AEGIS_ENABLE_DEMO_ENDPOINTS", "1")
    server = Mock()
    server.poll.return_value = None
    popen = Mock(return_value=server)
    call = Mock(return_value=0)
    monkeypatch.setattr(start_offline.subprocess, "Popen", popen)
    monkeypatch.setattr(start_offline.subprocess, "call", call)
    assert start_offline.main(["--port", "8123", "--plain"]) == 0
    for invocation in (popen.call_args, call.call_args):
        assert invocation.kwargs["env"]["AEGIS_API_URL"] == "http://127.0.0.1:8123/api"
        assert "AEGIS_ENABLE_DEMO_ENDPOINTS" not in invocation.kwargs["env"]
    assert call.call_args.args[0][-2:] == ["--plain", "shell"]
    server.terminate.assert_called_once()


def test_interrupted_session_reaps_owned_server(monkeypatch):
    monkeypatch.setattr(start_offline, "require_environment", lambda: None)
    monkeypatch.setattr(start_offline, "require_free_port", lambda: None)
    monkeypatch.setattr(start_offline, "wait_for_server", lambda process: None)
    server = Mock()
    server.poll.return_value = None
    monkeypatch.setattr(start_offline.subprocess, "Popen", Mock(return_value=server))
    monkeypatch.setattr(start_offline.subprocess, "call", Mock(side_effect=KeyboardInterrupt))
    assert start_offline.main([]) == 130
    server.terminate.assert_called_once()
    server.wait.assert_called_once()


def test_unavailable_cpu_frequency_does_not_break_non_windows_hardware(monkeypatch):
    from aegis.hardware import detector
    monkeypatch.setattr(detector.psutil, "cpu_freq", Mock(side_effect=NotImplementedError))
    assert detector.detect_hardware()["cpu_frequency_mhz"] is None


@pytest.mark.skipif(os.name == "nt", reason="Native POSIX owner/mode semantics")
def test_posix_state_and_keys_are_private(tmp_path):
    env = support.offline_environment()
    env["AEGIS_DATA_DIR"] = str(tmp_path.resolve() / "private-data")
    program = """
import stat
from aegis import config
from aegis.control import store
from aegis.storage.database import init_db
init_db()
store.init_control()
assert len(store.secret()) == 32
assert stat.S_IMODE(config.DATA_DIR.stat().st_mode) == 0o700
assert stat.S_IMODE((config.DATA_DIR / 'control.key').stat().st_mode) == 0o600
"""
    subprocess.run([sys.executable, "-c", program], cwd=ROOT, env=env, check=True, capture_output=True, text=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows batch wrapper")
def test_windows_wrapper_help_and_exit_code():
    command = ROOT / "Aegis.bat"
    if not (ROOT / ".runtime" / "python" / "python.exe").is_file():
        pytest.skip("Local reviewed bootstrap interpreter is not available")
    result = subprocess.run(["cmd", "/c", str(command), "--help"], cwd=ROOT.parent,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and "macOS" in result.stdout
    result = subprocess.run(["cmd", "/c", str(command), "not-a-command"], cwd=ROOT.parent,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
