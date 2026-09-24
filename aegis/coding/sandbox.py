"""Optional Linux/gVisor executor. No host source execution or automatic pulls.

The sandbox receives a bounded snapshot over stdin, not a host bind mount. Its
image must already be installed and pinned by sha256. A configured backend is
not a claim of independently verified host/network isolation.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import uuid

from aegis.control import store

COMMANDS = {"test": ["python", "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            "lint": ["python", "-I", "-m", "ruff", "check", "."],
            "typecheck": ["python", "-I", "-m", "mypy", ".", "--cache-dir=/tmp/mypy"]}

# This fixed program is passed as argv, never combined with model-supplied code.
BOOTSTRAP = r'''
import json, os, pathlib, subprocess, sys, tempfile
payload = json.load(sys.stdin)
root = pathlib.Path('/workspace')
for name, content in payload['files'].items():
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise ValueError('Invalid snapshot path')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
os.chdir(root)
with tempfile.TemporaryFile() as output:
    try:
        result = subprocess.run(payload['command'], stdout=output, stderr=subprocess.STDOUT, timeout=40,
                                env={'PATH': os.environ['PATH'], 'HOME': '/tmp', 'PYTHONDONTWRITEBYTECODE': '1'})
        code = result.returncode
    except subprocess.TimeoutExpired:
        code = 124
    output.seek(0)
    text = output.read(32001)
    print(json.dumps({'exit_code': code, 'output': text[:32000].decode('utf-8', 'replace'),
                      'truncated': len(text) > 32000}))
'''


def configuration():
    image = os.environ.get("AEGIS_SANDBOX_IMAGE", "")
    enabled = (os.environ.get("AEGIS_SANDBOX_ENABLED") == "1" and platform.system() == "Linux"
               and shutil.which("docker") is not None and bool(re.fullmatch(r"sha256:[a-f0-9]{64}", image)))
    return {"enabled": enabled, "image": image if enabled else None, "runtime": "runsc",
            "network": "none", "host_mounts": False, "commands": list(COMMANDS),
            "verified_isolation": False, "requirements": "Linux, Docker with runsc, installed sha256-pinned image"}


def execute(files, command):
    from aegis.coding.tools import validate_files
    validate_files(files)
    settings = configuration()
    if not settings["enabled"]:
        raise store.Denied("SANDBOX_UNAVAILABLE", settings["requirements"])
    if command not in COMMANDS:
        raise store.Denied("UNAUTHORIZED_TOOL", "Only fixed test, lint and typecheck commands are permitted")
    name = "aegis-task-" + uuid.uuid4().hex
    docker = shutil.which("docker")
    # Ignore inherited Docker contexts/hosts; require the local Linux engine.
    base = [docker, "--host", "unix:///var/run/docker.sock"]
    args = base + ["run", "--rm", "--name", name, "--runtime=runsc", "--pull=never", "--network=none",
                   "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
                   "--memory=512m", "--memory-swap=512m", "--cpus=1", "--user=65534:65534",
                   "--tmpfs=/workspace:rw,nosuid,nodev,size=16m,mode=1777",
                   "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777", "--workdir=/workspace",
                   "--entrypoint=python", "-i", settings["image"], "-I", "-c", BOOTSTRAP]
    clean_env = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "SYSTEMROOT"}}
    output = bytearray()
    overflow = threading.Event()
    process = None
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=clean_env)
        def read_output():
            while block := process.stdout.read(4096):
                if len(output) + len(block) > 65536:
                    overflow.set()
                    process.kill()
                    break
                output.extend(block)
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        payload = json.dumps({"files": files, "command": COMMANDS[command]}).encode()
        def write_input():
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except (OSError, ValueError):
                pass  # Main wait reports failed startup/timeout without leaking payload.
        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()
        process.wait(timeout=55)
        writer.join(timeout=2)
        reader.join(timeout=2)
        if overflow.is_set() or process.returncode or reader.is_alive() or writer.is_alive():
            raise store.Denied("SANDBOX_EXECUTION_FAILED", "Sandbox failed, exceeded output limits or did not stop")
        result = json.loads(output)
        if not isinstance(result, dict) or type(result.get("exit_code")) is not int or not isinstance(result.get("output"), str):
            raise ValueError("Invalid sandbox result")
        return {"status": "PASS" if result["exit_code"] == 0 else "FAIL", "command": command,
                "exit_code": result["exit_code"], "output": result["output"][:32000],
                "truncated": bool(result.get("truncated")), "runtime": "runsc", "image": settings["image"],
                "trust": "UNTRUSTED_TOOL_OUTPUT", "scope": "Command result; OS isolation needs independent validation"}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise store.Denied("SANDBOX_EXECUTION_FAILED", "Local gVisor execution failed or timed out") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdout,):
                if stream:
                    stream.close()
        try:
            cleanup = subprocess.run(base + ["rm", "--force", name], capture_output=True, timeout=10, env=clean_env)
            if cleanup.returncode and b"No such container" not in cleanup.stderr:
                store.event("SANDBOX_CLEANUP_FAILED", name)
                raise store.Denied("SANDBOX_CLEANUP_FAILED", "Sandbox removal could not be confirmed; result withheld")
        except (OSError, subprocess.TimeoutExpired):
            store.event("SANDBOX_CLEANUP_FAILED", name)
            raise store.Denied("SANDBOX_CLEANUP_FAILED", "Sandbox removal could not be confirmed; result withheld") from None
