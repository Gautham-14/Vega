"""Install a wheel into a fresh environment and verify commands and API startup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.request
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def check(wheel):
    # Refuse a stale or incomplete wheel even if its version metadata matches.
    expected = {
        path.relative_to(ROOT).as_posix(): path
        for path in (ROOT / "aegis").rglob("*")
        if path.is_file() and path.suffix in {".py", ".json"}
    }
    with zipfile.ZipFile(wheel) as archive:
        actual = {
            name
            for name in archive.namelist()
            if name.startswith("aegis/") and Path(name).suffix in {".py", ".json"}
        }
        if actual != set(expected):
            raise ValueError("Wheel package inventory does not match the source checkout")
        for name, source in expected.items():
            if archive.read(name).replace(b"\r\n", b"\n") != source.read_bytes().replace(
                b"\r\n", b"\n"
            ):
                raise ValueError("Stale wheel source: " + name)
    with tempfile.TemporaryDirectory(
        prefix="aegis-wheel-", dir=Path(tempfile.gettempdir()).resolve()
    ) as temporary:
        work = Path(temporary)
        environment = work / "env"
        venv.EnvBuilder(with_pip=True).create(environment)
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        env = {
            **os.environ,
            "AEGIS_DATA_DIR": str(work / "data"),
            "AEGIS_CLIENT_DIR": str(work / "client"),
        }
        env.pop("PYTHONPATH", None)
        env["AEGIS_SECURITY_PROFILE"] = "development"
        # A package smoke check must not inherit the operator's live GGUF setup.
        env["AEGIS_LOCAL_MODELS_CONFIG"] = ""
        env.pop("AEGIS_PROVIDER_LOCAL_MODELS_API_KEY", None)
        env.pop("AEGIS_LOCAL_MODELS_CONFIG_HASH", None)
        env.pop("AEGIS_ENABLE_DEMO_ENDPOINTS", None)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                str(ROOT / "requirements-cli.lock"),
            ],
            cwd=work,
            env=env,
            check=True,
        )
        subprocess.run(
            [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
            cwd=work,
            env=env,
            check=True,
        )
        subprocess.run([str(python), "-m", "pip", "check"], cwd=work, env=env, check=True)
        command = """import json, pathlib, importlib.metadata as m
import aegis, aegis.config
from aegis.control import policy
assert not aegis.config.DATA_DIR.exists()
assert m.version('aegis-runtime') == aegis.__version__
assert 'code-refactor-v1' in policy.SKILLS and 'security-audit-v1' in policy.SKILLS
print(json.dumps({'version': aegis.__version__, 'installed_path': str(pathlib.Path(aegis.__file__).resolve())}))
"""
        installed = json.loads(
            subprocess.check_output([str(python), "-c", command], cwd=work, env=env, text=True)
        )
        if Path(installed["installed_path"]).is_relative_to(ROOT):
            raise ValueError("Package smoke test imported the source checkout")
        for name in ("aegis", "aegis-server", "aegis-vm"):
            executable = scripts / (name + (".exe" if os.name == "nt" else ""))
            subprocess.run(
                [str(executable), "--help"], cwd=work, env=env, stdout=subprocess.PIPE, check=True
            )
        executable = scripts / ("aegis.exe" if os.name == "nt" else "aegis")
        subprocess.run(
            [str(executable), "--plain", "shell"],
            input="/exit\n",
            cwd=work,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            timeout=20,
            check=True,
        )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        server = scripts / ("aegis-server.exe" if os.name == "nt" else "aegis-server")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with (work / "server.log").open("w+", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(server), "--quiet", "--port", str(port)],
                cwd=work,
                env=env,
                stdout=log,
                stderr=log,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError("Installed server exited: " + log.read())
                    try:
                        with opener.open(
                            f"http://127.0.0.1:{port}/api/auth/status", timeout=1
                        ) as response:
                            status = json.load(response)
                        assert status["configured"] is False and status["demo"] is False
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Installed API startup timed out")
                assert not list((work / "data" / "models").iterdir())
            finally:
                if os.name == "nt":
                    # Windows console-script launchers spawn a Python child.
                    # Terminate only this smoke test's owned process tree.
                    taskkill = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
                    subprocess.run(
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )
                else:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        return {
            "status": "PASS",
            "version": installed["version"],
            "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "checks": [
                "fresh hash-pinned installation",
                "outside-checkout imports",
                "version metadata",
                "bundled skills",
                "import purity",
                "all three console commands",
                "plain piped shell",
                "API startup",
                "no models loaded",
            ],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if wheel.is_dir():
        candidates = list(wheel.glob("*.whl"))
        if len(candidates) != 1:
            parser.error("wheel directory must contain exactly one wheel")
        wheel = candidates[0]
    result = check(wheel)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
