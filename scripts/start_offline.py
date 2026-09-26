"""Run the loopback Aegis service and operator CLI as one local session."""

import http.client
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.runtime_support import require_environment as check_environment, offline_environment
HOST = "127.0.0.1"
PORT = 8000


def require_environment() -> None:
    check_environment(ROOT)


def require_free_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((HOST, PORT))
        except OSError:
            raise RuntimeError(f"Port {PORT} is busy. Close the existing Aegis session or use start --port <unused-port>.") from None


def wait_for_server(process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Aegis server stopped during startup")
        connection = http.client.HTTPConnection(HOST, PORT, timeout=1)
        try:
            connection.request("GET", "/health", headers={"Host": f"{HOST}:{PORT}"})
            response = connection.getresponse()
            status = json.loads(response.read(4096)) if response.status == 200 else None
            if isinstance(status, dict) and status.get("deployment_mode") == "LOCAL":
                return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.2)
    raise RuntimeError("Aegis server did not become ready on loopback")


def main(argv=None) -> int:
    global PORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--plain", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Port must be 1-65535")
    PORT = args.port
    server = None
    try:
        require_environment()
        require_free_port()
        env = offline_environment()
        env["AEGIS_API_URL"] = f"http://{HOST}:{PORT}/api"
        # Start in real-account mode; demonstration must be explicitly launched separately.
        env.pop("AEGIS_ENABLE_DEMO_ENDPOINTS", None)
        print("Starting Aegis locally...", flush=True)
        server = subprocess.Popen([sys.executable, "-I", str(ROOT / "run_aegis.py"), "--host", HOST,
                                   "--port", str(PORT), "--quiet"], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                  start_new_session=os.name != "nt")
        wait_for_server(server)
        print(f"Ready. Dashboard: http://{HOST}:{PORT} | /help for guidance | /exit stops this session.", flush=True)
        command = [sys.executable, "-I", str(ROOT / "scripts" / "run_cli.py")]
        if args.plain:
            command.append("--plain")
        return subprocess.call([*command, "shell"], cwd=ROOT, env=env)
    except (OSError, RuntimeError, ImportError) as error:
        print(f"Offline startup failed: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nClosing Aegis session.")
        return 130
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    raise SystemExit(main())
