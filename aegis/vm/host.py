"""Launch a pinned offline guest and expose its API on IPv4 loopback only."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from aegis.version import __version__
from aegis.vm import policy, protocol


class Channel:
    def __init__(self, sock):
        self.sock = sock
        self.stream = sock.makefile("rwb", buffering=0)
        self.broken = False

    def exchange(self, request):
        if self.broken:
            raise OSError("VM channel failed; restart and investigate")
        try:
            protocol.send(self.stream, request)
            return protocol.receive(self.stream)
        except Exception:
            self.broken = True
            raise

    def close(self):
        self.stream.close()
        self.sock.close()


def connect(settings):
    raw = socket.create_connection(("127.0.0.1", settings["channel_port"]), timeout=3)
    try:
        sock = policy.context(settings).wrap_socket(raw, server_hostname="localhost")
        if (
            hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
            != settings["server_certificate_sha256"]
        ):
            sock.close()
            raise ValueError("VM transport peer certificate pin mismatch")
        sock.settimeout(130)
        return Channel(sock)
    except Exception:
        raw.close()
        raise


class Gateway(http.server.HTTPServer):
    allow_reuse_address = False

    def __init__(self, port, channel):
        # Deliberately single-worker: bounded memory and serialized virtio RPC.
        super().__init__(("127.0.0.1", port), Handler)
        self.channel = channel


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "AegisVM"
    sys_version = ""

    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def log_message(self, *args):
        pass  # Never log request paths, credentials, queries or bodies.

    def handle_api(self):
        self.close_connection = True
        try:
            # Reject rebinding and ambiguous HTTP framing before replacing Host
            # with the fixed guest endpoint. Auth and Origin are never replaced.
            host = self.headers.get_all("Host", [])
            port = self.server.server_port
            if len(host) != 1 or host[0] not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
                raise ValueError("Use the configured loopback API address")
            if (
                self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Expect") is not None
            ):
                raise ValueError("Unsupported HTTP framing")
            lengths = self.headers.get_all("Content-Length", [])
            if (
                len(lengths) > 1
                or lengths
                and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10)
            ):
                raise ValueError("Invalid Content-Length")
            length = int(lengths[0]) if lengths else 0
            if length > protocol.MAX_BODY:
                raise ValueError("HTTP body exceeds the VM bridge limit")
            protocol.target(self.command, self.path)
            headers = protocol.headers([list(pair) for pair in self.headers.items()])
            body = protocol.read_exact(self.rfile, length)
            request_id = secrets.token_hex(16)
            result = self.server.channel.exchange(
                {
                    "id": request_id,
                    "method": self.command,
                    "path": self.path,
                    "headers": [list(pair) for pair in headers],
                    "body": protocol.encode_body(body),
                }
            )
            if (
                set(result) != {"id", "status", "headers", "body"}
                or result["id"] != request_id
                or type(result["status"]) is not int
                or not 200 <= result["status"] <= 599
            ):
                raise OSError("Invalid VM response envelope")
            response_headers = protocol.headers(result["headers"])
            response_body = protocol.decode_body(result["body"])
        except (ValueError, EOFError):
            self.send_error(400, "Invalid bounded API request")
            return
        except OSError:
            self.send_error(503, "VM API unavailable; no native fallback")
            return
        self.send_response(result["status"])
        for name, value in response_headers:
            # BaseHTTPRequestHandler already generates these two headers.
            if name.lower() not in {"server", "date"}:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response_body)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = handle_api


def stop(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        killer = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
        subprocess.run(
            [str(killer), "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def child_environment(settings):
    # No preload hooks, QEMU override variables, application credentials or
    # ambient TLS logging. OS libraries remain part of host acceptance review.
    environment = {"PATH": str(settings["qemu"].parent), "LANG": "C", "QEMU_AUDIO_DRV": "none"}
    for name in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def run(settings, boot_timeout=180):
    policy.secure_mutable_files(settings)
    # Bind the operator port first: fail before booting if another service owns it.
    with Gateway(settings["api_port"], None) as gateway:
        process = subprocess.Popen(
            policy.command(settings),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
            shell=False,
            env=child_environment(settings),
        )
        channel = None
        try:
            deadline = time.monotonic() + boot_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Pinned VM exited before production readiness")
                try:
                    channel = connect(settings)
                    break
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.2)
            if channel is None:
                raise RuntimeError("VM transport startup timed out")
            # Authentication failures do not retry or downgrade to plaintext.
            status = channel.exchange({"operation": "health"})
            if status != {"version": __version__, "production_ready": True}:
                raise RuntimeError("VM guest version or production prerequisites do not match")
            gateway.channel = channel
            gateway.timeout = 0.5
            print(f"Isolated VM API: http://127.0.0.1:{settings['api_port']} (no guest network)")
            print("Use aegis --url <that-address> shell. Ctrl+C stops the owned VM.")
            while process.poll() is None and not channel.broken:
                gateway.handle_request()
            raise RuntimeError("VM stopped or its authenticated channel failed; no fallback")
        finally:
            if channel is not None:
                channel.close()
            stop(process)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "start"])
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        settings = policy.load(args.policy)
        if args.action == "check":
            print(
                json.dumps(
                    {
                        "inventory_verified": True,
                        "host": sys.platform,
                        "version": __version__,
                        "production_accepted": False,
                    }
                )
            )
        else:
            run(settings)
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Aegis VM: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
