"""Bounded concurrent guest bridge. Run as the restricted API identity, not root."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import stat
import sys
import threading

from aegis.version import __version__
from aegis.vm import protocol

DEVICE = "/dev/virtio-ports/org.aegis.api"


def forward(request):
    if set(request) != {"id", "method", "path", "headers", "body"} or not re.fullmatch(
        r"[0-9a-f]{32}", str(request.get("id", ""))
    ):
        raise ValueError("Invalid VM request envelope")
    protocol.target(request["method"], request["path"])
    headers = protocol.headers(request["headers"])
    body = protocol.decode_body(request["body"])
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=300)
    active_socket = None

    def expire():
        stream = active_socket if active_socket is not None else connection.sock
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    deadline = threading.Timer(300, expire)
    deadline.daemon = True
    try:
        deadline.start()
        connection.putrequest(request["method"], request["path"], skip_accept_encoding=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        active_socket = connection.sock
        response = connection.getresponse()
        result = response.read(protocol.MAX_BODY + 1)
        return {
            "id": request["id"],
            "status": response.status,
            "headers": [
                [name, value]
                for name, value in protocol.headers([list(pair) for pair in response.getheaders()])
            ],
            "body": protocol.encode_body(result),
        }
    finally:
        deadline.cancel()
        connection.close()


def health():
    from aegis.security.deployment import validate

    deployment = validate()
    if deployment.get("production_ready") is not True:
        raise RuntimeError("VM guest must use the production security profile")
    response = forward(
        {"id": "0" * 32, "method": "GET", "path": "/api/auth/status", "headers": [], "body": ""}
    )
    status = json.loads(protocol.decode_body(response["body"]))
    if (
        response["status"] != 200
        or status.get("configured") is not True
        or status.get("demo") is not False
    ):
        raise RuntimeError("VM guest needs a provisioned production API without demo accounts")
    return {"version": __version__, "production_ready": True}


def serve(stream):
    writer = threading.Lock()
    operations = threading.BoundedSemaphore(8)
    incidents = threading.BoundedSemaphore(4)
    from aegis.security.incident import route

    def respond(request, slots):
        try:
            try:
                result = forward(request)
            except (ValueError, OSError, http.client.HTTPException):
                result = {
                    "id": request["id"],
                    "status": 503,
                    "headers": [],
                    "body": protocol.encode_body(b'{"detail":"Guest API request failed"}'),
                }
            with writer:
                protocol.send(stream, result)
        finally:
            slots.release()

    while True:
        request = protocol.receive(stream)
        if set(request) == {"operation"} and request["operation"] == "health":
            result = health()
            with writer:
                protocol.send(stream, result)
        else:
            if set(request) != {"id", "method", "path", "headers", "body"} or not re.fullmatch(
                r"[0-9a-f]{32}", str(request["id"])
            ):
                raise ValueError("Invalid VM request envelope")
            slots = incidents if route(request["method"], request["path"]) else operations
            if not slots.acquire(blocking=False):
                with writer:
                    protocol.send(
                        stream,
                        {
                            "id": request["id"],
                            "status": 429,
                            "headers": [],
                            "body": protocol.encode_body(
                                b'{"detail":"Guest request budget exhausted"}'
                            ),
                        },
                    )
            else:
                threading.Thread(target=respond, args=(request, slots), daemon=True).start()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        parser.error("Run the VM bridge inside Linux as the restricted API identity")
    health()
    # The kernel-generated virtio-port name is itself a symlink. Open this fixed
    # path only; require a character device and never accept a user-supplied path.
    descriptor = os.open(DEVICE, os.O_RDWR | os.O_NOCTTY)
    try:
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode):
            raise ValueError("VM bridge requires the provisioned virtio character device")
        with os.fdopen(descriptor, "r+b", buffering=0) as stream:
            descriptor = -1
            serve(stream)
    finally:
        if descriptor != -1:
            os.close(descriptor)


if __name__ == "__main__":
    main()
