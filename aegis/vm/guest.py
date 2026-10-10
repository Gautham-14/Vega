"""Guest-only serial bridge. Run as the restricted API identity, not root."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import stat
import sys

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
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=120)
    try:
        connection.putrequest(request["method"], request["path"], skip_accept_encoding=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
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
    while True:
        request = protocol.receive(stream)
        if set(request) == {"operation"} and request["operation"] == "health":
            result = health()
        else:
            result = forward(request)
        protocol.send(stream, result)


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
