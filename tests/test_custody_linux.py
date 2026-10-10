"""Real kernel peer-identity checks; explicitly run as root in Linux CI."""

import multiprocessing
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

from aegis.security import key_custody, local_rpc

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: -1)() != 0,
    reason="Separate-UID kernel custody integration requires Linux root",
)


def _server(path, value):
    os.setgid(65534)
    ring = key_custody.Keyring(value)
    local_rpc.serve(path, 65534, lambda request: key_custody.dispatch(ring, request))


def _client(path, uid, request, result):
    os.setgroups([])
    os.setgid(65534)
    os.setuid(uid)
    try:
        reply = local_rpc.call(path, 0, request)
        result.send({"accepted": True, "reply": reply})
    except (ValueError, OSError, RuntimeError):
        result.send({"accepted": False})
    finally:
        result.close()


def test_kernel_peer_credentials_and_no_export():
    context = multiprocessing.get_context("fork")
    with tempfile.TemporaryDirectory(prefix="aegis-custody-test-", dir="/run") as directory:
        os.chown(directory, 0, 65534)
        os.chmod(directory, 0o750)
        path = str(Path(directory) / "service.sock")
        server = context.Process(target=_server, args=(path, key_custody.Keyring.new().value))
        server.start()
        try:
            deadline = time.monotonic() + 5
            while not Path(path).exists():
                if time.monotonic() > deadline or not server.is_alive():
                    pytest.fail("Custody service did not start")
                time.sleep(0.02)
            for uid, request, expected in [
                (65534, {"operation": "status"}, True),
                (10001, {"operation": "status"}, False),
                (65534, {"operation": "export"}, False),
            ]:
                receiver, sender = context.Pipe(duplex=False)
                client = context.Process(target=_client, args=(path, uid, request, sender))
                client.start()
                sender.close()
                assert receiver.poll(8), "Custody request did not finish within its deadline"
                result = receiver.recv()
                client.join(2)
                assert client.exitcode == 0
                assert result["accepted"] is expected
                if expected:
                    assert result["reply"]["key_export"] is False
                receiver.close()
        finally:
            server.terminate()
            server.join(5)
