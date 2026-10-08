"""Bounded JSON RPC over Linux Unix sockets with kernel peer credentials.

No pickle, network listener, shell invocation, or caller-selected operation.
The socket owner and service UID must be different from the runtime UID.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import sys
import threading
import time

MAX_MESSAGE = 16 * 1024 * 1024


def peer_uid(stream):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Independent custody requires Linux SO_PEERCRED")
    return struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive(stream):
    deadline = time.monotonic() + 5
    def read(size):
        parts = bytearray()
        while len(parts) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Custody frame deadline exceeded")
            stream.settimeout(min(remaining, 5))
            chunk = stream.recv(size - len(parts))
            if not chunk:
                raise ValueError("Truncated custody response")
            parts.extend(chunk)
        return bytes(parts)
    length = struct.unpack("!I", read(4))[0]
    if not 0 < length <= MAX_MESSAGE:
        raise ValueError("Custody message exceeds the limit")
    value = json.loads(read(length))
    if not isinstance(value, dict):
        raise ValueError("Custody message must be an object")
    return value


def send(stream, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_MESSAGE:
        raise ValueError("Custody message exceeds the limit")
    stream.sendall(struct.pack("!I", len(raw)) + raw)


def call(path, owner_uid, request, timeout=5):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Protected custody RPC is available on Linux only")
    target = Path(path)
    if not target.is_absolute() or type(owner_uid) is not int or owner_uid < 0 or owner_uid == os.geteuid():
        raise ValueError("Custody service must belong to a separate OS identity")
    # Check ancestors without following symlinks; group-writable socket directories
    # permit substitution and are forbidden even when peer verification would catch it.
    for parent in (target.parent, *target.parent.parents):
        entry = parent.lstat()
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode) or entry.st_mode & 0o022:
            raise ValueError("Custody socket requires protected ancestor directories")
    entry = target.lstat()
    if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != owner_uid or entry.st_mode & 0o007:
        raise ValueError("Custody socket owner or permissions are invalid")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        if not 1 <= timeout <= 120:
            raise ValueError("Invalid custody deadline")
        stream.settimeout(timeout)
        stream.connect(str(target))
        if peer_uid(stream) != owner_uid:
            raise ValueError("Custody service identity differs from policy")
        send(stream, request)
        result = receive(stream)
    if result.get("ok") is not True:
        raise RuntimeError("Custody service refused the operation")
    return result["result"]


def serve(path, allowed_uid, dispatch):
    if not sys.platform.startswith("linux") or type(allowed_uid) is not int or allowed_uid == os.geteuid():
        raise RuntimeError("Service and runtime require separate Linux identities")
    target = Path(path)
    if not target.is_absolute() or target.is_symlink():
        raise ValueError("Use an absolute custody socket path")
    if target.exists():
        entry = target.lstat()
        if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != os.geteuid():
            raise ValueError("Existing custody path is not an owned socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            try:
                probe.connect(str(target))
            except ConnectionRefusedError:
                target.unlink()
            else:
                raise ValueError("Custody service is already listening")
    if target.parent.stat().st_uid != os.geteuid() or target.parent.stat().st_mode & 0o022:
        raise ValueError("Service must own its protected socket directory")
    slots = threading.BoundedSemaphore(4)
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                if peer_uid(self.request) != allowed_uid:
                    return
                value = dispatch(receive(self.request))
                send(self.request, {"ok": True, "result": value})
            except Exception:
                try:
                    send(self.request, {"ok": False})
                except OSError:
                    pass
            finally:
                slots.release()
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        # Refuse excess work before creating an unbounded thread population.
        def process_request(self, request, address):
            if not slots.acquire(blocking=False):
                request.close()
            else:
                super().process_request(request, address)
    with Server(str(target), Handler) as server:
        # The reviewed custody group permits the separately owned runtime to
        # connect; kernel peer UID checks still reject every other group member.
        os.chmod(target, 0o660)  # nosec B103
        try:
            server.serve_forever()
        finally:
            target.unlink(missing_ok=True)
