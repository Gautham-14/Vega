"""Bounded HTTP envelopes over a mutually authenticated serial transport.

This is framing, not custom cryptography: QEMU and Python's TLS stacks supply
authentication and encryption. API authentication and authorization remain in
the guest; the bridge never issues tokens or follows redirects.
"""

from __future__ import annotations

import base64
import json
import struct

MAX_BODY = 8 * 1024 * 1024
MAX_FRAME = 12 * 1024 * 1024
HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def read_exact(stream, length):
    parts = bytearray()
    while len(parts) < length:
        part = stream.read(length - len(parts))
        if not part:
            raise EOFError("VM channel closed")
        parts.extend(part)
    return bytes(parts)


def receive(stream):
    length = struct.unpack("!I", read_exact(stream, 4))[0]
    if not 1 <= length <= MAX_FRAME:
        raise ValueError("VM frame exceeds its limit")
    value = json.loads(read_exact(stream, length))
    if not isinstance(value, dict):
        raise ValueError("VM frame must be an object")
    return value


def send(stream, value):
    payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if not 1 <= len(payload) <= MAX_FRAME:
        raise ValueError("VM frame exceeds its limit")
    packet = struct.pack("!I", len(payload)) + payload
    # Buffered streams and raw character devices can perform partial writes.
    remaining = memoryview(packet)
    while remaining:
        count = stream.write(remaining)
        if not count:
            raise OSError("VM channel write failed")
        remaining = remaining[count:]
    stream.flush()


def encode_body(body):
    if len(body) > MAX_BODY:
        raise ValueError("VM HTTP body exceeds its limit")
    return base64.b64encode(body).decode("ascii")


def decode_body(value):
    if not isinstance(value, str) or len(value) > (MAX_BODY + 2) // 3 * 4:
        raise ValueError("Invalid VM HTTP body")
    body = base64.b64decode(value, validate=True)
    if len(body) > MAX_BODY:
        raise ValueError("VM HTTP body exceeds its limit")
    return body


def headers(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Too many VM HTTP headers")
    result = []
    total = 0
    names = set()
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("Invalid VM HTTP header")
        name, content = pair
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError("Invalid VM HTTP header")
        if not name or any(
            c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            for c in name
        ):
            raise ValueError("Invalid VM HTTP header name")
        if any(ord(c) < 32 or ord(c) > 126 for c in content):
            raise ValueError("Invalid VM HTTP header value")
        total += len(name) + len(content)
        if total > 16384 or name.lower() in names:
            raise ValueError("Oversized or duplicate VM HTTP headers")
        names.add(name.lower())
        if name.lower() not in HOP_HEADERS:
            result.append((name, content))
    return result


def target(method, path):
    if method not in METHODS or not isinstance(path, str) or len(path) > 8192:
        raise ValueError("Invalid VM HTTP request")
    if (
        not path.startswith("/api/")
        or path.startswith("//")
        or any(ord(c) < 33 or ord(c) > 126 or c in "\\#" for c in path)
    ):
        raise ValueError("Only origin-form /api/ requests are allowed")
