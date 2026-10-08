"""Versioned signing/encryption custody; production keys never leave the broker.

Local keyrings support development and offline migration. Independent broker
mode requires a separate Linux identity and a protected Unix socket.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken
from aegis.security.private_files import no_links, restrict_permissions


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Keyring:
    def __init__(self, value):
        if not isinstance(value, dict) or set(value) != {"version", "active", "keys", "legacy"} or value["version"] != 2:
            raise ValueError("Invalid custody keyring")
        if not isinstance(value["keys"], dict) or not 1 <= len(value["keys"]) <= 32:
            raise ValueError("Invalid custody key versions")
        if value["active"] not in value["keys"]:
            raise ValueError("Active custody key is absent")
        for identity, pair in value["keys"].items():
            if not re.fullmatch(r"[a-f0-9]{16}", identity) or set(pair) != {"signing", "encryption"}:
                raise ValueError("Invalid custody key identity")
            for raw in pair.values():
                if len(base64.b64decode(raw, validate=True)) != 32:
                    raise ValueError("Invalid custody key length")
        if value["legacy"] is not None and len(base64.b64decode(value["legacy"], validate=True)) != 32:
            raise ValueError("Invalid legacy custody key")
        self.value = value

    @classmethod
    def new(cls, legacy=None):
        identity = secrets.token_hex(8)
        return cls({"version": 2, "active": identity, "keys": {identity: {
            name: base64.b64encode(secrets.token_bytes(32)).decode() for name in ("signing", "encryption")}},
            "legacy": base64.b64encode(legacy).decode() if legacy else None})

    def rotate(self):
        if len(self.value["keys"]) >= 32:
            raise ValueError("Key version limit reached; migrate retained data before retiring keys")
        fresh = self.new().value
        self.value["keys"].update(fresh["keys"])
        self.value["active"] = fresh["active"]
        return self.value["active"]

    def _key(self, identity, kind):
        return base64.b64decode(self.value["keys"][identity][kind], validate=True)

    def sign(self, value, domain):
        identity = self.value["active"]
        message = (identity + ":" + domain + canonical(value)).encode()
        return identity + "." + hmac.new(self._key(identity, "signing"), message, hashlib.sha256).hexdigest()

    def verify(self, value, domain, signature):
        if not isinstance(signature, str) or len(signature) > 100:
            return False
        try:
            if "." not in signature:
                if self.value["legacy"] is None:
                    return False
                expected = hmac.new(base64.b64decode(self.value["legacy"]),
                    (domain + canonical(value)).encode(), hashlib.sha256).hexdigest()
            else:
                identity, _ = signature.split(".", 1)
                message = (identity + ":" + domain + canonical(value)).encode()
                expected = identity + "." + hmac.new(self._key(identity, "signing"), message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except (KeyError, ValueError, TypeError):
            return False

    def cipher(self, identity, namespace):
        raw = hmac.new(self._key(identity, "encryption"), namespace.encode(), hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(raw))

    def encrypt(self, namespace, raw):
        identity = self.value["active"]
        return identity + ":" + self.cipher(identity, namespace).encrypt(raw).decode()

    def decrypt(self, namespace, token):
        if ":" in token:
            identity, raw = token.split(":", 1)
            return self.cipher(identity, namespace).decrypt(raw.encode())
        if self.value["legacy"] is None:
            raise InvalidToken
        key = hmac.new(base64.b64decode(self.value["legacy"]), namespace.encode(), hashlib.sha256).digest()
        return Fernet(base64.urlsafe_b64encode(key)).decrypt(token.encode())


def load(path):
    path = no_links(path)
    if path.stat().st_size > 32768:
        raise ValueError("Custody keyring exceeds size limit")
    raw = path.read_bytes()
    if path.suffix == ".dpapi":
        from aegis.security.dpapi import unprotect
        raw = unprotect(raw)
    return Keyring(json.loads(raw))


def save(path, ring, *, create=False):
    path = no_links(path)
    raw = canonical(ring.value).encode()
    if path.suffix == ".dpapi":
        from aegis.security.dpapi import protect
        raw = protect(raw)
    temp = no_links(path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp"))
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        restrict_permissions(temp)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if create:
            # Atomic creation must never overwrite an existing keyring.
            os.link(temp, path)
            temp.unlink()
        else:
            os.replace(temp, path)
        restrict_permissions(path)
        if os.name != "nt":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temp.unlink(missing_ok=True)


def local_path():
    from aegis import config
    return config.DATA_DIR / ("control.keys.dpapi" if os.name == "nt" else "control.keys.json")


def dispatch(ring, request):
    op = request.get("operation")
    fields = {"status": {"operation"}, "sign": {"operation", "value", "domain"},
              "verify": {"operation", "value", "domain", "signature"},
              "encrypt": {"operation", "namespace", "data"}, "decrypt": {"operation", "namespace", "token"}}
    if op not in fields or set(request) != fields[op]:
        raise ValueError("Unsupported custody operation")
    if op == "status":
        return {"version": 2, "active": ring.value["active"], "key_versions": len(ring.value["keys"]), "key_export": False}
    label = request.get("domain", request.get("namespace"))
    if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,120}", label):
        raise ValueError("Invalid custody domain")
    if op == "sign":
        return ring.sign(request["value"], label)
    if op == "verify":
        return ring.verify(request["value"], label, request["signature"])
    if op == "encrypt":
        return ring.encrypt(label, base64.b64decode(request["data"], validate=True))
    return base64.b64encode(ring.decrypt(label, request["token"])).decode()


def remote(request):
    from aegis.security.local_rpc import call
    path = os.environ.get("AEGIS_KEY_BROKER_SOCKET")
    if not path:
        raise RuntimeError("Independent key broker is not configured")
    return call(path, int(os.environ["AEGIS_KEY_BROKER_UID"]), request)


def initialize():
    from aegis.control import store
    if os.environ.get("AEGIS_KEY_BROKER_SOCKET"):
        raise ValueError("Initialize broker keys under the independent service identity")
    with store.LOCK:
        from aegis.security.quiescence import exclusive
        with exclusive("migrating local key custody"):
            path = local_path()
            if path.exists():
                raise ValueError("Keyring already exists")
            ring = Keyring.new(store.secret())
            save(path, ring, create=True)
            return dispatch(ring, {"operation": "status"})


def main():
    parser = argparse.ArgumentParser(description="Offline custody administration; stop the service before rotation")
    parser.add_argument("action", choices=("init", "rotate", "serve"))
    parser.add_argument("--keyring", required=True)
    parser.add_argument("--socket")
    parser.add_argument("--runtime-uid", type=int)
    args = parser.parse_args()
    if args.action == "init":
        save(args.keyring, Keyring.new(), create=True)
        return
    from aegis.security.quiescence import exclusive
    with exclusive("rotating or starting key custody", Path(args.keyring).with_suffix(".lock")):
        ring = load(args.keyring)
        if args.action == "rotate":
            ring.rotate()
            save(args.keyring, ring)
        else:
            from aegis.security.local_rpc import serve
            lock = threading.RLock()
            def process(request):
                with lock:
                    return dispatch(ring, request)
            serve(args.socket, args.runtime_uid, process)


if __name__ == "__main__":
    main()
