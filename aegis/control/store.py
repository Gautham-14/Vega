"""Small durable object store and transactional, authenticated receipt chain."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid

from aegis import config
from aegis.storage.database import get_db_connection, execute_write, query_all, query_one

LOCK = threading.RLock()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def uid(prefix):
    return f"{prefix}-{uuid.uuid4().hex}"


def _requires_existing_key():
    """Never replace a lost trust root when protected state already exists."""
    if not config.DB_PATH.exists():
        return False
    with get_db_connection() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        for table in ("control_receipts", "control_head"):
            if table in tables and conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                return True
        if "control_objects" in tables:
            for row in conn.execute("SELECT kind,body FROM control_objects"):
                value = json.loads(row[1])
                if ({"ciphertext", "wrapped_key", "wrapped", "seal"} & value.keys()
                        or row[0] == "lease" and "signature" in value):
                    return True
    return False


def secret():
    # Local software trust root. Current-user DPAPI protects Windows copies at
    # rest; a compromised logged-in account or host administrator can still use it.
    path = config.DATA_DIR / "control.key"
    protected = config.DATA_DIR / "control.key.dpapi"
    with LOCK:
        from aegis.security.private_files import no_links
        no_links(path)
        no_links(protected)
        if protected.exists():
            if os.name != "nt":
                raise RuntimeError("This data directory contains a Windows-protected key. Restore an encrypted Aegis backup on this OS; do not copy the live Windows directory.")
            from aegis.security.dpapi import unprotect
            key = unprotect(protected.read_bytes())
            if path.exists() and path.read_bytes() != key:
                raise RuntimeError("Conflicting raw and protected control keys")
            if len(key) != 32:
                raise RuntimeError("Invalid protected control key")
            return key
        if not path.exists():
            if _requires_existing_key():
                raise RuntimeError("Control key is missing for existing protected state; restore the original key from an encrypted backup")
            key = secrets.token_bytes(32)
            if os.name == "nt":
                from aegis.security.dpapi import protect, unprotect
                from aegis.security.private_files import restrict_permissions
                fd = os.open(protected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    restrict_permissions(protected)
                    with os.fdopen(fd, "wb") as stream:
                        fd = -1
                        stream.write(protect(key))
                        stream.flush()
                        os.fsync(stream.fileno())
                    if unprotect(protected.read_bytes()) != key:
                        raise RuntimeError("New protected control key verification failed")
                except Exception:
                    if fd >= 0:
                        os.close(fd)
                    protected.unlink(missing_ok=True)
                    raise
                return key
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(key)
                stream.flush()
                os.fsync(stream.fileno())
        if os.name != "nt":
            from aegis.security.private_files import restrict_permissions
            restrict_permissions(path)
        key = path.read_bytes()
    if len(key) != 32:
        raise RuntimeError("Invalid local control key")
    return key


def protect_secret():
    """Migrate a backed-up key to current-user Windows DPAPI, then drop raw file."""
    if os.name != "nt":
        return "POSIX_KEY_PERMISSIONS_ONLY"
    from aegis.security.dpapi import protect, unprotect
    from aegis.security.private_files import no_links, restrict_permissions
    path = no_links(config.DATA_DIR / "control.key")
    protected = no_links(config.DATA_DIR / "control.key.dpapi")
    with LOCK:
        key = secret()
        if protected.exists():
            if unprotect(protected.read_bytes()) != key:
                raise RuntimeError("Protected control key does not match the live key")
        else:
            wrapped = protect(key)
            fd = os.open(protected, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                restrict_permissions(protected)
                with os.fdopen(fd, "wb") as stream:
                    fd = -1
                    stream.write(wrapped)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                if fd >= 0:
                    os.close(fd)
                protected.unlink(missing_ok=True)
                raise
            if unprotect(protected.read_bytes()) != key:
                raise RuntimeError("Protected control key verification failed")
        path.unlink(missing_ok=True)
        return "CURRENT_USER_DPAPI"


def sign(value, domain):
    return hmac.new(secret(), (domain + canonical(value)).encode(), hashlib.sha256).hexdigest()


def encryption_key(namespace):
    return base64.urlsafe_b64encode(hmac.new(secret(), namespace.encode(), hashlib.sha256).digest())


def init_control():
    with get_db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS control_objects (
                kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (kind, id)
            );
            CREATE TABLE IF NOT EXISTS control_receipts (
                sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS control_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL, hash TEXT NOT NULL, signature TEXT NOT NULL
            );
        """)


def get(kind, identity):
    row = query_one("SELECT body FROM control_objects WHERE kind=? AND id=?", (kind, identity))
    return json.loads(row["body"]) if row else None


def require(kind, identity):
    value = get(kind, identity)
    if value is None:
        raise Denied("UNKNOWN_OBJECT", "Object is not registered", identity)
    return value


def put(kind, identity, value):
    execute_write("INSERT INTO control_objects(kind,id,body) VALUES(?,?,?) "
                  "ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", (kind, identity, canonical(value)))
    return value


def all_objects(kind):
    return [json.loads(r["body"]) for r in query_all(
        "SELECT body FROM control_objects WHERE kind=? ORDER BY id", (kind,))]


def event(code, reference="", action="BLOCKED"):
    identity = uid("SEC")
    execute_write("INSERT INTO security_events(id,event_type,severity,description,source_document,action_taken) "
                  "VALUES(?,?,?,?,?,?)", (identity, code, "HIGH", code.replace("_", " "), reference, action))
    return identity


class Denied(ValueError):
    def __init__(self, code, message, reference=""):
        self.code = code
        self.event_id = event(code, reference)
        super().__init__(message)


def verify_rows(rows, head, key=None):
    previous = "0" * 64
    sequence = 0
    try:
        for row in rows:
            body = json.loads(row["body"])
            sequence += 1
            if (row["sequence"] != sequence or body["sequence"] != sequence or row["id"] != body["id"]
                    or body["previous_receipt_hash"] != previous or digest(body) != row["hash"]):
                return False
            previous = row["hash"]
        if not head:
            return sequence == 0
        expected = {"sequence": sequence, "hash": previous}
        signature = (hmac.new(key, ("receipt-head" + canonical(expected)).encode(), hashlib.sha256).hexdigest()
                     if key is not None else sign(expected, "receipt-head"))
        return (head["sequence"] == sequence and head["hash"] == previous
                and hmac.compare_digest(head["signature"], signature))
    except (KeyError, ValueError, TypeError):
        return False


def verify_chain(record_failure=True):
    with LOCK, get_db_connection() as conn:
        conn.execute("BEGIN")
        rows = conn.execute("SELECT * FROM control_receipts ORDER BY sequence").fetchall()
        head = conn.execute("SELECT * FROM control_head WHERE singleton=1").fetchone()
        valid = verify_rows(rows, head)
    if not valid and record_failure:
        event("RECEIPT_CHAIN_FAILURE")
    return {"is_valid": valid, "count": len(rows), "status": "VALID" if valid else "TAMPERED",
            "scope": "Local hash chain with HMAC head; not an external or hardware trust anchor"}


def receipt(action, actor="system", **metadata):
    if set(metadata) & {"id", "sequence", "timestamp", "previous_receipt_hash", "receipt_hash"}:
        raise ValueError("Receipt metadata cannot replace chain identity fields")
    with LOCK, get_db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("SELECT * FROM control_receipts ORDER BY sequence").fetchall()
        head = conn.execute("SELECT * FROM control_head WHERE singleton=1").fetchone()
        if not verify_rows(rows, head):
            # Record after the write transaction has released its lock.
            conn.rollback()
            raise Denied("RECEIPT_CHAIN_FAILURE", "Receipt chain is damaged; append refused")
        sequence = (head["sequence"] if head else 0) + 1
        body = {"id": uid("GREC"), "sequence": sequence, "action": action,
                "actor": actor, "timestamp": time.time(), "mode": "SOFTWARE_SIMULATION",
                "previous_receipt_hash": head["hash"] if head else "0" * 64, **metadata}
        hashed = digest(body)
        conn.execute("INSERT INTO control_receipts VALUES(?,?,?,?)", (sequence, body["id"], canonical(body), hashed))
        head_data = {"sequence": sequence, "hash": hashed}
        conn.execute("INSERT INTO control_head VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET "
                     "sequence=excluded.sequence,hash=excluded.hash,signature=excluded.signature",
                     (sequence, hashed, sign(head_data, "receipt-head")))
    return {**body, "receipt_hash": hashed}


def receipts():
    return [{**json.loads(r["body"]), "receipt_hash": r["hash"]} for r in query_all(
        "SELECT body,hash FROM control_receipts ORDER BY sequence DESC")]
