"""Local account authentication. Role assignment is a host-administrator action.

Passwords use scrypt, bearer tokens are stored only as hashes, and resetting an
account revokes its sessions. Demo headers are accepted only in explicit demo
mode before any accounts have been provisioned.
"""
import hashlib
import hmac
import os
import secrets
import time

from fastapi import HTTPException, Request
from aegis.control import policy, store
from aegis.storage.database import execute_write, get_db_connection, query_one

SESSION_SECONDS = 8 * 60 * 60


def init_auth():
    with get_db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS auth_accounts (
                actor TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY, actor TEXT NOT NULL, expires_at REAL NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_attempts (
                bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_start REAL NOT NULL
            );
        """)


def configured():
    init_auth()
    return bool(query_one("SELECT actor FROM auth_accounts LIMIT 1"))


def demo_identity_enabled():
    return os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") == "1" and not configured()


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def provision(actor, password):
    policy.actor(actor)
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password of 12-256 characters")
    init_auth()
    salt = secrets.token_hex(16)
    hashed = password_hash(password, salt)
    with store.LOCK, get_db_connection() as conn:
        conn.execute("INSERT INTO auth_accounts(actor,salt,password_hash) VALUES(?,?,?) "
                     "ON CONFLICT(actor) DO UPDATE SET salt=excluded.salt,password_hash=excluded.password_hash,disabled=0",
                     (actor, salt, hashed))
        conn.execute("DELETE FROM auth_sessions WHERE actor=?", (actor,))
    store.receipt("ACCOUNT_PROVISIONED", actor)
    return {"actor": actor, "sessions_revoked": True}


def login(actor, password, client):
    init_auth()
    now = time.time()
    # One bounded bucket per client, not per arbitrary username.
    bucket = hashlib.sha256(client.encode()).hexdigest()
    with store.LOCK:
        attempt = query_one("SELECT * FROM auth_attempts WHERE bucket=?", (bucket,))
        if attempt and attempt["window_start"] > now - 300 and attempt["failures"] >= 8:
            raise HTTPException(429, "Too many sign-in attempts. Try again in five minutes.")
        row = query_one("SELECT * FROM auth_accounts WHERE actor=?", (actor,))
        salt = row["salt"] if row else "00" * 16
        expected = row["password_hash"] if row else "00" * 64
        valid = hmac.compare_digest(password_hash(password, salt), expected)
        if not row or not valid or row["disabled"]:
            failures = attempt["failures"] + 1 if attempt and attempt["window_start"] > now - 300 else 1
            start = attempt["window_start"] if failures > 1 else now
            execute_write("INSERT OR REPLACE INTO auth_attempts VALUES(?,?,?)", (bucket, failures, start))
            raise HTTPException(401, "Invalid account or password")
        token = secrets.token_urlsafe(32)
        with get_db_connection() as conn:
            # A valid low-privilege password must not reset guesses against other accounts.
            conn.execute("DELETE FROM auth_attempts WHERE window_start<?", (now - 300,))
            conn.execute("DELETE FROM auth_sessions WHERE expires_at<=?", (now,))
            conn.execute("INSERT INTO auth_sessions VALUES(?,?,?,?)",
                         (hashlib.sha256(token.encode()).hexdigest(), actor, now + SESSION_SECONDS, now))
        store.receipt("SESSION_LOGIN", actor)
    return {"access_token": token, "token_type": "bearer", "expires_at": now + SESSION_SECONDS,
            "actor": actor, "role": policy.actor(actor)["role"]}


def authenticate(request: Request):
    authorization = request.headers.get("authorization", "")
    token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else request.cookies.get("aegis_session")
    if token:
        init_auth()
        row = query_one("SELECT s.actor,s.expires_at FROM auth_sessions s JOIN auth_accounts a ON a.actor=s.actor "
                        "WHERE s.token_hash=? AND a.disabled=0", (hashlib.sha256(token.encode()).hexdigest(),))
        if row and row["expires_at"] > time.time():
            request.state.actor = row["actor"]
            request.state.session_token = token
            return row["actor"]
        raise HTTPException(401, "Session expired or revoked. Sign in again.")
    if authorization:
        raise HTTPException(401, "Use a Bearer session token")
    if demo_identity_enabled():
        actor = policy.actor(request.headers.get("x-aegis-actor", "operator"))["id"]
        request.state.actor = actor
        return actor
    raise HTTPException(401, "Sign in to Aegis. Provision a local account with 'aegis users set <actor>' if needed.")


def logout(token):
    execute_write("DELETE FROM auth_sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))


def principal(request: Request):
    return getattr(request.state, "actor", None) or authenticate(request)


def authorize_legacy(request: Request):
    """Legacy unscoped stores are administrative surfaces, not a lease bypass."""
    if demo_identity_enabled():
        return
    path = request.url.path
    roles = None
    if path.startswith("/api/knowledge"):
        roles = ["Data Owner"]
    elif path.startswith(("/api/tasks", "/api/receipts", "/api/security/events", "/api/dashboard")):
        roles = ["Auditor", "Security Officer"]
    elif request.method not in {"GET", "HEAD"} and path.startswith(("/api/models", "/api/hardware")):
        roles = ["Model Custodian"]
    if roles:
        policy.actor(request.state.actor, roles)
