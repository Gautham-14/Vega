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
import re

from fastapi import HTTPException, Request
from aegis.control import policy, store
from aegis.storage.database import execute_write, get_db_connection, query_one, query_all

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


def provision(actor, password, template=None):
    if not isinstance(actor, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", actor):
        raise ValueError("Account names use 1-64 lowercase letters, digits and hyphens")
    if template is not None and template not in policy.ACTORS:
        raise ValueError("Choose a built-in account template with users roles")
    if actor in policy.ACTORS and template not in {None, actor}:
        raise ValueError("Built-in accounts cannot change their role template")
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password of 12-256 characters")
    init_auth()
    salt = secrets.token_hex(16)
    hashed = password_hash(password, salt)
    with store.LOCK:
        profile = store.get("account-profile", actor)
        if profile:
            policy.actor(actor)  # authenticate the existing immutable binding
            if template is not None and profile["template"] != template:
                raise ValueError("Role templates are immutable; create a new named account and disable the old one")
        elif actor not in policy.ACTORS:
            if template is None:
                raise ValueError("New named accounts require --like <account-template>")
            body = {"id": actor, "template": template}
            profile = {**body, "seal": store.sign(body, "account-profile-v1")}
        with get_db_connection() as conn:
            if profile:
                conn.execute("INSERT INTO control_objects(kind,id,body) VALUES('account-profile',?,?) "
                             "ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", (actor, store.canonical(profile)))
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


def account_inventory():
    """Host administrator view; never returns salts, credentials or token hashes."""
    init_auth()
    return [dict(row) for row in query_all(
        "SELECT a.actor,a.disabled,COUNT(s.token_hash) AS active_sessions FROM auth_accounts a "
        "LEFT JOIN auth_sessions s ON s.actor=a.actor AND s.expires_at>? GROUP BY a.actor,a.disabled ORDER BY a.actor",
        (time.time(),))]


def session_inventory(actor):
    policy.actor(actor)
    init_auth()
    return [dict(row) for row in query_all(
        "SELECT created_at,expires_at FROM auth_sessions WHERE actor=? AND expires_at>? ORDER BY created_at",
        (actor, time.time()))]


def revoke_account(actor, *, disable=False):
    """Local administrator action. No API can assign roles or revive accounts."""
    policy.actor(actor)
    init_auth()
    with store.LOCK:
        if not query_one("SELECT actor FROM auth_accounts WHERE actor=?", (actor,)):
            raise ValueError("Account is not provisioned")
        store.receipt("ACCOUNT_DISABLED" if disable else "ACCOUNT_SESSIONS_REVOKED", "host-administrator",
                      actor_id_hash=store.digest(actor))
        with get_db_connection() as conn:
            if disable:
                conn.execute("UPDATE auth_accounts SET disabled=1 WHERE actor=?", (actor,))
            conn.execute("DELETE FROM auth_sessions WHERE actor=?", (actor,))
        # Invalidate prior work even if the account is later enabled/reset.
        for raw in store.all_objects("coding-lease"):
            if raw.get("user") == actor:
                store.put("coding-revocation", raw["id"], {"revoked_at": time.time(), "actor": "host-administrator"})
        from aegis.media import service as media
        for raw in store.all_objects("media-job"):
            if raw.get("user") == actor and raw.get("ciphertext"):
                media.destroy(media.read(raw["id"]), "REVOKED")
    return {"actor": actor, "sessions_revoked": True, "existing_work_revoked": True, "disabled": disable}


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
