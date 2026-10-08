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
import base64
import struct
from urllib.parse import quote

from fastapi import HTTPException, Request
from aegis.control import policy, store
from aegis.storage.database import execute_write, get_db_connection, query_one, query_all

SESSION_SECONDS = 8 * 60 * 60
PRIVILEGED_SESSION_SECONDS = 15 * 60
STEP_UP_SECONDS = 5 * 60
MAX_SESSIONS = 3
PRIVILEGED_ROLES = {"Data Owner", "Model Custodian", "Security Officer", "Key Custodian"}


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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_sessions)")}
        if "mfa_at" not in columns:
            conn.execute("ALTER TABLE auth_sessions ADD COLUMN mfa_at REAL NOT NULL DEFAULT 0")


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
        _invalidate_work(actor)
    store.receipt("ACCOUNT_PROVISIONED", actor)
    return {"actor": actor, "sessions_revoked": True}


def totp(secret, counter):
    key = base64.b32decode(secret, casefold=False)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000).zfill(6)


def enroll_mfa(actor):
    """Host administrator enrollment/reset; the seed is displayed once locally."""
    policy.actor(actor)
    init_auth()
    with store.LOCK:
        if not query_one("SELECT actor FROM auth_accounts WHERE actor=? AND disabled=0", (actor,)):
            raise ValueError("Provision an enabled account before enrolling MFA")
        seed = base64.b32encode(secrets.token_bytes(20)).decode()
        body = {"id": actor, "secret": store.encrypt("auth-mfa", seed.encode()), "last_counter": -1}
        store.put("account-mfa", actor, {**body, "seal": store.sign(body, "account-mfa")})
        execute_write("DELETE FROM auth_sessions WHERE actor=?", (actor,))
        _invalidate_work(actor)
        store.receipt("MFA_ENROLLED", "host-administrator", account_hash=store.digest(actor))
    return {"actor": actor, "secret": seed,
            "otpauth_uri": f"otpauth://totp/Aegis:{quote(actor)}?secret={seed}&issuer=Aegis&algorithm=SHA1&digits=6&period=30"}


def _verify_otp(actor, code, now):
    value = store.get("account-mfa", actor)
    if value is None:
        return False
    body = {key: item for key, item in value.items() if key != "seal"}
    if body.get("id") != actor or not store.verify_signature(body, "account-mfa", value.get("seal")):
        raise store.Denied("MFA_INTEGRITY_FAILURE", "MFA enrollment is damaged")
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return False
    seed = store.decrypt("auth-mfa", body["secret"]).decode()
    current = int(now // 30)
    matching = [counter for counter in (current - 1, current, current + 1)
                if counter > body["last_counter"] and hmac.compare_digest(totp(seed, counter), code)]
    if not matching:
        return False
    counter = max(matching)
    # The sealed row alone could be replayed. Bind replay prevention to the
    # independently witnessed receipt history as well as the current enrollment.
    latest = query_one("SELECT MAX(json_extract(body,'$.counter')) AS counter FROM control_receipts "
                       "WHERE json_extract(body,'$.action')='MFA_VERIFIED' AND json_extract(body,'$.account_hash')=?",
                       (store.digest(actor),))
    if latest and latest["counter"] is not None and counter <= latest["counter"]:
        return False
    store.receipt("MFA_VERIFIED", actor, account_hash=store.digest(actor), counter=counter)
    body["last_counter"] = counter
    store.put("account-mfa", actor, {**body, "seal": store.sign(body, "account-mfa")})
    return True


def login(actor, password, client, otp=None):
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
        from aegis.security.deployment import production
        privileged = bool(row and valid and policy.actor(actor)["role"] in PRIVILEGED_ROLES)
        mfa_required = bool(store.get("account-mfa", actor)) or (production() and privileged)
        mfa_valid = _verify_otp(actor, otp, now) if row and valid and not row["disabled"] and mfa_required else False
        if not row or not valid or row["disabled"] or (mfa_required and not mfa_valid):
            failures = attempt["failures"] + 1 if attempt and attempt["window_start"] > now - 300 else 1
            start = attempt["window_start"] if failures > 1 else now
            execute_write("INSERT OR REPLACE INTO auth_attempts VALUES(?,?,?)", (bucket, failures, start))
            raise HTTPException(401, "Invalid account, password or verification code")
        token = secrets.token_urlsafe(32)
        lifetime = PRIVILEGED_SESSION_SECONDS if privileged else SESSION_SECONDS
        with get_db_connection() as conn:
            # A valid low-privilege password must not reset guesses against other accounts.
            conn.execute("DELETE FROM auth_attempts WHERE window_start<?", (now - 300,))
            conn.execute("DELETE FROM auth_sessions WHERE expires_at<=?", (now,))
            existing = conn.execute("SELECT token_hash FROM auth_sessions WHERE actor=? ORDER BY created_at DESC,token_hash DESC", (actor,)).fetchall()
            for old in existing[MAX_SESSIONS - 1:]:
                conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (old[0],))
            conn.execute("INSERT INTO auth_sessions(token_hash,actor,expires_at,created_at,mfa_at) VALUES(?,?,?,?,?)",
                         (hashlib.sha256(token.encode()).hexdigest(), actor, now + lifetime, now, now if mfa_valid else 0))
        store.receipt("SESSION_LOGIN", actor)
    return {"access_token": token, "token_type": "bearer", "expires_at": now + lifetime,
            "actor": actor, "role": policy.actor(actor)["role"]}


def authenticate(request: Request):
    authorizations = request.headers.getlist("authorization")
    if len(authorizations) > 1:
        raise HTTPException(401, "Use one Bearer session token")
    authorization = authorizations[0] if authorizations else ""
    if authorizations:
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or any(c.isspace() for c in token):
            raise HTTPException(401, "Use a Bearer session token")
    else:
        token = request.cookies.get("aegis_session")
    if token:
        if len(token) > 256:
            raise HTTPException(401, "Invalid session token")
        init_auth()
        row = query_one("SELECT s.actor,s.expires_at,s.mfa_at FROM auth_sessions s JOIN auth_accounts a ON a.actor=s.actor "
                        "WHERE s.token_hash=? AND a.disabled=0", (hashlib.sha256(token.encode()).hexdigest(),))
        if row and row["expires_at"] > time.time():
            request.state.actor = row["actor"]
            request.state.session_token = token
            request.state.mfa_at = row["mfa_at"]
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


def _invalidate_work(actor):
    """Caller holds LOCK. A reset must not revive previously authorized work."""
    for raw in store.all_objects("coding-lease"):
        if raw.get("user") == actor:
            store.put("coding-revocation", raw["id"], {"revoked_at": time.time(), "actor": "host-administrator"})
    from aegis.coding import service as coding
    for raw in store.all_objects("coding-task"):
        if raw.get("user") == actor and raw.get("ciphertext"):
            coding.destroy(coding.verified("task", raw["id"]), "REVOKED")
    from aegis.media import service as media
    for raw in store.all_objects("media-job"):
        if raw.get("user") == actor and raw.get("ciphertext"):
            media.destroy(media.read(raw["id"]), "REVOKED")


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
        _invalidate_work(actor)
    return {"actor": actor, "sessions_revoked": True, "existing_work_revoked": True, "disabled": disable}


def principal(request: Request):
    return getattr(request.state, "actor", None) or authenticate(request)


def require_step_up(request):
    from aegis.security.deployment import production
    identity = principal(request)
    if (production() and request.method not in {"GET", "HEAD"}
        and request.url.path not in {"/api/auth/logout", "/api/auth/step-up"}
        and policy.actor(identity)["role"] in PRIVILEGED_ROLES
        and getattr(request.state, "mfa_at", 0) < time.time() - STEP_UP_SECONDS):
        raise HTTPException(403, "Fresh MFA verification required; use auth step-up")


def step_up(request, code):
    identity = principal(request)
    token = getattr(request.state, "session_token", None)
    if not token:
        raise HTTPException(401, "A real session is required")
    now = time.time()
    with store.LOCK:
        bucket = "mfa:" + hashlib.sha256(identity.encode()).hexdigest()
        attempt = query_one("SELECT * FROM auth_attempts WHERE bucket=?", (bucket,))
        if attempt and attempt["window_start"] > now - 300 and attempt["failures"] >= 8:
            raise HTTPException(429, "Too many verification attempts")
        if not _verify_otp(identity, code, now):
            failures = attempt["failures"] + 1 if attempt and attempt["window_start"] > now - 300 else 1
            start = attempt["window_start"] if failures > 1 else now
            execute_write("INSERT OR REPLACE INTO auth_attempts VALUES(?,?,?)", (bucket, failures, start))
            raise HTTPException(401, "Invalid or reused verification code")
        execute_write("UPDATE auth_sessions SET mfa_at=? WHERE token_hash=?", (now, hashlib.sha256(token.encode()).hexdigest()))
    return {"verified": True, "valid_until": now + STEP_UP_SECONDS}


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
