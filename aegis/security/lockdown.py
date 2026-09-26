"""Local incident stop; never claims to kill an external process or erase RAM."""
import hmac
import json
import time

from aegis.control import policy, store
from aegis.storage.database import query_one

ACTION = "EXECUTION_LOCKDOWN_CHANGED"


def status():
    with store.LOCK:
        # Check even when the state is absent: deleting the state and its receipt
        # must not make a damaged ledger look like a fresh, unlocked installation.
        if not store.verify_chain(record_failure=False)["is_valid"]:
            raise store.Denied("LOCKDOWN_INTEGRITY_FAILURE", "Incident-control ledger is damaged; execution is withheld")
        value = store.get("execution-lockdown", "global")
        latest = query_one("SELECT body FROM control_receipts WHERE json_extract(body,'$.action')=? ORDER BY sequence DESC LIMIT 1", (ACTION,))
        if value is None and latest is None:
            return {"enabled": False, "generation": 0, "scope": "APPLICATION_EXECUTION_ONLY"}
        body = {k: v for k, v in (value or {}).items() if k != "seal"}
        if (value is None or latest is None or type(body.get("enabled")) is not bool
                or type(body.get("generation")) is not int or body["generation"] < 1
                or not isinstance(value.get("seal"), str)
                or not hmac.compare_digest(value["seal"], store.sign(body, "execution-lockdown"))
                or json.loads(latest["body"]).get("state_hash") != store.digest(body)):
            raise store.Denied("LOCKDOWN_INTEGRITY_FAILURE", "Incident-control state is missing or changed; execution is withheld")
        return body


def check(generation=None):
    value = status()
    if value["enabled"]:
        raise store.Denied("EXECUTION_LOCKED", "Security Officer lockdown blocks model calls, execution and content release")
    if generation is not None and generation != value["generation"]:
        raise store.Denied("EXECUTION_AUTHORIZATION_REVOKED", "Incident-control state changed; obtain fresh authorization")
    return value["generation"]


def change(enabled, identity):
    policy.actor(identity, ["Security Officer"])
    if type(enabled) is not bool:
        raise ValueError("Lockdown enabled must be a boolean")
    with store.LOCK:
        previous = status()
        if previous["enabled"] == enabled:
            return previous
        body = {"enabled": enabled, "generation": previous["generation"] + 1,
                "changed_at": time.time(), "changed_by": identity, "scope": "APPLICATION_EXECUTION_ONLY"}
        # A crash between these durable writes produces a mismatch and blocks work.
        store.receipt(ACTION, identity, state_hash=store.digest(body), enabled=enabled, generation=body["generation"])
        store.put("execution-lockdown", "global", {**body, "seal": store.sign(body, "execution-lockdown")})
        return body
