"""Bounded, content-free event persistence shared by scanner and control gates."""

import hashlib
import re
import uuid

from aegis.storage.database import get_db_connection

MAX_EVENTS = 4000


def safe_reference(value):
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value):
        return value
    return "sha256-" + hashlib.sha256(str(value).encode()).hexdigest()


def record(code, reference="", *, action="BLOCKED", severity="HIGH", rules=None):
    from aegis.security.availability import storage_budget

    storage_budget()
    code = safe_reference(code)
    reference = safe_reference(reference) if reference else ""
    identity = "SEC-" + uuid.uuid4().hex
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO security_events(id,event_type,severity,description,source_document,"
            "matched_rule,raw_payload,action_taken) VALUES(?,?,?,?,?,?,NULL,?)",
            (
                identity,
                code,
                severity,
                code.replace("_", " "),
                reference,
                (rules or "")[:1000],
                safe_reference(action),
            ),
        )
        conn.execute(
            "DELETE FROM security_events WHERE rowid NOT IN "
            "(SELECT rowid FROM security_events ORDER BY rowid DESC LIMIT ?)",
            (MAX_EVENTS,),
        )
    return identity
