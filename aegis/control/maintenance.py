"""Audited expiry archival; immutable tombstones prevent record resurrection."""

import json
import math
import time

from aegis.control import store
from aegis.storage.database import get_db_connection, query_all

OBJECT_QUOTA = 4096
DOMAINS = {
    "approval": ("seal", "approval-v1"),
    "lease": ("signature", "purpose-lease"),
    "coding-lease": ("seal", "coding:lease"),
    "coding-task": ("seal", "coding:task"),
    "advisory-lease": ("seal", "advisory:lease"),
    "advisory-task": ("seal", "advisory:task"),
    "media-job": ("seal", "media-job"),
    "coding-export-request": ("seal", "coding:export-request"),
}


def quotas():
    return [
        {**row, "limit": OBJECT_QUOTA, "needs_archive": row["count"] >= OBJECT_QUOTA * 3 // 4}
        for row in query_all("SELECT kind,COUNT(*) AS count FROM control_objects GROUP BY kind")
    ]


def archive_expired(identity="system", *, kind=None, force=False):
    """Keep receipts/revocations, retain signed content-free archival commitments."""
    now = time.time()
    archived = 0
    with store.LOCK:
        selected = [
            row["kind"]
            for row in quotas()
            if row["kind"] in DOMAINS
            and (kind is None or row["kind"] == kind)
            and (force or row["needs_archive"])
        ]
        for category in selected:
            eligible = []
            field, domain = DOMAINS[category]
            for row in query_all(
                "SELECT id,body FROM control_objects WHERE kind=? ORDER BY id", (category,)
            ):
                value = json.loads(row["body"])
                if value.get("id") != row["id"]:
                    raise store.Denied(
                        "ARCHIVE_INTEGRITY_FAILURE", "Expired record identity is inconsistent"
                    )
                if (
                    value.get("ciphertext")
                    or value.get("wrapped_key")
                    or value.get("status") == "RUNNING"
                ):
                    continue
                expires = value.get("expires_at")
                if category == "coding-export-request":
                    approval = store.get("approval", value["id"])
                    if approval is None:
                        # Only an already archived approval may make this reference stale.
                        archived_approval = query_all(
                            "SELECT body FROM control_archives WHERE kind='approval' AND id=?",
                            (value["id"],),
                        )
                        expires = None
                        if archived_approval:
                            tombstone = json.loads(archived_approval[0]["body"])
                            body = {k: v for k, v in tombstone.items() if k != "seal"}
                            if (
                                body.get("kind") != "approval"
                                or body.get("id") != value["id"]
                                or not store.verify_signature(
                                    body, "object-archive-v1", tombstone.get("seal")
                                )
                            ):
                                raise store.Denied(
                                    "ARCHIVE_INTEGRITY_FAILURE",
                                    "Archived approval has an invalid seal",
                                )
                            expires = 0
                    else:
                        body = {k: v for k, v in approval.items() if k != "seal"}
                        if approval.get("id") != value["id"] or not store.verify_signature(
                            body, "approval-v1", approval.get("seal")
                        ):
                            raise store.Denied(
                                "ARCHIVE_INTEGRITY_FAILURE", "Approval has an invalid seal"
                            )
                        expires = approval.get("expires_at")
                if expires is None and value.get("status") in {"FAILED", "BLOCKED", "CLOSED"}:
                    created = value.get("created_at")
                    expires = created + 86400 if type(created) in {float, int} else None
                if type(expires) not in {float, int} or not math.isfinite(expires) or expires > now:
                    continue
                body = {k: v for k, v in value.items() if k != field}
                if not store.verify_signature(body, domain, value.get(field)):
                    raise store.Denied(
                        "ARCHIVE_INTEGRITY_FAILURE", "Expired record has an invalid seal"
                    )
                eligible.append(
                    {"kind": category, "id": value["id"], "body_hash": store.digest(value)}
                )
            if not eligible:
                continue
            # Commit and independently witness the exact deletion plan BEFORE
            # changing operational rows. A crash leaves extra inactive rows,
            # never unwitnessed deletion or an ahead-of-database witness.
            receipt = store.receipt(
                "EXPIRED_OBJECTS_ARCHIVED",
                identity,
                kind=category,
                count=len(eligible),
                records_hash=store.digest(eligible),
            )
            with get_db_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                for item in eligible:
                    row = conn.execute(
                        "SELECT body FROM control_objects WHERE kind=? AND id=?",
                        (category, item["id"]),
                    ).fetchone()
                    if row is None or store.digest(json.loads(row["body"])) != item["body_hash"]:
                        raise store.Denied(
                            "ARCHIVE_INTEGRITY_FAILURE", "Record changed during archival"
                        )
                    body = {**item, "archived_at": now, "receipt_id": receipt["id"]}
                    tombstone = {**body, "seal": store.sign(body, "object-archive-v1")}
                    conn.execute(
                        "INSERT INTO control_archives VALUES(?,?,?)",
                        (category, item["id"], store.canonical(tombstone)),
                    )
                    conn.execute(
                        "DELETE FROM control_objects WHERE kind=? AND id=?", (category, item["id"])
                    )
            archived += len(eligible)
    return {"archived": archived, "quotas": quotas(), "receipt_history": "PRESERVED"}
