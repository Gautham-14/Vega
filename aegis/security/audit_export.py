"""Content-free commitments for a separately maintained offline audit anchor."""

from aegis.control import policy, store
from aegis.storage.database import get_db_connection


def snapshot(identity):
    policy.actor(identity, ["Auditor", "Security Officer"])
    with store.LOCK, get_db_connection() as conn:
        conn.execute("BEGIN")
        rows = conn.execute("SELECT * FROM control_receipts ORDER BY sequence").fetchall()
        head = conn.execute("SELECT * FROM control_head WHERE singleton=1").fetchone()
        if not store.verify_rows(rows, head):
            conn.rollback()
            raise store.Denied(
                "RECEIPT_CHAIN_FAILURE", "Cannot export commitments for a damaged chain"
            )
        from aegis.security.audit_anchor import synchronize

        anchored = synchronize(conn, head)
        return {
            "schema_version": "aegis-audit-commitments-v1",
            "count": len(rows),
            "commitments": [
                {"sequence": row["sequence"], "receipt_hash": row["hash"]} for row in rows
            ],
            "head": {"sequence": head["sequence"], "hash": head["hash"]} if head else None,
            "independently_anchored": anchored,
        }
