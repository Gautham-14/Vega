"""Irreversible authorization revocation witnessed by the authenticated ledger."""

from aegis.control import store
from aegis.storage.database import query_one


def revoked(kind, identity):
    # lockdown.check verifies the ledger before authorization uses this helper.
    return (
        query_one(
            "SELECT sequence FROM control_receipts WHERE "
            "json_extract(body,'$.action')='AUTHORIZATION_REVOKED' AND "
            "json_extract(body,'$.authorization_hash')=? LIMIT 1",
            (store.digest({"kind": kind, "id": identity}),),
        )
        is not None
    )


def record(kind, identity, actor):
    if not revoked(kind, identity):
        store.receipt(
            "AUTHORIZATION_REVOKED",
            actor,
            authorization_hash=store.digest({"kind": kind, "id": identity}),
        )
