"""Independent, durable, monotonic receipt witness using content-free hashes.

The witness cannot prove that a compromised application recorded honest events.
It detects rollback/forks relative to commitments it has already acknowledged.
It never resets an installation or accepts a caller-selected witness key.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from contextlib import contextmanager

from aegis.security.private_files import no_links, restrict_permissions

ZERO = "0" * 64


class Witness:
    def __init__(self, path):
        self.path = no_links(path)
        self.lock = threading.RLock()
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS anchor (installation TEXT PRIMARY KEY, sequence INTEGER NOT NULL, hash TEXT NOT NULL)")
        restrict_permissions(self.path)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(no_links(self.path), timeout=5)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA trusted_schema=OFF")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def dispatch(self, request):
        op = request.get("operation")
        expected = {"operation", "installation"} | ({"commitments"} if op == "advance" else set())
        if op not in {"status", "advance"} or set(request) != expected:
            raise ValueError("Invalid witness operation")
        installation = request["installation"]
        if not isinstance(installation, str) or not re.fullmatch(r"[a-f0-9]{32}", installation):
            raise ValueError("Installation requires a host-provisioned identity")
        with self.lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT sequence,hash FROM anchor WHERE installation=?", (installation,)).fetchone()
            if row is None:
                # Enrollment is an offline administrative operation, never RPC.
                raise ValueError("Installation is not enrolled in this witness")
            sequence, digest = row
            if op == "advance":
                items = request["commitments"]
                if not isinstance(items, list) or not 1 <= len(items) <= 256:
                    raise ValueError("Witness updates require 1-256 contiguous commitments")
                for item in items:
                    if (not isinstance(item, dict) or set(item) != {"sequence", "hash", "previous"}
                        or type(item["sequence"]) is not int or item["sequence"] != sequence + 1
                        or item["previous"] != digest or not isinstance(item["hash"], str)
                        or not re.fullmatch(r"[a-f0-9]{64}", item["hash"])):
                        raise ValueError("Witness refuses a rollback, gap or fork")
                    sequence, digest = item["sequence"], item["hash"]
                conn.execute("UPDATE anchor SET sequence=?,hash=? WHERE installation=?", (sequence, digest, installation))
            return {"installation": installation, "sequence": sequence, "hash": digest}

    def enroll(self, installation, sequence=0, digest=ZERO):
        if not re.fullmatch(r"[a-f0-9]{32}", installation) or type(sequence) is not int or sequence < 0 or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid initial audit commitment")
        if sequence == 0 and digest != ZERO:
            raise ValueError("Empty ledger must use the genesis hash")
        with self.lock, self.connect() as conn:
            conn.execute("INSERT INTO anchor VALUES(?,?,?)", (installation, sequence, digest))


def configured():
    return bool(os.environ.get("AEGIS_AUDIT_WITNESS_SOCKET"))


def remote(operation, **extra):
    from aegis.security.local_rpc import call
    return call(os.environ["AEGIS_AUDIT_WITNESS_SOCKET"], int(os.environ["AEGIS_AUDIT_WITNESS_UID"]),
        {"operation": operation, "installation": os.environ["AEGIS_INSTALLATION_ID"], **extra})


def synchronize(conn, head):
    """Caller has verified the complete local chain before publishing anything."""
    if not configured():
        return False
    anchor = remote("status")
    local_sequence = head["sequence"] if head else 0
    if type(anchor.get("sequence")) is not int or anchor["sequence"] < 0 or anchor["sequence"] > local_sequence:
        raise RuntimeError("Audit witness detects a rolled-back local ledger")
    previous = ZERO if anchor["sequence"] == 0 else conn.execute(
        "SELECT hash FROM control_receipts WHERE sequence=?", (anchor["sequence"],)).fetchone()
    previous = previous if isinstance(previous, str) else previous[0] if previous else None
    if previous != anchor.get("hash"):
        raise RuntimeError("Audit witness detects a forked local ledger")
    cursor = conn.execute("SELECT sequence,body,hash FROM control_receipts WHERE sequence>? ORDER BY sequence", (anchor["sequence"],))
    while True:
        rows = cursor.fetchmany(256)
        if not rows:
            break
        items = [{"sequence": row["sequence"], "hash": row["hash"],
                  "previous": json.loads(row["body"])["previous_receipt_hash"]} for row in rows]
        response = remote("advance", commitments=items)
        if response.get("sequence") != items[-1]["sequence"] or response.get("hash") != items[-1]["hash"]:
            raise RuntimeError("Audit witness did not acknowledge the local commitment")
    return True


def main():
    parser = argparse.ArgumentParser(description="Independent audit witness administration")
    parser.add_argument("action", choices=("enroll", "serve"))
    parser.add_argument("--database", required=True)
    parser.add_argument("--installation")
    parser.add_argument("--sequence", type=int, default=0)
    parser.add_argument("--hash", default=ZERO)
    parser.add_argument("--socket")
    parser.add_argument("--runtime-uid", type=int)
    args = parser.parse_args()
    witness = Witness(args.database)
    if args.action == "enroll":
        witness.enroll(args.installation, args.sequence, args.hash)
    else:
        from aegis.security.local_rpc import serve
        serve(args.socket, args.runtime_uid, witness.dispatch)


if __name__ == "__main__":
    main()
