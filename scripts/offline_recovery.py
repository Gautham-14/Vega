"""Root-only coherent production archive without exposing keys to the API UID."""

import argparse
import base64
import json
import os
import sqlite3
import tempfile
from getpass import getpass
from pathlib import Path

from aegis.security.key_custody import canonical, load
from aegis.security.private_files import no_links
from aegis.security.quiescence import exclusive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-data", required=True)
    parser.add_argument("--broker-keyring", required=True)
    parser.add_argument("--archive", required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError(
            "Production recovery export requires the offline Linux host administrator"
        )
    source, archive = no_links(args.runtime_data), no_links(args.archive)
    if archive.is_relative_to(source) or archive.exists():
        raise ValueError("Use a new archive outside live runtime storage")
    password = getpass("New backup passphrase (16-256 characters): ")
    if password != getpass("Confirm backup passphrase: "):
        raise ValueError("Backup passphrases do not match")
    with exclusive("offline production recovery export", source / "runtime.lock"):
        with tempfile.TemporaryDirectory(prefix=".aegis-recovery-", dir=archive.parent) as staging:
            stage = Path(staging)
            ring = load(args.broker_keyring)
            (stage / "control.keys.json").write_text(canonical(ring.value))
            (stage / "control.keys.json").chmod(0o600)
            legacy = base64.b64decode(ring.value["legacy"]) if ring.value["legacy"] else bytes(32)
            (stage / "control.key").write_bytes(legacy)
            (stage / "control.key").chmod(0o600)
            (stage / "db").mkdir(mode=0o700)
            database = no_links(source / "db" / "aegis.db")
            with (
                sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as original,
                sqlite3.connect(stage / "db" / "aegis.db") as copied,
            ):
                original.backup(copied)
            total = entries = 0
            for name in ("knowledge", "receipts", "artifacts"):
                root = no_links(source / name)
                if not root.exists():
                    continue
                for path in root.rglob("*"):
                    path = no_links(path)
                    entries += 1
                    if entries > 20000:
                        raise ValueError("Recovery inventory exceeds limit")
                    target = stage / path.relative_to(source)
                    if path.is_dir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    total += path.stat().st_size
                    if not path.is_file() or total > 128 * 1024 * 1024:
                        raise ValueError("Recovery contents exceed bounded archive limit")
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with path.open("rb") as incoming, target.open("xb") as outgoing:
                        while chunk := incoming.read(1024 * 1024):
                            outgoing.write(chunk)
                    target.chmod(0o600)
            # Import runtime configuration only after selecting administrator-
            # owned staging, preserving the live directory's ownership/ACLs.
            os.environ["AEGIS_DATA_DIR"] = staging
            os.environ.pop("AEGIS_KEY_BROKER_SOCKET", None)
            os.environ.pop("AEGIS_RECOVERY_KEYRING", None)
            from aegis.security.recovery import create_backup

            print(json.dumps(create_backup(archive, password), sort_keys=True))


if __name__ == "__main__":
    main()
