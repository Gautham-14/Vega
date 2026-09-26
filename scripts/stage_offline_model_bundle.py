"""Run on an offline staging computer, never on the Aegis inference host.

Reads an operator-reviewed draft manifest and an existing encrypted Ed25519
private key. Writes canonical manifest.json and detached manifest.sig into a
model bundle without copying the private key.
"""

from __future__ import annotations

import argparse
import base64
from getpass import getpass
import hashlib
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aegis.security.offline_bundle import (
    BundleManifest, MAX_MANIFEST_BYTES, _read_json, _regular_file, _safe_relative,
    _sha256_file, canonical_bytes,
)
from aegis.security.private_files import no_links


def stage(bundle_directory: str | Path, draft_path: str | Path, private_key_path: str | Path, password: bytes) -> dict:
    root, draft, secret = map(no_links, (bundle_directory, draft_path, private_key_path))
    if not root.is_dir() or draft.is_relative_to(root) or secret.is_relative_to(root):
        raise ValueError("Draft and private key must be outside the bundle directory")
    if (root / "manifest.json").exists() or (root / "manifest.sig").exists():
        raise ValueError("Staging never overwrites an existing signed manifest")
    if _regular_file(secret).st_size > 16_384:
        raise ValueError("Private key file is too large")
    key = serialization.load_pem_private_key(secret.read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Staging key must be Ed25519")
    draft_json, _ = _read_json(draft, MAX_MANIFEST_BYTES)
    declared = draft_json.get("files")
    if not isinstance(declared, list):
        raise ValueError("Draft must list bundle files and roles")
    files = []
    for item in declared:
        if not isinstance(item, dict) or set(item) != {"path", "role"}:
            raise ValueError("Draft file entries must contain path and role only")
        name = _safe_relative(item["path"])
        path = root.joinpath(*name.split("/"))
        size = _regular_file(path).st_size
        files.append({"path": name, "role": item["role"], "size": size, "sha256": _sha256_file(path, size)})
    manifest = {**draft_json, "files": files}
    BundleManifest.model_validate(manifest)
    raw = canonical_bytes(manifest)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("Signed manifest exceeds size limit")
    # Reject undeclared files before signing. The verifier repeats this check.
    actual = set()
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in (*dirs, *names):
            path = Path(parent) / name
            no_links(path)
            if path.is_file():
                _regular_file(path)
                actual.add(path.relative_to(root).as_posix())
    if actual != {item["path"] for item in files}:
        raise ValueError("Bundle contains missing or undeclared files")
    signature = base64.b64encode(key.sign(raw))
    manifest_path, signature_path = root / "manifest.json", root / "manifest.sig"
    with manifest_path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        with signature_path.open("xb") as stream:
            stream.write(signature)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        manifest_path.unlink(missing_ok=True)
        raise
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "signer_public_key_sha256": hashlib.sha256(public).hexdigest(),
            "file_count": len(files), "private_key_copied": False,
            "next_step": "Transfer only the bundle; provision public key and trust policy separately"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a reviewed offline model bundle on a separate staging computer")
    parser.add_argument("bundle_directory")
    parser.add_argument("--draft", required=True, help="Reviewed draft manifest JSON outside bundle")
    parser.add_argument("--private-key", required=True, help="Existing encrypted Ed25519 PEM outside bundle")
    args = parser.parse_args()
    password = getpass("Staging private-key passphrase: ").encode()
    try:
        print(stage(args.bundle_directory, args.draft, args.private_key, password))
        return 0
    except (OSError, ValueError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
