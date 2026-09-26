"""Signed offline bundles protect actual files, not just metadata strings."""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.security.offline_bundle import SCHEMA, POLICY_SCHEMA, canonical_bytes, verify_bundle


def bundle_fixture(tmp_path, *, modality="text", tokenizer_mode="embedded"):
    root = tmp_path / "bundle"
    root.mkdir()
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    key_file = tmp_path / "trusted-publisher.pem"
    key_file.write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    contents = {
        "LICENSE.txt": (b"reviewed test license", "license"),
        "runtime/server.exe": (b"test runtime fixture", "runtime"),
        "weights/model.gguf": (b"test model bytes", "weights"),
    }
    if tokenizer_mode == "file":
        contents["tokenizer/tokenizer.json"] = (b'{"vocab":{}}', "tokenizer")
    if modality == "vision":
        contents["weights/projector.gguf"] = (b"test projector bytes", "projector")
    files = []
    for name, (content, role) in sorted(contents.items()):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files.append({"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest(), "role": role})
    manifest = {"schema_version": SCHEMA, "bundle_id": "fixture-v1", "model_family": "fixture",
                "version": 1, "signer_id": "publisher", "license_id": "MIT",
                "modality": modality, "tokenizer_mode": tokenizer_mode,
                "runtime_entry": "runtime/server.exe", "files": files}
    raw = canonical_bytes(manifest)
    (root / "manifest.json").write_bytes(raw)
    (root / "manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))
    policy = {"schema_version": POLICY_SCHEMA,
              "signers": {"publisher": {"public_key_path": str(key_file), "public_key_sha256": fingerprint}},
              "minimum_versions": {"fixture": 1}, "allowed_license_ids": ["MIT"],
              "revoked_manifest_sha256": [], "expires_at": int(time.time()) + 3600}
    trust_file = tmp_path / "trust-policy.json"
    trust_file.write_bytes(canonical_bytes(policy))
    return root, trust_file, key, manifest, policy


def resign(root, key, manifest):
    raw = canonical_bytes(manifest)
    (root / "manifest.json").write_bytes(raw)
    (root / "manifest.sig").write_bytes(base64.b64encode(key.sign(raw)))


def test_signed_bundle_checks_real_bytes_and_keeps_runtime_unverified(tmp_path):
    root, trust, _, _, _ = bundle_fixture(tmp_path, modality="vision", tokenizer_mode="file")
    result = verify_bundle(root, trust)
    assert result["signature_verified"] and result["artifact_integrity_verified"]
    assert result["file_count"] == 5
    assert result["runtime_binding_verified"] is False
    assert result["model_qualification_verified"] is False
    assert result["network_isolation_verified"] is False
    assert result["production_eligible"] is False


def test_cli_verifies_bundle_without_server_or_private_key(tmp_path):
    import aegis_cli
    root, trust, _, _, _ = bundle_fixture(tmp_path)
    args = aegis_cli.build_parser().parse_args(["bundle-verify", str(root), "--trust-policy", str(trust)])
    assert aegis_cli.execute(args, None)["status"] == "VERIFIED_OFFLINE_FILES"


def test_offline_staging_signs_exact_files_with_encrypted_key(tmp_path):
    from scripts.stage_offline_model_bundle import stage
    root, trust, key, manifest, _ = bundle_fixture(tmp_path)
    (root / "manifest.json").unlink()
    (root / "manifest.sig").unlink()
    draft = {**manifest, "files": [{"path": item["path"], "role": item["role"]} for item in manifest["files"]]}
    draft_file = tmp_path / "draft.json"
    draft_file.write_bytes(canonical_bytes(draft))
    private = tmp_path / "offline-private.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(b"staging-only-passphrase")))
    result = stage(root, draft_file, private, b"staging-only-passphrase")
    assert result["private_key_copied"] is False
    assert verify_bundle(root, trust)["artifact_integrity_verified"] is True
    assert not (root / private.name).exists()


@pytest.mark.parametrize("mutation,expected", [
    ("weight", "hash"),
    ("signature", "signature"),
    ("extra", "undeclared"),
    ("missing", "missing"),
    ("rollback", "minimum"),
    ("revoked", "revoked"),
    ("key", "fingerprint"),
    ("license", "License"),
    ("expired", "expired"),
])
def test_bundle_rejects_tampering_and_invalid_trust_policy(tmp_path, mutation, expected):
    root, trust, _, manifest, policy = bundle_fixture(tmp_path)
    if mutation == "weight":
        (root / "weights/model.gguf").write_bytes(b"modified weights")
    elif mutation == "signature":
        (root / "manifest.sig").write_bytes(base64.b64encode(b"x" * 64))
    elif mutation == "extra":
        (root / "unexpected.txt").write_text("extra")
    elif mutation == "missing":
        (root / "LICENSE.txt").unlink()
    elif mutation == "rollback":
        policy["minimum_versions"]["fixture"] = 2
    elif mutation == "revoked":
        policy["revoked_manifest_sha256"].append(hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest())
    elif mutation == "key":
        policy["signers"]["publisher"]["public_key_sha256"] = "0" * 64
    elif mutation == "license":
        policy["allowed_license_ids"] = ["OTHER"]
    elif mutation == "expired":
        policy["expires_at"] = int(time.time()) - 1
    trust.write_bytes(canonical_bytes(policy))
    with pytest.raises(ValueError, match=expected):
        verify_bundle(root, trust)


@pytest.mark.parametrize("path", ["../escape.gguf", "weights\\escape.gguf", "C:/model.gguf",
                                    "weights/CON.gguf", "weights/model.pkl", "manifest.json"])
def test_signed_manifest_cannot_authorize_unsafe_paths(tmp_path, path):
    root, trust, key, manifest, _ = bundle_fixture(tmp_path)
    manifest["files"][-1]["path"] = path
    manifest["files"].sort(key=lambda item: item["path"])
    resign(root, key, manifest)
    with pytest.raises(ValueError):
        verify_bundle(root, trust)


def test_bundle_rejects_links_and_undeclared_substitutions(tmp_path):
    root, trust, _, _, _ = bundle_fixture(tmp_path)
    target = root / "weights/model.gguf"
    target.unlink()
    try:
        target.symlink_to(root / "LICENSE.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable to this Windows account")
    with pytest.raises(ValueError, match="link"):
        verify_bundle(root, trust)


def test_bundle_rejects_duplicate_json_keys(tmp_path):
    root, trust, _, _, _ = bundle_fixture(tmp_path)
    raw = (root / "manifest.json").read_bytes()
    (root / "manifest.json").write_bytes(raw.replace(b'{"bundle_id":', b'{"bundle_id":"shadow","bundle_id":', 1))
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        verify_bundle(root, trust)
