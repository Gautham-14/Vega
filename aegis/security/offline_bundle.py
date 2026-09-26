"""Verify signed offline model files without executing or importing them.

The trust policy and public key are provisioned separately from the bundle.
Successful verification proves file identity at inspection time, not that a
server loaded those bytes or that the model is safe to use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.security.private_files import no_links


SCHEMA = "aegis-offline-model-bundle-v1"
POLICY_SCHEMA = "aegis-offline-model-trust-v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_FILES = 20_000
MAX_FILE_BYTES = 16 * 1024**4
HEX64 = r"^[0-9a-f]{64}$"
ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$"
UNSAFE_SUFFIXES = {".py", ".pyc", ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib",
                   ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".js", ".jar"}
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _read_json(path: Path, limit: int) -> tuple[dict, bytes]:
    path = no_links(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Manifest or trust policy is missing or too large")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Manifest or trust policy is too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Manifest or trust policy is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Manifest or trust policy must be a JSON object")
    return value, raw


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _safe_relative(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or ":" in value
            or any(ord(char) < 32 for char in value)):
        raise ValueError("Bundle file path is invalid")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(part.rstrip(" .") != part or part.split(".")[0].upper() in RESERVED for part in path.parts)):
        raise ValueError("Bundle file path is unsafe")
    if path.suffix.lower() in UNSAFE_SUFFIXES:
        raise ValueError("Executable model serialization or script is not accepted")
    if value in {"manifest.json", "manifest.sig"}:
        raise ValueError("Bundle metadata cannot be declared as a model file")
    return value


class BundleFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str
    size: int = Field(ge=1, le=MAX_FILE_BYTES)
    sha256: str = Field(pattern=HEX64)
    role: Literal["weights", "tokenizer", "projector", "runtime", "license", "config", "evaluation"]

    @model_validator(mode="after")
    def safe_path(self):
        _safe_relative(self.path)
        suffix = PurePosixPath(self.path).suffix.lower()
        if self.role in {"weights", "projector"} and suffix not in {".gguf", ".safetensors"}:
            raise ValueError("Model weights must use GGUF or safetensors")
        return self


class BundleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[SCHEMA]
    bundle_id: str = Field(pattern=ID)
    model_family: str = Field(pattern=ID)
    version: int = Field(ge=1)
    signer_id: str = Field(pattern=ID)
    license_id: str = Field(min_length=1, max_length=120)
    modality: Literal["text", "vision", "image-generation", "embedding"]
    tokenizer_mode: Literal["embedded", "file"]
    runtime_entry: str
    files: list[BundleFile] = Field(min_length=3, max_length=MAX_FILES)

    @model_validator(mode="after")
    def complete_file_set(self):
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len({name.casefold() for name in paths}) != len(paths):
            raise ValueError("Bundle files must be sorted and have unique case-insensitive paths")
        roles = {item.role for item in self.files}
        if not {"weights", "runtime", "license"} <= roles:
            raise ValueError("Bundle requires weights, runtime and license files")
        if self.tokenizer_mode == "file" and "tokenizer" not in roles:
            raise ValueError("External tokenizer file is missing")
        if self.modality == "vision" and "projector" not in roles:
            raise ValueError("Vision projector file is missing")
        _safe_relative(self.runtime_entry)
        if PurePosixPath(self.runtime_entry).suffix.lower() != ".exe":
            raise ValueError("Windows runtime entry must be an executable file")
        if not any(item.path == self.runtime_entry and item.role == "runtime" for item in self.files):
            raise ValueError("Runtime entry must identify a declared runtime file")
        return self


class TrustedSigner(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    public_key_path: str
    public_key_sha256: str = Field(pattern=HEX64)


class TrustPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[POLICY_SCHEMA]
    signers: dict[str, TrustedSigner] = Field(min_length=1)
    minimum_versions: dict[str, int] = Field(min_length=1)
    allowed_license_ids: list[str] = Field(min_length=1)
    revoked_manifest_sha256: list[str] = Field(default_factory=list)
    expires_at: int = Field(gt=0)

    @model_validator(mode="after")
    def valid_policy(self):
        if any(not re.fullmatch(ID, name) for name in (*self.signers, *self.minimum_versions)):
            raise ValueError("Trust policy identifiers are invalid")
        if any(type(version) is not int or version < 1 for version in self.minimum_versions.values()):
            raise ValueError("Minimum versions must be positive integers")
        if any(not re.fullmatch(HEX64, item) for item in self.revoked_manifest_sha256):
            raise ValueError("Revoked manifest digest is invalid")
        return self


def _regular_file(path: Path) -> os.stat_result:
    no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Bundle contains a link or non-regular file")
    return info


def _sha256_file(path: Path, expected_size: int) -> str:
    before = _regular_file(path)
    if before.st_size != expected_size:
        raise ValueError("Bundle file size differs from signed manifest")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError("Bundle file changed while opening")
        read_size = 0
        while block := stream.read(min(1024 * 1024, expected_size - read_size + 1)):
            read_size += len(block)
            if read_size > expected_size:
                raise ValueError("Bundle file grew while hashing")
            digest.update(block)
        closed = os.fstat(stream.fileno())
    after = _regular_file(path)
    fields = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if fields(before) != fields(opened) or fields(opened) != fields(closed) or fields(closed) != fields(after):
        raise ValueError("Bundle file changed while hashing")
    return digest.hexdigest()


def verify_bundle(bundle_dir: str | Path, trust_policy_path: str | Path) -> dict:
    """Verify signature, anti-rollback policy, and every file; do not execute code."""
    root, policy_path = no_links(bundle_dir), no_links(trust_policy_path)
    if not root.is_dir() or policy_path.is_relative_to(root):
        raise ValueError("Trust policy must be provisioned outside the bundle")
    policy_json, policy_raw = _read_json(policy_path, MAX_POLICY_BYTES)
    _regular_file(policy_path)
    policy = TrustPolicy.model_validate(policy_json)
    if int(time.time()) >= policy.expires_at:
        raise ValueError("Offline trust policy expired")
    manifest_json, manifest_raw = _read_json(root / "manifest.json", MAX_MANIFEST_BYTES)
    manifest = BundleManifest.model_validate(manifest_json)
    if manifest_raw != canonical_bytes(manifest_json):
        raise ValueError("Manifest must use canonical UTF-8 JSON")
    manifest_hash = hashlib.sha256(manifest_raw).hexdigest()
    if manifest_hash in policy.revoked_manifest_sha256:
        raise ValueError("Bundle manifest is revoked")
    minimum = policy.minimum_versions.get(manifest.model_family)
    if minimum is None or manifest.version < minimum:
        raise ValueError("Bundle version is below the trusted minimum")
    if manifest.license_id not in policy.allowed_license_ids:
        raise ValueError("License identifier has not been approved in the trust policy")
    signer = policy.signers.get(manifest.signer_id)
    if signer is None:
        raise ValueError("Bundle signer is not trusted")
    if not Path(signer.public_key_path).is_absolute():
        raise ValueError("Trusted public key path must be absolute")
    key_path = no_links(signer.public_key_path)
    if key_path.is_relative_to(root):
        raise ValueError("Trusted public key must be outside the bundle")
    if _regular_file(key_path).st_size > 16_384:
        raise ValueError("Trusted public key is too large")
    with key_path.open("rb") as stream:
        key_pem = stream.read(16_385)
    if len(key_pem) > 16_384:
        raise ValueError("Trusted public key is too large")
    key = serialization.load_pem_public_key(key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Trusted signer must use an Ed25519 public key")
    raw_key = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if hashlib.sha256(raw_key).hexdigest() != signer.public_key_sha256:
        raise ValueError("Trusted public key fingerprint mismatch")
    signature_path = root / "manifest.sig"
    _regular_file(signature_path)
    with signature_path.open("rb") as stream:
        signature_raw = stream.read(129)
    if len(signature_raw) > 128:
        raise ValueError("Bundle signature is too large")
    try:
        signature = base64.b64decode(signature_raw, validate=True)
        key.verify(signature, manifest_raw)
    except (ValueError, InvalidSignature) as error:
        raise ValueError("Bundle signature verification failed") from error
    expected = {"manifest.json", "manifest.sig", *(item.path for item in manifest.files)}
    actual = set()
    visited = 0
    def unreadable(error):
        raise ValueError("Bundle inventory could not be completely read") from error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        visited += 1
        if visited + len(dirs) + len(files) + len(actual) > MAX_FILES * 2 + 2:
            raise ValueError("Bundle inventory exceeds entry limit")
        for name in (*dirs, *files):
            item = Path(parent) / name
            no_links(item)
            if item.is_file():
                _regular_file(item)
                actual.add(item.relative_to(root).as_posix())
            elif not item.is_dir():
                raise ValueError("Bundle contains a non-regular entry")
    if actual != expected:
        raise ValueError("Bundle contains missing or undeclared files")
    total = 0
    for item in manifest.files:
        path = root.joinpath(*PurePosixPath(item.path).parts)
        if _sha256_file(path, item.size) != item.sha256:
            raise ValueError("Bundle file hash differs from signed manifest")
        total += item.size
    if (_sha256_file(root / "manifest.json", len(manifest_raw)) != manifest_hash
            or _sha256_file(signature_path, len(signature_raw)) != hashlib.sha256(signature_raw).hexdigest()
            or _sha256_file(policy_path, len(policy_raw)) != hashlib.sha256(policy_raw).hexdigest()
            or _sha256_file(key_path, len(key_pem)) != hashlib.sha256(key_pem).hexdigest()):
        raise ValueError("Bundle signature or trust root changed during verification")
    return {"status": "VERIFIED_OFFLINE_FILES", "bundle_id": manifest.bundle_id,
            "model_family": manifest.model_family, "version": manifest.version,
            "modality": manifest.modality, "manifest_sha256": manifest_hash,
            "trust_policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
            "signer_public_key_sha256": signer.public_key_sha256,
            "file_count": len(manifest.files), "file_bytes": total,
            "signature_verified": True, "artifact_integrity_verified": True,
            "license_identifier_allowlisted": True,
            "runtime_binding_verified": False, "model_qualification_verified": False,
            "network_isolation_verified": False, "production_eligible": False}
