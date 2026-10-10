"""Build and verify signed, complete offline application releases and SBOMs."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import time
from importlib import metadata
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from aegis.security.private_files import no_links, restrict_permissions

DIRECTORIES = ("aegis", "scripts", "deploy", "evaluations")
MAX_FILES = 10000
SOURCE_SUFFIXES = {
    ".py",
    ".json",
    ".md",
    ".txt",
    ".lock",
    ".toml",
    ".service",
    ".socket",
    ".conf",
    ".rules",
    ".yml",
    ".yaml",
    ".sh",
    ".bat",
    ".command",
    ".ps1",
}


class ReleaseTrust(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    public_key_path: str = Field(min_length=1, max_length=512)
    public_key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    minimum_version: int = Field(ge=1)
    expires_at: float = Field(gt=0, allow_inf_nan=False)
    revoked_manifest_sha256: list[str] = Field(default_factory=list, max_length=10000)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def inventory(directory, *, metadata_files=False):
    directory = no_links(directory)
    result = []

    def unreadable(error):
        raise ValueError("Cannot completely inventory release") from error

    for current, dirs, files in os.walk(directory, followlinks=False, onerror=unreadable):
        for name in dirs + files:
            no_links(Path(current) / name)
        for name in files:
            path = no_links(Path(current) / name)
            relative = path.relative_to(directory).as_posix()
            if metadata_files and relative in {"release.json", "release.sig"}:
                continue
            if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("Release contains unsupported file")
            raw = path.read_bytes()
            result.append(
                {"path": relative, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            )
            if len(result) > MAX_FILES:
                raise ValueError("Release exceeds inventory limit")
    return sorted(result, key=lambda item: item["path"])


def sbom():
    components = sorted(
        [
            {
                "type": "library",
                "name": item.metadata["Name"],
                "version": item.version,
                "purl": "pkg:pypi/"
                + item.metadata["Name"].lower().replace("_", "-")
                + "@"
                + item.version,
            }
            for item in metadata.distributions()
        ],
        key=lambda item: item["name"].lower(),
    )
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}


def source_files(root):
    """Reject private/unknown files before reading their bytes into a release."""

    def unreadable(error):
        raise ValueError("Cannot completely inventory release source") from error

    count = 0
    for current, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in list(dirs):
            no_links(Path(current) / name)
            if name == "__pycache__":
                dirs.remove(name)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                continue
            path = no_links(Path(current) / name)
            lowered = name.lower()
            if (
                path.suffix not in SOURCE_SUFFIXES
                or lowered.startswith((".env", "control.key"))
                or ".private." in lowered
                or lowered in {"credentials.json", "secrets.json"}
            ):
                raise ValueError(
                    "Release source contains private or unsupported configuration; move it outside the source tree"
                )
            count += 1
            if count > MAX_FILES:
                raise ValueError("Release source exceeds file budget")
            yield path


def build(source, destination, private_key, version, epoch=None):
    source, destination, private_key = (
        no_links(source),
        no_links(destination),
        no_links(private_key),
    )
    if destination.exists() or destination.is_relative_to(source):
        raise ValueError("Build into a new directory outside the source tree")
    if type(version) is not int or version < 1:
        raise ValueError("Release version must be a positive monotonic integer")
    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Release signing requires Ed25519")
    candidates = [
        source / name
        for name in (
            "pyproject.toml",
            "run_aegis.py",
            "aegis.py",
            "Aegis.bat",
            "Aegis.command",
            "demo_pipeline.py",
            "LICENSE",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "ARCHITECTURE.md",
            "CONFIGURATION.md",
            "RELEASE.md",
            "VM_DEPLOYMENT.md",
            "LOCAL_MODELS.md",
            "WORKFLOW_VERIFICATION.md",
            "README.md",
            "QUICKSTART.md",
            "PROVIDER_ASSURANCE.md",
            "SECURITY_IMPLEMENTATION.md",
        )
        if (source / name).exists()
    ]
    candidates += [
        path
        for pattern in ("requirements*.txt", "requirements*.lock")
        for path in source.glob(pattern)
    ]
    for name in DIRECTORIES:
        root = source / name
        if not root.exists():
            continue
        candidates.extend(source_files(root))
    destination.mkdir(mode=0o700)
    for path in candidates:
        no_links(path)
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    (destination / "sbom.json").write_bytes(canonical(sbom()))
    body = {
        "schema_version": "aegis-application-release-v1",
        "version": version,
        "created_at": int(
            epoch if epoch is not None else os.environ.get("SOURCE_DATE_EPOCH", int(time.time()))
        ),
        "files": inventory(destination),
    }
    raw = canonical(body)
    (destination / "release.json").write_bytes(raw)
    (destination / "release.sig").write_bytes(base64.b64encode(key.sign(raw)))
    return {
        "directory": str(destination),
        "version": version,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "files": len(body["files"]),
    }


def verify(directory, policy_path):
    directory, policy_path = no_links(directory), no_links(policy_path)
    if policy_path.is_relative_to(directory):
        raise ValueError("Release trust must be provisioned separately")
    from aegis.security.offline_bundle import _read_json

    policy = ReleaseTrust.model_validate(_read_json(policy_path, 256 * 1024)[0]).model_dump()
    if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in policy["revoked_manifest_sha256"]):
        raise ValueError("Invalid release revocation digest")
    key_path = no_links(policy["public_key_path"])
    if key_path.is_relative_to(directory) or not Path(policy["public_key_path"]).is_absolute():
        raise ValueError("Publisher key must be separately provisioned")
    if key_path.stat().st_size > 16384:
        raise ValueError("Publisher key exceeds limit")
    key = serialization.load_pem_public_key(key_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Release publisher requires Ed25519")
    fingerprint = hashlib.sha256(
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    if fingerprint != policy["public_key_sha256"] or policy["expires_at"] <= time.time():
        raise ValueError("Publisher trust is invalid or expired")
    path = no_links(directory / "release.json")
    signature = no_links(directory / "release.sig")
    if path.stat().st_size > 2 * 1024 * 1024 or signature.stat().st_size > 128:
        raise ValueError("Release metadata exceeds limit")
    body, raw = _read_json(path, 2 * 1024 * 1024)
    key.verify(base64.b64decode(signature.read_bytes(), validate=True), raw)
    digest = hashlib.sha256(raw).hexdigest()
    if (
        body.get("schema_version") != "aegis-application-release-v1"
        or type(body.get("version")) is not int
        or body["version"] < policy["minimum_version"]
        or digest in policy.get("revoked_manifest_sha256", [])
    ):
        raise ValueError("Release is revoked, rolled back or unsupported")
    if inventory(directory, metadata_files=True) != body["files"]:
        raise ValueError("Release contains changed, missing or extra files")
    return {"valid": True, "version": body["version"], "manifest_sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build")
    make.add_argument("source")
    make.add_argument("destination")
    make.add_argument("--private-key", required=True)
    make.add_argument("--version", required=True, type=int)
    check = commands.add_parser("verify")
    check.add_argument("directory")
    check.add_argument("--trust-policy", required=True)
    report = commands.add_parser("sbom")
    report.add_argument("output")
    args = parser.parse_args()
    if args.command == "build":
        result = build(args.source, args.destination, args.private_key, args.version)
    elif args.command == "verify":
        result = verify(args.directory, args.trust_policy)
    else:
        target = no_links(args.output)
        with target.open("xb") as stream:
            restrict_permissions(target)
            stream.write(canonical(sbom()))
        result = {"output": str(target)}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
