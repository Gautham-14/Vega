"""Strict, offline VM inventory. No arbitrary QEMU options or network devices."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import ssl
import sys
from pathlib import Path

from aegis.security.private_files import no_links, restrict_permissions

FIELDS = {
    "schema",
    "qemu",
    "qemu_sha256",
    "root_image",
    "root_sha256",
    "state_image",
    "tls_directory",
    "server_certificate_sha256",
    "api_port",
    "channel_port",
    "memory_mib",
    "cpus",
    "accelerator",
    "firmware_directory",
    "firmware_sha256",
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def firmware_digest(directory):
    inventory = hashlib.sha256()
    count = 0
    for item in sorted(directory.rglob("*")):
        no_links(item)
        if item.is_file():
            count += 1
            inventory.update(item.relative_to(directory).as_posix().encode("utf-8") + b"\0")
            inventory.update(bytes.fromhex(digest(item)))
        elif not item.is_dir():
            raise ValueError("VM firmware inventory must contain only ordinary files")
    if count == 0:
        raise ValueError("VM firmware inventory is empty")
    return inventory.hexdigest()


def load(path):
    policy_path = no_links(path)
    if policy_path.stat().st_size > 16384:
        raise ValueError("VM policy is too large")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate VM policy field")
            value[key] = item
        return value

    value = json.loads(policy_path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        raise ValueError("VM policy must contain exactly the schema-1 fields")
    if sys.platform not in {"win32", "darwin", "linux"}:
        raise ValueError("VM hosts supported: Windows, macOS and Linux")
    for name in ("qemu", "root_image", "state_image", "tls_directory", "firmware_directory"):
        if not isinstance(value[name], str) or not Path(value[name]).is_absolute():
            raise ValueError("VM inventory paths must be absolute local paths")
        value[name] = no_links(value[name])
    if len({value[name] for name in ("qemu", "root_image", "state_image")}) != 3:
        raise ValueError("VM executable, immutable root and mutable state must be distinct")
    for name in ("qemu", "root_image", "state_image"):
        if not value[name].is_file() or value[name].stat().st_size == 0:
            raise ValueError("VM inventory requires nonempty regular files")
    for name in ("qemu_sha256", "root_sha256", "server_certificate_sha256", "firmware_sha256"):
        if (
            not isinstance(value[name], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value[name])
            or value[name] == "0" * 64
        ):
            raise ValueError("Replace VM inventory placeholders with reviewed SHA-256 pins")
    for name, pin in (("qemu", "qemu_sha256"), ("root_image", "root_sha256")):
        if digest(value[name]) != value[pin]:
            raise ValueError("VM inventory hash mismatch: " + name)
    if (
        not value["firmware_directory"].is_dir()
        or firmware_digest(value["firmware_directory"]) != value["firmware_sha256"]
    ):
        raise ValueError("VM firmware inventory hash mismatch")
    for name, lower, upper in (
        ("api_port", 1024, 65535),
        ("channel_port", 1024, 65535),
        ("memory_mib", 1024, 1048576),
        ("cpus", 1, 256),
    ):
        if type(value[name]) is not int or not lower <= value[name] <= upper:
            raise ValueError("Invalid VM resource/port setting: " + name)
    if value["api_port"] == value["channel_port"]:
        raise ValueError("VM API and transport ports must differ")
    allowed = {"linux": "kvm", "win32": "whpx", "darwin": "hvf"}
    if not isinstance(value["accelerator"], str) or value["accelerator"] not in {
        "tcg",
        allowed[sys.platform],
    }:
        raise ValueError("VM accelerator does not match the host OS")
    if value["accelerator"] != "tcg" and platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("This x86-64 guest needs TCG on non-x86-64 hosts")
    if not value["tls_directory"].is_dir():
        raise ValueError("VM TLS directory is missing")
    for name in (
        "ca-cert.pem",
        "server-cert.pem",
        "server-key.pem",
        "client-cert.pem",
        "client-key.pem",
    ):
        certificate = no_links(value["tls_directory"] / name)
        if not certificate.is_file() or not 1 <= certificate.stat().st_size <= 65536:
            raise ValueError("VM TLS inventory is incomplete")
    certificate = ssl.PEM_cert_to_DER_cert(
        (value["tls_directory"] / "server-cert.pem").read_text(encoding="ascii")
    )
    if hashlib.sha256(certificate).hexdigest() != value["server_certificate_sha256"]:
        raise ValueError("VM TLS server certificate pin mismatch")
    # Verify the client key/certificate and CA before launching any process.
    context(value)
    return value


def context(policy):
    directory = policy["tls_directory"]
    # Do not honor SSLKEYLOGFILE from the operator's ambient environment.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(directory / "ca-cert.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(directory / "client-cert.pem"), str(directory / "client-key.pem"))
    return ctx


def secure_mutable_files(policy):
    """Explicit startup permission changes; imports and `check` are read-only."""
    restrict_permissions(policy["state_image"])
    restrict_permissions(policy["tls_directory"], directory=True)
    for item in policy["tls_directory"].iterdir():
        if item.is_file():
            restrict_permissions(item)


def command(policy):
    def object_arg(value):
        return json.dumps(value, separators=(",", ":"))

    args = [
        str(policy["qemu"]),
        "-L",
        str(policy["firmware_directory"]),
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-machine",
        "q35",
        "-accel",
        policy["accelerator"],
        "-m",
        str(policy["memory_mib"]),
        "-smp",
        str(policy["cpus"]),
    ]
    for name, path, readonly in (
        ("root", policy["root_image"], True),
        ("state", policy["state_image"], False),
    ):
        args += [
            "-blockdev",
            object_arg(
                {
                    "driver": "raw",
                    "node-name": name,
                    "read-only": readonly,
                    "file": {"driver": "file", "filename": str(path)},
                }
            ),
            "-device",
            f"virtio-blk-pci,drive={name},bootindex={1 if name == 'root' else 2}",
        ]
    args += [
        "-object",
        object_arg(
            {
                "qom-type": "tls-creds-x509",
                "id": "aegis-tls",
                "endpoint": "server",
                "dir": str(policy["tls_directory"]),
                "verify-peer": True,
            }
        ),
        "-device",
        "virtio-serial-pci",
        "-chardev",
        f"socket,id=aegis-api,host=127.0.0.1,port={policy['channel_port']},server=on,wait=off,tls-creds=aegis-tls",
        "-device",
        "virtserialport,chardev=aegis-api,name=org.aegis.api",
    ]
    return args
