"""Independent Linux systemd attestor for pinned, mmap-based llama.cpp servers.

Root-owned policy binds the unit, argv, bundle trust and qualification. The
service observes namespaces, UID, mapped weight files and security properties;
it never signs caller-supplied booleans. Durable logging/cache retention is
disabled; this is not an assertion of physical RAM erasure or hardware trust.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit

import psutil
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis.security import offline_bundle
from aegis.security.private_files import no_links

PROPERTIES = ("MainPID", "User", "PrivateNetwork", "ProtectSystem", "NoNewPrivileges",
              "CapabilityBoundingSet", "ReadWritePaths", "StandardOutput", "StandardError",
              "MemoryDenyWriteExecute", "PrivateTmp", "RestrictNamespaces", "ControlGroup", "InaccessiblePaths")


def protected_json(path):
    path = no_links(path)
    entry = path.stat()
    if os.name != "posix" or entry.st_uid != 0 or entry.st_mode & 0o022:
        raise ValueError("Attestor policy must be root-owned and not writable by runtime identities")
    if any(parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022 for parent in path.parents):
        raise ValueError("Attestor policy requires root-owned protected ancestor directories")
    return offline_bundle._read_json(path, 256 * 1024)[0]


def unit_properties(unit):
    if not re.fullmatch(r"aegis-(?:model@[A-Za-z0-9_-]+|api)\.service", unit):
        raise ValueError("Attestor can supervise only reviewed Aegis units")
    result = subprocess.run(["/usr/bin/systemctl", "show", unit,
        "--property=" + ",".join(PROPERTIES)], capture_output=True, timeout=5, check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if len(result.stdout) > 16384:
        raise ValueError("Supervisor response exceeds limit")
    return dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)


def validate_argv(argv):
    forbidden = {"--log-file", "--lookup-cache-dynamic", "--slot-save-path", "--hf-repo", "--hf-file", "--hf-token", "--model-url", "--mmproj-url"}
    if any(value.split("=", 1)[0] in forbidden for value in argv):
        raise ValueError("Runtime argv enables durable retention or automatic downloads")
    if ("--log-disable" not in argv or "--no-mmap" in argv
        or "--offline" not in argv or "--no-cache-idle-slots" not in argv
        or "--cache-ram" not in argv or argv[argv.index("--cache-ram") + 1:argv.index("--cache-ram") + 2] != ["0"]):
        raise ValueError("Runtime logging/cache/mmap policy is not satisfied")


def observe(entry):
    unit = unit_properties(entry["unit"])
    api = unit_properties("aegis-api.service")
    required = {"PrivateNetwork": "yes", "ProtectSystem": "strict", "NoNewPrivileges": "yes",
                "CapabilityBoundingSet": "", "ReadWritePaths": "", "StandardOutput": "null",
                "StandardError": "null", "MemoryDenyWriteExecute": "yes", "PrivateTmp": "yes",
                "RestrictNamespaces": "yes"}
    if any(unit.get(name) != expected for name, expected in required.items()):
        raise ValueError("Model service does not match the required containment policy")
    if not all(path in unit.get("InaccessiblePaths", "").split() for path in (
        "/var/lib/aegis", "/run/aegis-key", "/run/aegis-witness", "/run/aegis-attestor")):
        raise ValueError("Model service can access protected runtime/custody paths")
    process = psutil.Process(int(unit["MainPID"]))
    api_process = psutil.Process(int(api["MainPID"]))
    started = process.create_time()
    if process.uids().effective == api_process.uids().effective or process.uids().effective == 0:
        raise ValueError("Model must use a separate unprivileged OS identity")
    model_ns = os.readlink(f"/proc/{process.pid}/ns/net")
    if model_ns == os.readlink("/proc/1/ns/net") or model_ns != os.readlink(f"/proc/{api_process.pid}/ns/net"):
        raise ValueError("API and model require a shared private network namespace")
    interfaces = Path(f"/proc/{process.pid}/net/dev").read_text().splitlines()[2:]
    if any(line.split(":", 1)[0].strip() != "lo" for line in interfaces):
        raise ValueError("Model network namespace has a non-loopback interface")
    if unit["ControlGroup"] not in Path(f"/proc/{process.pid}/cgroup").read_text():
        raise ValueError("Runtime is outside its reviewed supervisor cgroup")
    argv = process.cmdline()
    if argv != entry["argv"]:
        raise ValueError("Runtime argv changed from independent policy")
    validate_argv(argv)
    if any(process.environ().get(name) for name in ("LD_PRELOAD", "LD_AUDIT")):
        raise ValueError("Runtime environment requests executable interposition")
    verification = offline_bundle.verify_bundle(entry["bundle_directory"], entry["bundle_trust_policy"])
    root = no_links(entry["bundle_directory"])
    protected_json(entry["bundle_trust_policy"])
    manifest = offline_bundle._read_json(root / "manifest.json", offline_bundle.MAX_MANIFEST_BYTES)[0]
    for path in [root, root / "manifest.json", root / "manifest.sig", *[root / item["path"] for item in manifest["files"]]]:
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise ValueError("Runtime and weight files must be root-owned and immutable to runtime identities")
    executable = no_links(process.exe())
    if executable != no_links(root / manifest["runtime_entry"]) or offline_bundle._sha256_file(executable, executable.stat().st_size) != verification["runtime_sha256"]:
        raise ValueError("Serving executable differs from the independently verified bundle")
    maps = Path(f"/proc/{process.pid}/maps").read_text().splitlines()
    mapped = {parts[5] for line in maps if len(parts := line.split(maxsplit=5)) == 6}
    expected_weights = [no_links(root / item["path"]) for item in manifest["files"] if item["role"] in {"weights", "projector"}]
    if not expected_weights or any(str(path) not in mapped for path in expected_weights):
        raise ValueError("Pinned weights are not mapped into the serving process")
    for path in expected_weights:
        current = path.stat()
        matching = [line.split(maxsplit=5) for line in maps if line.split(maxsplit=5)[-1] == str(path)]
        if any(int(parts[4]) != current.st_ino or tuple(int(part, 16) for part in parts[3].split(":")) !=
               (os.major(current.st_dev), os.minor(current.st_dev)) or "w" in parts[1] for parts in matching):
            raise ValueError("Mapped weight inode differs from the verified read-only file")
    if any(path.endswith((".gguf", ".safetensors")) and path not in {str(item) for item in expected_weights} for path in mapped):
        raise ValueError("Serving process maps an unreviewed weight file")
    endpoint = urlsplit(entry["endpoint"])
    listeners = [item.laddr for item in process.net_connections(kind="inet") if item.status == psutil.CONN_LISTEN]
    if (not listeners or any(not ipaddress.ip_address(item.ip).is_loopback for item in listeners)
        or not any(item.ip == endpoint.hostname and item.port == endpoint.port for item in listeners)):
        raise ValueError("Runtime does not own exactly local serving endpoints")
    if not process.is_running() or process.create_time() != started:
        raise ValueError("Model process changed during measurement")
    return {"process": {"pid": process.pid, "created_at": float(started),
        "executable_sha256": verification["runtime_sha256"]}, "verification": verification,
        "network_isolation_verified": True, "loaded_weights_verified": True,
        "server_retention_disabled": True, "retention_scope": "No durable model logs/cache; RAM erasure is not asserted"}


class Attestor:
    def __init__(self, policy_path):
        self.policy_path = policy_path

    def dispatch(self, request):
        policy = protected_json(self.policy_path)
        op = request.get("operation")
        if op == "stop-all" and set(request) == {"operation"}:
            failures = []
            for identity, entry in policy["providers"].items():
                try:
                    unit_properties(entry["unit"])
                    subprocess.run(["/usr/bin/systemctl", "stop", entry["unit"]], check=True, timeout=15,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if int(unit_properties(entry["unit"])["MainPID"]) != 0:
                        raise ValueError("Model supervisor still reports a live process")
                except (ValueError, OSError, subprocess.SubprocessError):
                    failures.append(identity)
            return {"stopped": not failures, "failed_providers": failures}
        if op not in {"measure", "attest"} or set(request) != {"operation", "provider", "configuration_sha256"}:
            raise ValueError("Unsupported attestor operation")
        entry = policy["providers"][request["provider"]]
        if request["configuration_sha256"] != entry["provider_configuration_sha256"]:
            raise ValueError("Provider configuration differs from independent policy")
        measured = observe(entry)
        if op == "measure":
            return measured
        now = time.time()
        verified = measured["verification"]
        body = {"schema_version": "aegis-provider-attestation-v1", "signer_id": policy["signer_id"],
                "provider_id": request["provider"], "provider_configuration_sha256": entry["provider_configuration_sha256"],
                "bundle_record_id": entry["bundle_record_id"], "manifest_sha256": verified["manifest_sha256"],
                "weights_inventory_sha256": verified["weights_inventory_sha256"],
                "qualification_id": entry["qualification_id"], "qualification_sha256": entry["qualification_sha256"],
                "process": measured["process"], "loaded_weights_verified": True,
                "network_isolation_verified": True, "server_retention_disabled": True,
                "issued_at": now, "expires_at": now + 300}
        path = no_links(policy["private_key"])
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o077 or path.stat().st_size > 16384:
            raise ValueError("Attestor private key must be root-only")
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Attestor requires a separate Ed25519 key")
        return {"attestation": body, "signature": base64.b64encode(key.sign(offline_bundle.canonical_bytes(body))).decode()}


def remote(operation, spec=None):
    from aegis.security.local_rpc import call
    request = {"operation": operation}
    if spec is not None:
        from aegis.coding.providers import configuration_hash
        request.update(provider=spec["provider"], configuration_sha256=configuration_hash(spec))
    return call(os.environ["AEGIS_ATTESTOR_SOCKET"], int(os.environ["AEGIS_ATTESTOR_UID"]), request, timeout=120)


def main():
    parser = argparse.ArgumentParser(description="Independent systemd process/isolation attestor")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--runtime-uid", required=True, type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("Attestor requires root to inspect separately owned processes")
    from aegis.security.local_rpc import serve
    serve(args.socket, args.runtime_uid, Attestor(args.policy).dispatch)


if __name__ == "__main__":
    main()
