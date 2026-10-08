"""Administrator-run negative containment tests against a deployed Linux model.

Uses only synthetic probes; never reads protected file contents. No policy is
changed. Requires a provisioned, independently reviewed attestor policy.
"""
import argparse
import json
import os
import subprocess

import psutil
from aegis.security.attestor import observe, protected_json

PROBE = r'''
import json, os, socket
checks = {}
for name, address, family in [('ipv4', ('1.1.1.1', 443), socket.AF_INET),
                              ('ipv6', ('2606:4700:4700::1111', 443), socket.AF_INET6)]:
    with socket.socket(family, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        try:
            stream.connect(address)
            checks[name + '_blocked'] = False
        except OSError:
            checks[name + '_blocked'] = True
try:
    socket.getaddrinfo('aegis-security-probe.invalid', 443)
    checks['dns_blocked'] = False
except OSError:
    checks['dns_blocked'] = True
for name, path in [('runtime', '/var/lib/aegis'), ('keys', '/var/lib/aegis-key'),
                   ('witness', '/var/lib/aegis-witness'), ('docker', '/var/run/docker.sock')]:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        checks[name + '_inaccessible'] = True
    else:
        os.close(descriptor)
        checks[name + '_inaccessible'] = False
print(json.dumps(checks))
'''


def check(policy_path, provider):
    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("Deployment checks require Linux host administrator privileges")
    entry = protected_json(policy_path)["providers"][provider]
    measured = observe(entry)
    process = psutil.Process(measured["process"]["pid"])
    args = ["/usr/bin/nsenter", "--target", str(process.pid), "--net", "--mount",
            "--setuid", str(process.uids().effective), "--setgid", str(process.gids().effective),
            "/opt/aegis/.venv/bin/python", "-I", "-c", PROBE]
    result = subprocess.run(args, capture_output=True, timeout=15, check=True,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    checks = json.loads(result.stdout)
    expected = {"ipv4_blocked", "ipv6_blocked", "dns_blocked", "runtime_inaccessible", "keys_inaccessible", "witness_inaccessible", "docker_inaccessible"}
    if set(checks) != expected or any(value is not True for value in checks.values()):
        raise RuntimeError("Deployed model failed a negative containment check")
    if observe(entry)["process"] != measured["process"]:
        raise RuntimeError("Model process changed during deployment checks")
    return {"passed": True, "checks": checks, "process": measured["process"],
            "scope": "Observed process identity, model mount/network namespace and OS identity; no claim of complete sandbox escape resistance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--provider", required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.policy, args.provider), sort_keys=True))


if __name__ == "__main__":
    main()
