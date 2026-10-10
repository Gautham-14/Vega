"""Exact incident routes; reserved admission never grants route authority."""

import re
from urllib.parse import urlsplit

from aegis.control import policy


def route(method, path):
    path = urlsplit(path).path
    if method == "POST" and path == "/api/auth/step-up":
        return {"Data Owner", "Model Custodian", "Security Officer", "Key Custodian"}
    if path == "/api/security/lockdown" and method in {"GET", "POST"}:
        return {"Security Officer"}
    if method == "POST" and re.fullmatch(
        r"/api/(?:coding|advisory)/leases/[A-Za-z0-9_-]{1,160}/revoke", path
    ):
        return {"Data Owner", "Security Officer"}
    if method == "POST" and path == "/api/security/maintenance":
        return {"Security Officer", "Key Custodian"}
    return set()


def reserved(method, path, identity):
    roles = route(method, path)
    return bool(roles and policy.actor(identity)["role"] in roles)
