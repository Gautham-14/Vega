from __future__ import annotations

import ipaddress
import re
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:8000/api"
MAX_FILES, MAX_FILE_BYTES, MAX_IMPORT_BYTES = 64, 128_000, 512_000
MAX_JSON_BYTES, MAX_RESPONSE_BYTES = 2_000_000, 4_000_000
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
    ".aegis",
    ".ssh",
    ".aws",
    ".azure",
    ".gcp",
}
PRIVATE_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "authorized_keys",
    "known_hosts",
}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SECRET = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]",
    re.I,
)


class CLIError(Exception):
    """Expected client failure, printed without a traceback."""


def canonical_url(value):
    """Pin credentials to a numeric loopback origin; never use DNS or proxies."""
    if any(ord(c) < 33 for c in value):
        raise CLIError("API URL must not contain whitespace or control characters")
    try:
        url = urllib.parse.urlsplit(value)
        host = ipaddress.ip_address(url.hostname or "")
        port = url.port if url.port is not None else 80
    except ValueError:
        raise CLIError("Use a numeric loopback API URL, for example " + BASE_URL) from None
    if (
        url.scheme != "http"
        or not host.is_loopback
        or not 0 < port <= 65535
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path.rstrip("/") != "/api"
    ):
        raise CLIError(
            "API URL must be http://<numeric-loopback>:<port>/api without credentials, query, or fragment"
        )
    hostname = f"[{host.compressed}]" if host.version == 6 else host.compressed
    return f"http://{hostname}:{port}/api"


def no_links(path):
    from aegis.security.private_files import no_links as checked_path

    try:
        return checked_path(path)
    except ValueError as error:
        raise CLIError(str(error)) from None


def restrict_permissions(path, directory=False):
    """Reuse the shared owner-only ACL implementation."""
    from aegis.security.private_files import restrict_permissions as secure_permissions

    try:
        secure_permissions(path, directory=directory)
    except (ValueError, PermissionError) as error:
        raise CLIError(str(error)) from None


def redact(value):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower()
                in {
                    "access_token",
                    "refresh_token",
                    "password",
                    "authorization",
                    "api_key",
                    "token",
                    "secret",
                }
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def safe_endpoint(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith("/") or endpoint.startswith("//"):
        raise CLIError("Use a relative /api/... endpoint")
    path = urllib.parse.urlsplit(endpoint)
    if (
        path.scheme
        or path.netloc
        or path.fragment
        or "\\" in endpoint
        or "%" in path.path
        or any(ord(c) < 33 for c in endpoint)
    ):
        raise CLIError("Unsafe API endpoint")
    if (
        any(part in {".", ".."} for part in path.path.split("/"))
        or "//" in path.path
        or not re.fullmatch(r"/[A-Za-z0-9_./~-]+", path.path)
    ):
        raise CLIError("Unsafe API endpoint")
    return endpoint


def segment(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value):
        raise CLIError("Invalid object ID")
    return value
