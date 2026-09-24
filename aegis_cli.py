#!/usr/bin/env python3
"""Aegis local terminal operator; no cloud login or automatic model calls."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass

BASE_URL = "http://127.0.0.1:8000/api"
MAX_FILES, MAX_FILE_BYTES, MAX_IMPORT_BYTES = 64, 128_000, 512_000
MAX_JSON_BYTES, MAX_RESPONSE_BYTES = 2_000_000, 4_000_000
EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".idea", ".vscode", "dist", "build", "target", "coverage", ".next", ".aegis", ".ssh", ".aws", ".azure", ".gcp"}
PRIVATE_NAMES = {".env", ".npmrc", ".pypirc", ".netrc", "credentials", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "known_hosts"}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SECRET = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]", re.I)


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
    if url.scheme != "http" or not host.is_loopback or not 0 < port <= 65535 or url.username or url.password or url.query or url.fragment or url.path.rstrip("/") != "/api":
        raise CLIError("API URL must be http://<numeric-loopback>:<port>/api without credentials, query, or fragment")
    hostname = f"[{host.compressed}]" if host.version == 6 else host.compressed
    return f"http://{hostname}:{port}/api"


def no_links(path):
    """Reject symlinks and Windows reparse points, including ancestor paths."""
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise CLIError(f"Symbolic links and junctions are not allowed: {part}")
    return path


def restrict_permissions(path, directory=False):
    """Apply an owner-only Windows DACL, or 0700/0600 on POSIX."""
    if os.name != "nt":
        if path.stat().st_uid != os.getuid():
            raise CLIError("Session storage must belong to the current user")
        path.chmod(0o700 if directory else 0o600)
        return
    # SDDL avoids localized account names; no secret enters the process args.
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True, creationflags=0x08000000)
    sid = re.search(r"S-1-[0-9-]+", result.stdout)
    if sid is None:
        raise CLIError("Cannot identify Windows user for private session storage")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
    convert.restype = ctypes.c_int
    flags = "OICI" if directory else ""
    if not convert(f"D:P(A;{flags};FA;;;{sid.group()})", 1, ctypes.byref(descriptor), None):
        raise CLIError("Cannot create private Windows session permissions")
    try:
        setter = advapi.SetFileSecurityW
        setter.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p]
        setter.restype = ctypes.c_int
        if not setter(str(path), 0x80000004, descriptor):
            raise CLIError("Cannot restrict session storage to current Windows user")
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
        free(descriptor)


class SessionStore:
    def __init__(self, url, directory=None):
        self.url = canonical_url(url)
        self.directory = no_links(directory or os.environ.get("AEGIS_CLIENT_DIR") or Path.home() / ".aegis")
        key = hashlib.sha256(self.url.encode()).hexdigest()[:24]
        self.path = self.directory / f"session-{key}.json"
        self.value = {}
        if self.path.exists():
            no_links(self.path)
            if self.path.stat().st_size > 16_384:
                raise CLIError("Invalid session file; remove it and sign in again")
            restrict_permissions(self.directory, directory=True)
            restrict_permissions(self.path)
            try:
                self.value = json.loads(self.path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeError):
                raise CLIError("Invalid session file; remove it and sign in again") from None
            if not isinstance(self.value, dict) or self.value.get("url") != self.url:
                raise CLIError("Session file does not match selected API URL")
            token = self.value.get("access_token")
            if token is not None and (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token)):
                raise CLIError("Invalid session token; remove session file and sign in again")

    def save(self):
        no_links(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        restrict_permissions(self.directory, directory=True)
        no_links(self.path)
        self.value["url"] = self.url
        fd, temporary = tempfile.mkstemp(prefix=".session-", suffix=".tmp", dir=self.directory)
        temp_path = Path(temporary)
        try:
            restrict_permissions(temp_path)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                fd = None
                json.dump(self.value, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, self.path)
        finally:
            if fd is not None:
                os.close(fd)
            if temp_path.exists():
                temp_path.unlink()

    def clear(self):
        self.value = {}
        if self.path.exists():
            no_links(self.path)
            self.path.unlink()


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CLIError("API redirects refused; set --url explicitly to a numeric loopback server")


def safe_endpoint(endpoint):
    if not isinstance(endpoint, str) or not endpoint.startswith("/") or endpoint.startswith("//"):
        raise CLIError("Use a relative /api/... endpoint")
    path = urllib.parse.urlsplit(endpoint)
    if path.scheme or path.netloc or path.fragment or "\\" in endpoint or "%" in path.path or any(ord(c) < 33 for c in endpoint):
        raise CLIError("Unsafe API endpoint")
    if any(part in {".", ".."} for part in path.path.split("/")) or "//" in path.path or not re.fullmatch(r"/[A-Za-z0-9_./~-]+", path.path):
        raise CLIError("Unsafe API endpoint")
    return endpoint


def segment(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", value):
        raise CLIError("Invalid object ID")
    return value


class Client:
    def __init__(self, url=BASE_URL, timeout=120, session=None, opener=None):
        self.url = canonical_url(url)
        if not 1 <= timeout <= 300:
            raise CLIError("Timeout must be 1-300 seconds")
        self.timeout = timeout
        self.session = session or SessionStore(self.url)
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())

    def call(self, endpoint, method="GET", data=None, *, public=False):
        endpoint = safe_endpoint(endpoint)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if not public:
            value = self.session.value
            if value.get("access_token"):
                if value.get("expires_at", 0) <= time.time():
                    raise CLIError("Session expired. Use login to sign in again.")
                headers["Authorization"] = "Bearer " + value["access_token"]
            elif value.get("demo_persona"):
                headers["X-Aegis-Actor"] = value["demo_persona"]
            else:
                raise CLIError("Sign in with login <actor>, or explicitly select persona <actor> on an enabled demo server")
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(self.url + endpoint, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raw = error.read(16_385)
            try:
                detail = json.loads(raw.decode("utf-8")).get("detail", f"HTTP {error.code}")
            except (ValueError, UnicodeError, AttributeError):
                detail = f"HTTP {error.code}"
            raise CLIError(f"API {error.code}: {json.dumps(redact(detail), ensure_ascii=True)}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            raise CLIError(f"Cannot reach Aegis at {self.url}: {type(error).__name__}. Start the server or check --url.") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise CLIError("API response exceeded the 4 MB client limit")
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeError):
            raise CLIError("Server returned invalid JSON") from None

    def login(self, username):
        username = username or input("Aegis account: ").strip()
        password = getpass("Aegis password: ")
        result = self.call("/auth/login", "POST", {"username": username, "password": password}, public=True)
        password = None
        if not isinstance(result, dict) or not result.get("access_token") or result.get("actor") != username:
            raise CLIError("Server returned an invalid sign-in response")
        self.session.value = {key: result[key] for key in ("access_token", "actor", "expires_at")}
        try:
            self.session.save()
        except (CLIError, OSError, subprocess.SubprocessError):
            try:
                self.call("/auth/logout", "POST")
            except CLIError:
                pass
            self.session.value = {}
            raise
        return {"signed_in": True, "actor": result["actor"], "role": result.get("role"), "expires_at": result["expires_at"]}

    def persona(self, actor):
        status = self.call("/auth/status", public=True)
        if not status.get("demo") or status.get("configured"):
            raise CLIError("Persona switching requires server demo mode with no accounts; use login instead")
        previous = self.session.value
        self.session.value = {"demo_persona": segment(actor)}
        try:
            me = self.call("/auth/me")
        except CLIError:
            self.session.value = previous
            raise
        self.session.value["actor"] = me["id"]
        self.session.save()
        return {"demo": True, "identity": me, "authentication": "DEMO_PERSONA_ONLY"}

    def select_lease(self, lease_id, *, save=True):
        me = self.call("/auth/me")
        lease = self.call(f"/coding/leases/{segment(lease_id)}")
        if lease.get("user") != me["id"]:
            raise CLIError("Lease belongs to a different account")
        if lease.get("revoked") or lease.get("expires_at", 0) <= time.time():
            raise CLIError("Lease has expired or been revoked")
        if not lease.get("purpose") or lease.get("mode") not in {"ASK", "PLAN", "EXECUTE"}:
            raise CLIError("Invalid coding lease returned by server")
        if save:
            self.session.value["selected_lease"] = {"id": lease["id"], "actor": me["id"]}
            self.session.save()
        return lease

    def run(self, prompt, lease_id=None, purpose=None, parent_task_id=None):
        selected = self.session.value.get("selected_lease", {})
        if not lease_id:
            lease_id = selected.get("id")
            if lease_id and selected.get("actor") != self.session.value.get("actor"):
                raise CLIError("Selected lease belongs to another account; select it again with use <lease-id>")
        if not lease_id:
            raise CLIError("Select a lease with use <lease-id> before running a prompt")
        lease = self.select_lease(lease_id, save=False)
        if purpose is not None and purpose != lease["purpose"]:
            raise CLIError("Prompt purpose must match the selected lease")
        if not prompt or len(prompt) > 8000:
            raise CLIError("Prompt must contain 1-8000 characters")
        body = {"lease_id": lease_id, "prompt": prompt, "purpose": lease["purpose"]}
        if parent_task_id:
            body["parent_task_id"] = segment(parent_task_id)
        return self.call("/coding/tasks", "POST", body)


def redact(value):
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in {"access_token", "refresh_token", "password", "authorization", "api_key", "token", "secret"} else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def print_result(value):
    print(json.dumps(redact(value), indent=2, ensure_ascii=True))


def json_file(path):
    path = no_links(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise CLIError("JSON request file exceeds 2 MB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise CLIError("Request file must contain valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise CLIError("Request JSON must be an object")
    return value


def private_path(path):
    return any(part.lower() in EXCLUDED_DIRS or part.lower() in PRIVATE_NAMES or part.lower().startswith(".env.") for part in path.parts) or path.suffix.lower() in PRIVATE_SUFFIXES


def import_files(paths):
    """Read explicitly named files/directory, with bounded UTF-8 input."""
    if not paths:
        raise CLIError("Name a directory or one or more UTF-8 files")
    originals = [no_links(p) for p in paths]
    directories = [p for p in originals if p.is_dir()]
    if directories and len(originals) != 1:
        raise CLIError("Import one directory or a list of explicit files")
    files, skipped, seen = {}, [], set()
    total = 0
    if directories:
        root = directories[0]
        candidates = []
        for current, dirs, names in os.walk(root, followlinks=False):
            for name in list(dirs):
                child = Path(current) / name
                try:
                    no_links(child)
                    allowed = not private_path(child.relative_to(root))
                except CLIError:
                    allowed = False
                if not allowed:
                    dirs.remove(name)
                    skipped.append(str(child.relative_to(root)) + "/")
            for name in sorted(names):
                child = Path(current) / name
                relative = child.relative_to(root)
                try:
                    no_links(child)
                    allowed = not private_path(relative)
                except CLIError:
                    allowed = False
                if not allowed:
                    skipped.append(relative.as_posix())
                    continue
                candidates.append((child, relative.as_posix()))
    else:
        if any(not path.is_file() for path in originals):
            raise CLIError("Every import path must be an existing regular file")
        root = Path(os.path.commonpath([str(p.parent) for p in originals]))
        candidates = [(p, p.relative_to(root).as_posix()) for p in originals]
    if len(candidates) > MAX_FILES:
        raise CLIError(f"Import exceeds {MAX_FILES} files. Name fewer files; nothing was imported.")
    for path, name in sorted(candidates, key=lambda pair: pair[1]):
        if private_path(Path(name)) or private_path(path):
            raise CLIError(f"Private configuration cannot be imported: {name}")
        no_links(path)
        if not path.is_file():
            raise CLIError(f"Not a regular file: {name}")
        if name.casefold() in seen:
            raise CLIError("Import paths conflict on a case-insensitive filesystem")
        seen.add(name.casefold())
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise CLIError(f"File exceeds 128 KB: {name}; nothing was imported")
        total += len(raw)
        if total > MAX_IMPORT_BYTES:
            raise CLIError("Import exceeds 512 KB; nothing was imported")
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            raise CLIError(f"Not UTF-8 text: {name}; name only text files") from None
        if "\x00" in text:
            raise CLIError(f"Binary file cannot be imported: {name}")
        if SECRET.search(text):
            raise CLIError(f"Secret-like content detected in {name}; remove it before import")
        files[name] = text
    if not files:
        raise CLIError("No eligible text files found")
    return files, skipped


def export_patch(client, task_id, approval_id, destination):
    destination = no_links(destination)
    if destination.exists():
        raise CLIError("Export destination already exists; choose a new file")
    if not destination.parent.is_dir():
        raise CLIError("Export destination directory does not exist")
    result = client.call(f"/coding/tasks/{segment(task_id)}/export", "POST", {"approval_id": approval_id})
    if not isinstance(result.get("patch"), str):
        raise CLIError("Server did not return a patch")
    no_links(destination)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        restrict_permissions(destination)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = None
            stream.write(result["patch"])
    finally:
        if fd is not None:
            os.close(fd)
    return {"exported": str(destination), "bytes": len(result["patch"].encode("utf-8")), "classification": result.get("classification")}


def build_parser():
    parser = argparse.ArgumentParser(description="Aegis terminal operator. Local API only; website displays telemetry.")
    parser.add_argument("--url", default=os.environ.get("AEGIS_API_URL", BASE_URL), help="Numeric loopback API URL (or AEGIS_API_URL)")
    parser.add_argument("--timeout", type=float, default=120, help="API timeout in seconds (1-300)")
    parser.add_argument("--persona", help="Explicit demo identity; requires enabled demo server with no accounts")
    commands = parser.add_subparsers(dest="command")
    for name, help_text in {
        "shell": "Interactive operator shell (default)", "status": "Authentication and local runtime status", "logout": "Revoke and clear this server's session", "whoami": "Show authenticated identity", "state": "Coding workspace state", "control-state": "Control plane state", "providers": "List local provider profiles and supported connections", "tasks": "List your coding tasks", "leases": "List visible coding leases", "repositories": "List visible repository snapshots", "validate": "Run local negative-case validation", "telemetry": "Read measured local telemetry", "receipts": "List control receipts", "endpoints": "Discover available API endpoints", "demo-prepare": "Prepare explicit control demo", "demo-activate": "Activate explicit control demo", "coding-fixture": "Import explicit coding demo fixture", "sandbox": "Inspect sandbox availability and enforcement",
    }.items():
        commands.add_parser(name, help=help_text)
    login = commands.add_parser("login", help="Sign in locally; password is prompted securely")
    login.add_argument("username", nargs="?")
    commands.add_parser("manifest-hash", help="Compute a metadata manifest checksum locally from JSON").add_argument("file")
    users = commands.add_parser("users", help="Host administrator provisioning (same AEGIS data directory as server)")
    user_commands = users.add_subparsers(dest="user_command", required=True)
    user_commands.add_parser("roles", help="List supported account roles")
    user_commands.add_parser("set", help="Create/reset account and revoke its sessions").add_argument("actor")
    for command, field, help_text in [("persona", "actor", "Select a demo identity explicitly"), ("provider-add", "file", "Register immutable local provider from JSON file"), ("provider-probe", "id", "Explicitly probe a local provider"), ("use", "id", "Select a live lease owned by signed-in account"), ("task", "id", "Read a coding task"), ("diff", "id", "Read task diff and review hash"), ("export-request", "id", "Request permission to export an applied patch"), ("review", "id", "Review exact patch bound to export approval"), ("close", "id", "Close task and destroy retained content"), ("revoke", "id", "Revoke coding lease"), ("provider", "id", "Inspect provider profile")]:
        commands.add_parser(command, help=help_text).add_argument(field)
    register = commands.add_parser("register", aliases=["coding-capsule"], help="Register measured Capsule and request dual approval")
    register.add_argument("profile", nargs="?", help="Provider profile ID, reference, or legacy ollama")
    register.add_argument("--provider", help="Alias for provider profile ID")
    approve = commands.add_parser("approve", help="Record account's independent approval decision")
    approve.add_argument("id")
    approve.add_argument("decision", choices=["approve", "reject"])
    activate = commands.add_parser("activate", help="Activate Capsule after required approvals")
    activate.add_argument("capsule_id")
    activate.add_argument("approval_id")
    lease = commands.add_parser("lease", aliases=["coding-lease"], help="Issue scoped coding lease (Data Owner)")
    lease.add_argument("--repo", required=True)
    lease.add_argument("--capsule", required=True)
    lease.add_argument("--mode", choices=["ASK", "PLAN", "EXECUTE"], default="PLAN")
    lease.add_argument("--recipient", "--user", dest="recipient", default="operator")
    lease.add_argument("--minutes", type=int, choices=range(1, 16), default=15)
    lease.add_argument("--export", action="store_true", help="Explicitly permit approved patch export; off by default")
    run = commands.add_parser("run", aliases=["coding-run"], help="Run prompt under selected lease and its bound purpose")
    run.add_argument("text", nargs="*")
    run.add_argument("--prompt", help="Legacy explicit prompt option")
    run.add_argument("--lease", help="Explicit lease; otherwise use selected lease")
    run.add_argument("--purpose", help="Optional assertion; must match lease purpose")
    run.add_argument("--parent-task", help="Continue an APPLIED task under the same lease")
    imp = commands.add_parser("import", help="Import explicit UTF-8 files or one directory into encrypted snapshot")
    imp.add_argument("paths", nargs="+")
    imp.add_argument("--name", required=True)
    imp.add_argument("--compartment", choices=["Engineering", "Maintenance", "Finance", "HR", "Public"], default="Engineering")
    imp.add_argument("--classification", choices=["PUBLIC", "INTERNAL"], default="INTERNAL")
    for name in ("apply", "revert"):
        apply = commands.add_parser(name, help=f"{name.title()} reviewed hash in encrypted snapshot; host checkout untouched")
        apply.add_argument("id")
        apply.add_argument("diff_hash")
    export = commands.add_parser("export", help="Export approved patch to a new local file (never overwrite)")
    export.add_argument("id")
    export.add_argument("approval_id")
    export.add_argument("file")
    commands.add_parser("verify", help="Verify receipt chain, or legacy task receipt").add_argument("id", nargs="?")
    api = commands.add_parser("api", help="Local API escape hatch; endpoints lists operations and schemas")
    api.add_argument("method", type=str.upper, choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    api.add_argument("endpoint", help="An /api/... path on selected loopback server")
    api.add_argument("file", nargs="?", help="Optional UTF-8 JSON request file")
    return parser


def provision_user(args):
    from aegis.control import policy, store
    if args.user_command == "roles":
        return policy.ACTORS
    if args.actor not in policy.ACTORS:
        raise CLIError("Unknown account. Use users roles to list supported IDs.")
    password = getpass("New Aegis password (12-256 characters): ")
    if password != getpass("Confirm password: "):
        raise CLIError("Passwords do not match")
    if not 12 <= len(password) <= 256:
        raise CLIError("Use a password of 12-256 characters")
    from aegis.security.auth import provision
    from aegis.storage.database import init_db
    init_db()
    store.init_control()
    return provision(args.actor, password)


def execute(args, client):
    command = {"coding-capsule": "register", "coding-lease": "lease", "coding-run": "run"}.get(args.command, args.command)
    if command == "manifest-hash":
        from aegis.models.manifest import ModelManifest, compute_manifest_sha256
        value = json_file(args.file)
        value["sha256"] = "0" * 64
        value = ModelManifest.model_validate(value).model_dump()
        value["sha256"] = compute_manifest_sha256(value)
        return value
    if command == "login":
        return client.login(args.username)
    if command == "logout":
        try:
            return client.call("/auth/logout", "POST")
        finally:
            client.session.clear()
    if command == "persona":
        return client.persona(args.actor)
    if command == "users":
        return provision_user(args)
    if command == "status":
        return {"authentication": client.call("/auth/status", public=True), "coding": client.call("/coding/status", public=True), "api_url": client.url}
    get_routes = {"whoami": "/auth/me", "state": "/coding/state", "control-state": "/control/state", "providers": "/providers", "tasks": "/coding/tasks", "leases": "/coding/leases", "repositories": "/coding/repositories", "telemetry": "/telemetry/latest", "endpoints": "/endpoints", "receipts": "/control/receipts", "sandbox": "/coding/sandbox"}
    if command in get_routes:
        return client.call(get_routes[command])
    post_routes = {"validate": "/coding/validation", "demo-prepare": "/control/demo/prepare", "demo-activate": "/control/demo/activate", "coding-fixture": "/coding/demo/repository"}
    if command in post_routes:
        return client.call(post_routes[command], "POST")
    if command == "provider":
        return client.call(f"/providers/{segment(args.id)}")
    if command == "provider-add":
        return client.call("/providers", "POST", json_file(args.file))
    if command == "provider-probe":
        return client.call(f"/providers/{segment(args.id)}/probe", "POST")
    if command == "register":
        provider = args.profile or args.provider or "reference"
        if args.profile and args.provider and args.profile != args.provider:
            raise CLIError("Specify one provider profile")
        return client.call("/coding/capsules", "POST", {"provider": provider})
    if command == "approve":
        return client.call(f"/control/approvals/{segment(args.id)}/decide", "POST", {"decision": args.decision.upper()})
    if command == "activate":
        return client.call(f"/control/capsules/{segment(args.capsule_id)}/approve", "POST", {"approval_id": args.approval_id})
    if command == "lease":
        return client.call("/coding/leases", "POST", {"repository_id": args.repo, "capsule_id": args.capsule, "user": args.recipient, "mode": args.mode, "minutes": args.minutes, "allow_export": args.export})
    if command == "use":
        return client.select_lease(args.id)
    if command == "run":
        if args.text and args.prompt:
            raise CLIError("Pass prompt text or --prompt, not both")
        return client.run(args.prompt if args.prompt is not None else " ".join(args.text), args.lease, args.purpose, args.parent_task)
    if command == "import":
        files, skipped = import_files(args.paths)
        if skipped:
            print("Excluded private/generated/link paths: " + json.dumps(skipped, ensure_ascii=True), file=sys.stderr)
        result = client.call("/coding/repositories", "POST", {"name": args.name, "files": files, "compartment": args.compartment, "classification": args.classification})
        return {"repository": result, "imported_files": sorted(files), "skipped": skipped}
    if command in {"task", "diff"}:
        result = client.call(f"/coding/tasks/{segment(args.id)}")
        return {key: result.get(key) for key in ("id", "status", "diff_hash", "diff", "reason", "host_checkout_modified")} if command == "diff" else result
    if command in {"apply", "revert"}:
        if not re.fullmatch(r"[a-f0-9]{64}", args.diff_hash):
            raise CLIError("Review hash must contain exactly 64 lowercase hexadecimal characters")
        return client.call(f"/coding/tasks/{segment(args.id)}/{command}", "POST", {"diff_hash": args.diff_hash})
    if command in {"close", "export-request"}:
        return client.call(f"/coding/tasks/{segment(args.id)}/{command}", "POST")
    if command == "review":
        return client.call(f"/coding/approvals/{segment(args.id)}/review")
    if command == "revoke":
        result = client.call(f"/coding/leases/{segment(args.id)}/revoke", "POST")
        if client.session.value.get("selected_lease", {}).get("id") == args.id:
            client.session.value.pop("selected_lease")
            client.session.save()
        return result
    if command == "export":
        return export_patch(client, args.id, args.approval_id, args.file)
    if command == "verify":
        return client.call(f"/receipts/{segment(args.id)}/verify", "POST") if args.id else client.call("/control/receipts/verify")
    if command == "api":
        safe_endpoint(args.endpoint)
        if not args.endpoint.startswith("/api/") or args.endpoint.startswith("/api/auth/"):
            raise CLIError("Use an /api/... operation endpoint; use login/logout/whoami for authentication")
        if args.method == "GET" and args.file:
            raise CLIError("GET requests do not accept a request file")
        return client.call(args.endpoint[4:], args.method, json_file(args.file) if args.file else None)
    raise CLIError("Unknown command; use --help")


def failed_result(value):
    return isinstance(value, dict) and (value.get("status") in {"BLOCKED", "FAILED", "FAIL", "DENIED", "REJECTED"}
        or any(value.get(key) is False for key in ("valid", "is_valid", "passed", "all_passed")))


def shell(client, parser):
    print(f"Aegis terminal | {client.url}")
    print("Use /login <actor>, /help, or /exit. Plain text runs under your selected lease.")
    print("Website: telemetry. Apply: encrypted task snapshot. Export: approved local patch.")
    while True:
        actor = client.session.value.get("actor", "signed-out")
        try:
            line = input(f"aegis[{actor}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line in {"/exit", "/quit"}:
            return 0
        if line in {"/help", "/?"}:
            parser.print_help()
            continue
        try:
            if not line.startswith("/"):
                result = client.run(line)
            else:
                # Preserve Windows path backslashes and strip matching outer quotes.
                words = shlex.split(line[1:], posix=False)
                words = [w[1:-1] if len(w) >= 2 and w[0] == w[-1] and w[0] in "\"'" else w for w in words]
                args = parser.parse_args(words)
                if not args.command or args.command == "shell":
                    raise CLIError("Already in the Aegis shell")
                if args.persona:
                    client.persona(args.persona)
                result = execute(args, client)
            print_result(result)
            if failed_result(result):
                print("Operation did not complete; inspect status and reason above.", file=sys.stderr)
        except SystemExit:
            continue  # argparse errors and --help never terminate an active shell.
        except (CLIError, OSError, ValueError, subprocess.SubprocessError) as error:
            print("Error: " + str(error), file=sys.stderr)
        except KeyboardInterrupt:
            print("\nCommand interrupted.", file=sys.stderr)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "users":
            print_result(provision_user(args))
            return 0
        client = Client(args.url, args.timeout)
        if args.persona:
            client.persona(args.persona)
        if not args.command or args.command == "shell":
            return shell(client, parser)
        result = execute(args, client)
        print_result(result)
        return 1 if failed_result(result) else 0
    except (CLIError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
