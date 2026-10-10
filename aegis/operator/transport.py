from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass
from pathlib import Path

from .common import (
    BASE_URL,
    MAX_RESPONSE_BYTES,
    CLIError,
    canonical_url,
    no_links,
    redact,
    restrict_permissions,
    safe_endpoint,
    segment,
)


class SessionStore:
    def __init__(self, url, directory=None):
        self.url = canonical_url(url)
        self.directory = no_links(
            directory or os.environ.get("AEGIS_CLIENT_DIR") or Path.home() / ".aegis"
        )
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
            if token is not None and (
                not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token)
            ):
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


class Client:
    def __init__(
        self, url=BASE_URL, timeout=120, session=None, opener=None, password_reader=getpass
    ):
        self.password_reader = password_reader
        self.url = canonical_url(url)
        if not 1 <= timeout <= 300:
            raise CLIError("Timeout must be 1-300 seconds")
        self.timeout = timeout
        self.session = session or SessionStore(self.url)
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirects()
        )

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
                raise CLIError(
                    "Sign in with login <actor>, or explicitly select persona <actor> on an enabled demo server"
                )
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        limit = (
            12_000_000
            if endpoint.startswith("/media/")
            else 4_000_000
            if endpoint in {"/chat", "/chat/route"}
            else MAX_RESPONSE_BYTES
        )
        if payload is not None and len(payload) > limit:
            raise CLIError("API request exceeds the client size limit")
        request = urllib.request.Request(
            self.url + endpoint, data=payload, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            raw = error.read(16_385)
            try:
                detail = json.loads(raw.decode("utf-8")).get("detail", f"HTTP {error.code}")
            except (ValueError, UnicodeError, AttributeError):
                detail = f"HTTP {error.code}"
            raise CLIError(
                f"API {error.code}: {json.dumps(redact(detail), ensure_ascii=True)}"
            ) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            followup = (
                " Check server state before retrying; a submitted operation may still complete."
                if method != "GET"
                else " Start the server or check --url."
            )
            raise CLIError(
                f"Cannot reach Aegis at {self.url}: {type(error).__name__}." + followup
            ) from None
        if len(raw) > limit:
            raise CLIError("API response exceeded the client size limit")
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeError):
            raise CLIError("Server returned invalid JSON") from None

    def login(self, username, mfa=False):
        username = username or input("Aegis account: ").strip()
        password = self.password_reader("Aegis password: ")
        body = {"username": username, "password": password}
        if mfa:
            body["otp"] = self.password_reader("Authenticator code: ")
        result = self.call("/auth/login", "POST", body, public=True)
        password = None
        if (
            not isinstance(result, dict)
            or not result.get("access_token")
            or result.get("actor") != username
        ):
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
        return {
            "signed_in": True,
            "actor": result["actor"],
            "role": result.get("role"),
            "expires_at": result["expires_at"],
        }

    def persona(self, actor):
        status = self.call("/auth/status", public=True)
        if not status.get("demo") or status.get("configured"):
            raise CLIError(
                "Persona switching requires server demo mode with no accounts; use login instead"
            )
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
        incident = self.call("/security/lockdown")
        if incident.get("enabled") is not False or type(incident.get("generation")) is not int:
            raise CLIError("Execution is locked or its state is unavailable. Use lockdown status.")
        if lease.get("lockdown_generation", 0) != incident["generation"]:
            raise CLIError(
                "This lease predates an incident-control change. Request a fresh lease from the Data Owner."
            )
        if save:
            self.session.value.pop("public_auto_chat", None)
            self.session.value["selected_lease"] = {
                "id": lease["id"],
                "actor": me["id"],
                "mode": lease["mode"],
            }
            self.session.save()
        return lease

    def run(self, prompt, lease_id=None, purpose=None, parent_task_id=None):
        selected = self.session.value.get("selected_lease", {})
        if not lease_id:
            lease_id = selected.get("id")
            if lease_id and selected.get("actor") != self.session.value.get("actor"):
                raise CLIError(
                    "Selected lease belongs to another account; select it again with use <lease-id>"
                )
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

    def chat(self, prompt, *, image=None, preview=False):
        if not prompt.strip() or len(prompt) > 8000:
            raise CLIError("PUBLIC prompt must contain 1-8000 characters")
        body = {"prompt": prompt, "classification": "PUBLIC"}
        if image:
            import base64

            path = no_links(image)
            if not path.is_file() or path.stat().st_size > 2_000_000:
                raise CLIError("Provide one PUBLIC local image of at most 2 MB")
            body["images"] = [base64.b64encode(path.read_bytes()).decode("ascii")]
        return self.call("/chat/route" if preview else "/chat", "POST", body)
