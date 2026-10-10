"""Aegis operator entry point and backwards-compatible public CLI facade."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from getpass import getpass

from aegis.cli_support import GUIDES, doctor, terminal_text

from .operator import admin, display, transport
from .operator import shell as interactive_shell
from .operator.common import BASE_URL as BASE_URL
from .operator.common import EXCLUDED_DIRS as EXCLUDED_DIRS
from .operator.common import MAX_FILE_BYTES as MAX_FILE_BYTES
from .operator.common import MAX_FILES as MAX_FILES
from .operator.common import MAX_IMPORT_BYTES as MAX_IMPORT_BYTES
from .operator.common import MAX_JSON_BYTES as MAX_JSON_BYTES
from .operator.common import MAX_RESPONSE_BYTES as MAX_RESPONSE_BYTES
from .operator.common import PRIVATE_NAMES as PRIVATE_NAMES
from .operator.common import PRIVATE_SUFFIXES as PRIVATE_SUFFIXES
from .operator.common import SECRET as SECRET
from .operator.common import CLIError as CLIError
from .operator.common import canonical_url as canonical_url
from .operator.common import no_links as no_links
from .operator.common import redact as redact
from .operator.common import restrict_permissions as restrict_permissions
from .operator.common import safe_endpoint as safe_endpoint
from .operator.common import segment as segment
from .operator.files import export_media as export_media
from .operator.files import export_patch as export_patch
from .operator.files import import_files as import_files
from .operator.files import json_file as json_file
from .operator.files import private_path as private_path
from .operator.parser import build_parser as build_parser
from .operator.shell import compose as compose
from .operator.shell import run_sovereign_pipeline_ui as run_sovereign_pipeline_ui
from .operator.transport import NoRedirects as NoRedirects
from .operator.transport import SessionStore as SessionStore

console, has_rich = display.console, display.has_rich


class Client(transport.Client):
    def __init__(self, url=BASE_URL, timeout=120, session=None, opener=None):
        super().__init__(
            url, timeout, session, opener, password_reader=lambda prompt: getpass(prompt)
        )


def print_result(value, *, json_output=False, plain=False):
    return display.print_result(
        value, json_output=json_output, plain=plain, console=console, has_rich=has_rich
    )


def provision_user(args):
    return admin.provision_user(args, password_reader=getpass)


def backup_command(args):
    return admin.backup_command(args, password_reader=getpass)


def shell(client, parser, *, plain=False):
    return interactive_shell.shell(client, parser, plain=plain, context=sys.modules[__name__])


def execute(args, client):
    command = {"coding-capsule": "register", "coding-lease": "lease", "coding-run": "run"}.get(
        args.command, args.command
    )
    if command == "maintenance":
        return (
            client.call("/security/quotas")
            if args.action == "status"
            else client.call("/security/maintenance", "POST")
        )
    if command == "local-models":
        return client.call("/chat/models")
    if command == "auto":
        if args.action == "on":
            if not args.public:
                raise CLIError(
                    "Use auto on --public to acknowledge PUBLIC-only prompts. Protected work still needs its governed lease."
                )
            status = client.call("/chat/models")
            if not status.get("configured") or not status.get("runtime_managed"):
                raise CLIError("The managed local model runtime is not ready")
        client.session.value["public_auto_chat"] = args.action == "on"
        client.session.save()
        return {
            "auto_chat": args.action == "on",
            "classification": "PUBLIC_ONLY",
            "tools": [],
            "scope": "Ordinary shell prompts only; run/use retain their governed coding lease",
        }
    if command in {"chat", "route"}:
        return client.chat(" ".join(args.text), image=args.image, preview=command == "route")
    if command == "keys":
        from aegis.control import store
        from aegis.security import key_custody
        from aegis.storage.database import init_db

        init_db()
        store.init_control()
        if args.action == "init":
            return key_custody.initialize()
        if os.environ.get("AEGIS_KEY_BROKER_SOCKET"):
            if args.action == "rotate":
                raise CLIError("Stop and rotate keys under the broker identity using key_custody")
            return key_custody.remote({"operation": "status"})
        path = key_custody.local_path()
        with store.LOCK:
            from aegis.security.quiescence import exclusive

            if args.action == "rotate":
                with exclusive("rotating local custody keys"):
                    ring = key_custody.load(path)
                    ring.rotate()
                    key_custody.save(path, ring)
            else:
                ring = key_custody.load(path)
            return key_custody.dispatch(ring, {"operation": "status"})
    if command == "step-up":
        return client.call("/auth/step-up", "POST", {"otp": getpass("Authenticator code: ")})
    if command == "provider-attest-supervised":
        return client.call(f"/providers/{segment(args.id)}/attest-supervised", "POST")
    if command == "provider-refresh-supervised":
        return client.call(f"/providers/{segment(args.id)}/refresh-supervised", "POST")
    if command == "audit-export":
        value = client.call("/security/audit-commitments")
        target = no_links(args.file)
        with target.open("x", encoding="utf-8") as stream:
            restrict_permissions(target)
            json.dump(
                value,
                stream,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        return {
            "path": str(target),
            "count": value["count"],
            "independently_anchored": value.get("independently_anchored", False),
        }
    if command == "help":
        if args.topic in GUIDES:
            return {"kind": "guide", "title": "Aegis / " + args.topic, "steps": GUIDES[args.topic]}
        subcommands = next(
            action
            for action in build_parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        ).choices
        if args.topic not in subcommands:
            raise CLIError("Unknown help topic. Use help for workflows or --help for all commands.")
        return {
            "kind": "guide",
            "title": "Aegis / " + args.topic,
            "reference": subcommands[args.topic].format_help(),
        }
    if command == "doctor":
        previous = client.timeout
        client.timeout = min(previous, 5)
        try:
            return doctor(client, CLIError)
        finally:
            client.timeout = previous
    if command == "context":
        identity = client.call("/auth/me")
        incident = client.call("/security/lockdown")
        selected = client.session.value.get("selected_lease", {})
        lease = client.select_lease(selected["id"], save=False) if selected.get("id") else None
        return {
            "identity": identity,
            "lockdown": incident,
            "lease": None
            if lease is None
            else {
                key: lease.get(key)
                for key in (
                    "id",
                    "mode",
                    "purpose",
                    "expires_at",
                    "lockdown_generation",
                    "allow_export",
                )
            },
            "next_step": "run <prompt> or /compose in the shell" if lease else "use <lease-id>",
            "scope": "Current application authorization; backend checks it again before execution.",
        }
    if command == "compose":
        raise CLIError("Open the shell and use /compose. One-shot prompts use run <text>.")
    if command == "capacity":
        from aegis.hardware.capacity import estimate

        return estimate(args.parameters_billions, args.bits)
    if command == "lockdown":
        return (
            client.call("/security/lockdown")
            if args.action == "status"
            else client.call("/security/lockdown", "POST", {"enabled": args.action == "enable"})
        )
    if command == "bundle-verify":
        from aegis.security.offline_bundle import verify_bundle

        return verify_bundle(args.directory, args.trust_policy)
    if command in {"bundle-record", "bundle-revoke"}:
        from aegis.control import store
        from aegis.security import bundle_custody
        from aegis.storage.database import init_db

        init_db()
        store.init_control()
        return (
            bundle_custody.record(args.directory, args.trust_policy)
            if command == "bundle-record"
            else bundle_custody.revoke(args.id)
        )
    if command == "media-capabilities":
        return client.call("/media/capabilities")
    if command in {"advisory-capabilities", "advisory-sources"}:
        return client.call("/advisory/" + command.removeprefix("advisory-"))
    if command == "advisory-register":
        return client.call("/advisory/capsules", "POST", {"provider": args.provider})
    if command in {"advisory-source", "advisory-lease", "advisory-lease-review", "advisory-run"}:
        endpoint = {
            "advisory-source": "sources",
            "advisory-lease": "leases",
            "advisory-lease-review": "leases/review",
            "advisory-run": "tasks",
        }[command]
        return client.call("/advisory/" + endpoint, "POST", json_file(args.file))
    if command == "advisory-revoke":
        return client.call(f"/advisory/leases/{segment(args.id)}/revoke", "POST")
    if command in {"advisory-task", "advisory-close", "advisory-export-request", "advisory-export"}:
        endpoint = f"/advisory/tasks/{segment(args.id)}"
        if command == "advisory-task":
            return client.call(endpoint)
        suffix = command.removeprefix("advisory-")
        return client.call(
            endpoint + "/" + suffix,
            "POST",
            {"approval_id": args.approval_id} if command == "advisory-export" else None,
        )
    if command == "media-register":
        return client.call("/media/capsules", "POST", {"provider": args.provider})
    if command == "media-prepare":
        value = json_file(args.file)
        if args.image:
            if value.get("images") or len(args.image) > 4:
                raise CLIError("Use up to four --image files; do not also include images in JSON")
            value["images"] = []
            for filename in args.image:
                if filename.startswith(("\\\\", "//")):
                    raise CLIError("Images must be local files")
                path = no_links(filename)
                if not path.is_file():
                    raise CLIError("Image must be a regular local file")
                with path.open("rb") as stream:
                    raw = stream.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise CLIError("Image exceeds 2 MB")
                value["images"].append(base64.b64encode(raw).decode("ascii"))
        return client.call("/media/tasks", "POST", value)
    if command in {"media-review", "media-run", "media-revoke", "media-export-request"}:
        path = f"/media/tasks/{segment(args.id)}"
        result = (
            client.call(path)
            if command == "media-review"
            else client.call(path + "/" + command.removeprefix("media-"), "POST")
        )
        for field, phase in (("request", "input"), ("result", "output")):
            for index, item in enumerate(result.get(field, {}).get("images", [])):
                item.pop("data", None)
                item["preview_url"] = client.url + path + f"/images/{phase}/{index}"
        return result
    if command == "media-export":
        return export_media(client, args.id, args.approval_id, args.file)
    if command == "manifest-hash":
        from aegis.models.manifest import ModelManifest, compute_manifest_sha256

        value = json_file(args.file)
        value["sha256"] = "0" * 64
        value = ModelManifest.model_validate(value).model_dump()
        value["sha256"] = compute_manifest_sha256(value)
        return value
    if command == "login":
        return client.login(args.username, mfa=True) if args.mfa else client.login(args.username)
    if command == "logout":
        try:
            return client.call("/auth/logout", "POST")
        finally:
            client.session.clear()
    if command == "persona":
        return client.persona(args.actor)
    if command == "users":
        return provision_user(args)
    if command == "backup":
        return backup_command(args)
    if command == "status":
        return {
            "authentication": client.call("/auth/status", public=True),
            "coding": client.call("/coding/status", public=True),
            "api_url": client.url,
        }
    if command in {"demo", "pipeline"}:
        prompt_val = (
            getattr(args, "prompt", None)
            or "Review Pump P-204 vibration readings against engineering SOP"
        )
        return run_sovereign_pipeline_ui(
            prompt_val, plain=getattr(args, "plain", False), client=client
        )
    get_routes = {
        "whoami": "/auth/me",
        "state": "/coding/state",
        "control-state": "/control/state",
        "providers": "/providers",
        "tasks": "/coding/tasks",
        "leases": "/coding/leases",
        "repositories": "/coding/repositories",
        "telemetry": "/telemetry/latest",
        "endpoints": "/endpoints",
        "receipts": "/control/receipts",
        "sandbox": "/coding/sandbox",
    }
    if command in get_routes:
        return client.call(get_routes[command])
    post_routes = {
        "validate": "/coding/validation",
        "demo-prepare": "/control/demo/prepare",
        "demo-activate": "/control/demo/activate",
        "coding-fixture": "/coding/demo/repository",
    }
    if command in post_routes:
        return client.call(post_routes[command], "POST")
    if command == "provider":
        return client.call(f"/providers/{segment(args.id)}")
    if command == "provider-preflight":
        return client.call(f"/providers/{segment(args.id)}/preflight")
    if command == "provider-add":
        return client.call("/providers", "POST", json_file(args.file))
    if command == "provider-probe":
        return client.call(f"/providers/{segment(args.id)}/probe", "POST")
    if command == "provider-qualify":
        return client.call(f"/providers/{segment(args.id)}/qualify", "POST", json_file(args.suite))
    if command == "provider-qualify-media":
        return client.call(
            f"/providers/{segment(args.id)}/qualify-media", "POST", json_file(args.suite)
        )
    if command == "provider-qualify-advisory":
        return client.call(
            f"/providers/{segment(args.id)}/qualify-advisory", "POST", json_file(args.suite)
        )
    if command == "embedding-qualify":
        from aegis.control import store
        from aegis.security.embedding_qualification import run
        from aegis.storage.database import init_db

        init_db()
        store.init_control()
        return run(args.directory, args.digest, json_file(args.suite))
    if command == "provider-attest":
        return client.call(
            f"/providers/{segment(args.id)}/attestations", "POST", json_file(args.file)
        )
    if command == "provider-refresh":
        return client.call(
            f"/providers/{segment(args.id)}/release/refresh", "POST", json_file(args.file)
        )
    if command == "provider-measure":
        if args.pid <= 0:
            raise CLIError("PID must be positive")
        return client.call(f"/providers/{segment(args.id)}/measurement?pid={args.pid}")
    if command == "provider-release":
        return client.call(
            f"/providers/{segment(args.id)}/release",
            "POST",
            {"approval_id": segment(args.approval_id)},
        )
    if command == "provider-release-review":
        return client.call(
            f"/providers/{segment(args.id)}/release-candidates/{segment(args.candidate_id)}"
        )
    if command == "provider-assurance":
        return client.call(f"/providers/{segment(args.id)}/assurance")
    if command == "provider-revoke-release":
        return client.call(f"/providers/{segment(args.id)}/release/revoke", "POST")
    if command == "register":
        provider = args.profile or args.provider or "reference"
        if args.profile and args.provider and args.profile != args.provider:
            raise CLIError("Specify one provider profile")
        return client.call("/coding/capsules", "POST", {"provider": provider})
    if command == "approve":
        return client.call(
            f"/control/approvals/{segment(args.id)}/decide",
            "POST",
            {"decision": args.decision.upper()},
        )
    if command == "activate":
        return client.call(
            f"/control/capsules/{segment(args.capsule_id)}/approve",
            "POST",
            {"approval_id": args.approval_id},
        )
    if command == "lease":
        return client.call(
            "/coding/leases",
            "POST",
            {
                "repository_id": args.repo,
                "capsule_id": args.capsule,
                "user": args.recipient,
                "mode": args.mode,
                "minutes": args.minutes,
                "allow_export": args.export,
            },
        )
    if command == "use":
        return client.select_lease(args.id)
    if command == "run":
        if args.text and args.prompt:
            raise CLIError("Pass prompt text or --prompt, not both")
        return client.run(
            args.prompt if args.prompt is not None else " ".join(args.text),
            args.lease,
            args.purpose,
            args.parent_task,
        )
    if command == "import":
        files, skipped = import_files(args.paths)
        if skipped:
            print(
                "Excluded private/generated/link paths: " + json.dumps(skipped, ensure_ascii=True),
                file=sys.stderr,
            )
        result = client.call(
            "/coding/repositories",
            "POST",
            {
                "name": args.name,
                "files": files,
                "compartment": args.compartment,
                "classification": args.classification,
            },
        )
        return {"repository": result, "imported_files": sorted(files), "skipped": skipped}
    if command in {"task", "diff"}:
        result = client.call(f"/coding/tasks/{segment(args.id)}")
        return (
            {
                key: result.get(key)
                for key in ("id", "status", "diff_hash", "diff", "reason", "host_checkout_modified")
            }
            if command == "diff"
            else result
        )
    if command in {"apply", "revert"}:
        if not re.fullmatch(r"[a-f0-9]{64}", args.diff_hash):
            raise CLIError("Review hash must contain exactly 64 lowercase hexadecimal characters")
        return client.call(
            f"/coding/tasks/{segment(args.id)}/{command}", "POST", {"diff_hash": args.diff_hash}
        )
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
        return (
            client.call(f"/receipts/{segment(args.id)}/verify", "POST")
            if args.id
            else client.call("/control/receipts/verify")
        )
    if command == "api":
        safe_endpoint(args.endpoint)
        if not args.endpoint.startswith("/api/") or args.endpoint.startswith("/api/auth/"):
            raise CLIError(
                "Use an /api/... operation endpoint; use login/logout/whoami for authentication"
            )
        if args.method == "GET" and args.file:
            raise CLIError("GET requests do not accept a request file")
        return client.call(
            args.endpoint[4:], args.method, json_file(args.file) if args.file else None
        )
    raise CLIError("Unknown command; use --help")


def failed_result(value):
    return isinstance(value, dict) and (
        value.get("status")
        in {"BLOCKED", "FAILED", "FAIL", "DENIED", "REJECTED", "NEEDS_ATTENTION"}
        or any(value.get(key) is False for key in ("valid", "is_valid", "passed", "all_passed"))
    )


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.json and (not args.command or args.command == "shell"):
            raise CLIError(
                "--json requires a one-shot command; use --plain shell for interactive text."
            )
        if args.command in {"users", "backup"}:
            print_result(
                provision_user(args) if args.command == "users" else backup_command(args),
                json_output=args.json,
                plain=args.plain,
            )
            return 0
        if args.command in {"capacity", "manifest-hash", "bundle-verify", "help", "keys"}:
            print_result(execute(args, None), json_output=args.json, plain=args.plain)
            return 0
        client = Client(args.url, args.timeout)
        if args.persona:
            client.persona(args.persona)
        if not args.command or args.command == "shell":
            return shell(client, parser, plain=args.plain)
        result = execute(args, client)
        print_result(result, json_output=args.json, plain=args.plain)
        return 1 if failed_result(result) else 0
    except (CLIError, OSError, ValueError, subprocess.SubprocessError) as error:
        if args.json:
            print_result({"status": "FAILED", "error": str(error)}, json_output=True)
        else:
            print("Error: " + terminal_text(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
