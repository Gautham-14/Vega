from __future__ import annotations

import argparse
import os

from .common import (
    BASE_URL,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Aegis terminal operator. Local API only; website displays telemetry."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("AEGIS_API_URL", BASE_URL),
        help="Numeric loopback API URL (or AEGIS_API_URL)",
    )
    parser.add_argument("--timeout", type=float, default=120, help="API timeout in seconds (1-300)")
    parser.add_argument(
        "--persona", help="Explicit demo identity; requires enabled demo server with no accounts"
    )
    parser.add_argument("--plain", action="store_true", help="Disable terminal styling")
    parser.add_argument(
        "--json", action="store_true", help="Emit compact redacted JSON for one-shot commands"
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("local-models", help="Show live model roles and local runtime readiness")
    auto = commands.add_parser(
        "auto", help="Enable PUBLIC-only dynamic chat for ordinary shell prompts"
    )
    auto.add_argument("action", choices=["on", "off"])
    auto.add_argument(
        "--public", action="store_true", help="Acknowledge prompts contain PUBLIC information only"
    )
    for name in ("chat", "route"):
        chat = commands.add_parser(
            name,
            help="Dynamic local PUBLIC chat"
            if name == "chat"
            else "Preview prompt routing without inference",
        )
        chat.add_argument("text", nargs="+")
        chat.add_argument("--public", action="store_true", required=True)
        chat.add_argument("--image", help="One PUBLIC local PNG/JPEG/WebP image, at most 2 MB")
    guide = commands.add_parser("help", help="Guided workflows or exact command arguments")
    guide.add_argument("topic", nargs="?", default="quickstart")
    commands.add_parser("doctor", help="Read-only local diagnostics; no model probes or downloads")
    commands.add_parser(
        "context", help="Inspect identity, selected lease and current incident authorization"
    )
    commands.add_parser(
        "compose", help="Multiline prompt: /send, /preview, /clear or /cancel; shell only"
    )
    for name, help_text in {
        "shell": "Interactive operator shell (default)",
        "status": "Authentication and local runtime status",
        "logout": "Revoke and clear this server's session",
        "whoami": "Show authenticated identity",
        "state": "Coding workspace state",
        "control-state": "Control plane state",
        "providers": "List local provider profiles and supported connections",
        "tasks": "List your coding tasks",
        "leases": "List visible coding leases",
        "repositories": "List visible repository snapshots",
        "validate": "Run local negative-case validation",
        "telemetry": "Read measured local telemetry",
        "receipts": "List control receipts",
        "endpoints": "Discover available API endpoints",
        "demo-prepare": "Prepare explicit control demo",
        "demo-activate": "Activate explicit control demo",
        "coding-fixture": "Import explicit coding demo fixture",
        "sandbox": "Inspect sandbox availability and enforcement",
        "demo": "Run explicitly enabled deterministic control fixture",
        "pipeline": "Run explicitly enabled deterministic control fixture",
    }.items():
        subp = commands.add_parser(name, help=help_text)
        if name in {"demo", "pipeline"}:
            subp.add_argument(
                "--prompt",
                nargs="?",
                default="Review Pump P-204 vibration readings against engineering SOP",
            )
    login = commands.add_parser("login", help="Sign in locally; password is prompted securely")
    incident = commands.add_parser(
        "lockdown", help="Inspect or change the Security Officer incident stop"
    )
    incident.add_argument(
        "action", choices=["status", "enable", "disable"], nargs="?", default="status"
    )
    commands.add_parser(
        "maintenance", help="Inspect quotas or archive signed expired operational records"
    ).add_argument("action", choices=["status", "archive"], nargs="?", default="status")
    login.add_argument("username", nargs="?")
    login.add_argument(
        "--mfa", action="store_true", help="Prompt securely for the enrolled authenticator code"
    )
    commands.add_parser("step-up", help="Verify MFA again before privileged production changes")
    key = commands.add_parser(
        "keys", help="Offline local keyring migration and rotation; stop Aegis first"
    )
    key.add_argument("action", choices=["init", "rotate", "status"])
    commands.add_parser(
        "provider-attest-supervised", help="Import fresh evidence from the independent supervisor"
    ).add_argument("id")
    commands.add_parser(
        "provider-refresh-supervised",
        help="Refresh unchanged evidence within the active approval window",
    ).add_argument("id")
    commands.add_parser(
        "manifest-hash", help="Compute a metadata manifest checksum locally from JSON"
    ).add_argument("file")
    bundle = commands.add_parser(
        "bundle-verify", help="Verify every file in an independently signed offline model bundle"
    )
    bundle.add_argument(
        "directory", help="Offline bundle directory containing manifest.json and manifest.sig"
    )
    bundle.add_argument(
        "--trust-policy",
        required=True,
        help="Separately provisioned trust policy JSON outside the bundle",
    )
    custody = commands.add_parser(
        "bundle-record",
        help="Host admin: verify and persist signed bundle custody in the server data directory",
    )
    custody.add_argument("directory")
    custody.add_argument("--trust-policy", required=True)
    commands.add_parser("bundle-revoke", help="Host admin: revoke a recorded bundle").add_argument(
        "id"
    )
    qualification = commands.add_parser(
        "provider-qualify", help="Run PUBLIC candidate tests; never grants production approval"
    )
    qualification.add_argument("id", help="Registered live provider ID")
    qualification.add_argument("suite", help="Reviewed PUBLIC qualification-suite JSON")
    media_qualification = commands.add_parser(
        "provider-qualify-media",
        help="Run PUBLIC vision/OCR/generation/editing candidate regression tests",
    )
    media_qualification.add_argument("id")
    media_qualification.add_argument("suite")
    advisory_qualification = commands.add_parser(
        "provider-qualify-advisory",
        help="Explicit PUBLIC advisory contract tests; runs a model only when requested",
    )
    advisory_qualification.add_argument("id")
    advisory_qualification.add_argument("suite")
    embed = commands.add_parser(
        "embedding-qualify",
        help="Host admin: run PUBLIC ranking cases against pinned local embeddings",
    )
    embed.add_argument("directory")
    embed.add_argument("digest")
    embed.add_argument("suite")
    attestation = commands.add_parser(
        "provider-attest", help="Import independently signed runtime and zero-egress evidence"
    )
    attestation.add_argument("id", help="Registered live provider ID")
    attestation.add_argument(
        "file", help="JSON containing attestation and detached base64 signature"
    )
    refresh = commands.add_parser(
        "provider-refresh",
        help="Refresh unchanged signed evidence before expiry; fifteen-minute review ceiling",
    )
    refresh.add_argument("id")
    refresh.add_argument("file")
    measure = commands.add_parser(
        "provider-measure", help="Measure local runtime; does not attest network isolation"
    )
    measure.add_argument("id")
    measure.add_argument("pid", type=int)
    release = commands.add_parser(
        "provider-release", help="Activate the exact independently approved provider evidence"
    )
    release.add_argument("id", help="Registered live provider ID")
    release.add_argument("approval_id", help="Approved provider-release review ID")
    commands.add_parser(
        "provider-assurance", help="Revalidate and show a provider's sensitive-data gate"
    ).add_argument("id")
    commands.add_parser(
        "provider-preflight",
        help="Inspect configuration readiness without connecting to or loading a model",
    ).add_argument("id")
    commands.add_parser(
        "provider-revoke-release", help="Security Officer revokes a provider release immediately"
    ).add_argument("id")
    release_review = commands.add_parser(
        "provider-release-review",
        help="Review the exact qualification, process and network evidence",
    )
    release_review.add_argument("id", help="Registered live provider ID")
    release_review.add_argument(
        "candidate_id", help="Release candidate ID returned by provider-attest"
    )
    users = commands.add_parser(
        "users", help="Host administrator provisioning (same AEGIS data directory as server)"
    )
    user_commands = users.add_subparsers(dest="user_command", required=True)
    user_commands.add_parser("roles", help="List supported account roles")
    user_set = user_commands.add_parser("set", help="Create/reset account and revoke its sessions")
    user_set.add_argument("actor")
    user_set.add_argument(
        "--like",
        dest="template",
        help="Immutable built-in role/clearance template for a new named account",
    )
    user_commands.add_parser("list", help="List provisioned accounts and session counts")
    user_commands.add_parser(
        "sessions", help="List account session times without credentials"
    ).add_argument("actor")
    user_commands.add_parser(
        "disable", help="Disable account, revoke sessions and existing work"
    ).add_argument("actor")
    user_commands.add_parser(
        "revoke-sessions", help="Revoke all account sessions and existing work"
    ).add_argument("actor")
    user_commands.add_parser(
        "mfa-enroll", help="Enroll/reset MFA locally; displays the seed once"
    ).add_argument("actor")
    commands.add_parser(
        "audit-export", help="Export receipt hashes only for independent offline anchoring"
    ).add_argument("file")
    backup = commands.add_parser(
        "backup", help="Encrypted offline operational-state backup and recovery"
    )
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_commands.add_parser(
        "create", help="Create a new encrypted backup; prompts for passphrase"
    ).add_argument("file")
    backup_commands.add_parser(
        "verify", help="Authenticate backup, database and receipt chain"
    ).add_argument("file")
    restore = backup_commands.add_parser(
        "restore", help="Restore into a new directory without overwriting live data"
    )
    restore.add_argument("file")
    restore.add_argument("directory")
    drill = backup_commands.add_parser(
        "drill", help="Restore to a new directory and verify written files and receipt chain"
    )
    drill.add_argument("file")
    drill.add_argument("directory")
    commands.add_parser("media-capabilities", help="Inspect local image support and limits")
    commands.add_parser(
        "advisory-capabilities", help="Inspect read-only advisory workflows; no model calls"
    )
    commands.add_parser("advisory-sources", help="List sources visible to your account")
    commands.add_parser(
        "advisory-register", help="Register a local text-provider advisory Capsule"
    ).add_argument("provider")
    for name in ("advisory-source", "advisory-lease", "advisory-lease-review", "advisory-run"):
        commands.add_parser(
            name, help="Submit an explicit advisory request JSON file"
        ).add_argument("file")
    for name in ("advisory-task", "advisory-close", "advisory-revoke", "advisory-export-request"):
        commands.add_parser(
            name, help="Inspect or manage purpose-bound advisory work"
        ).add_argument("id")
    advisory_export = commands.add_parser(
        "advisory-export", help="Retrieve independently approved advisory export"
    )
    advisory_export.add_argument("id")
    advisory_export.add_argument("approval_id")
    commands.add_parser(
        "media-register", help="Register a vision/diffusion Capsule for approval"
    ).add_argument("provider")
    media = commands.add_parser(
        "media-prepare",
        help="Prepare image request JSON and explicitly named local images for review",
    )
    media.add_argument("file")
    media.add_argument(
        "--image", action="append", default=[], help="PNG/JPEG/WebP file; repeat up to four times"
    )
    for name in ("media-review", "media-run", "media-revoke", "media-export-request"):
        commands.add_parser(name, help="Operate a reviewed local image task").add_argument("id")
    media_export = commands.add_parser(
        "media-export", help="Save an approved result to a new PNG or text file"
    )
    media_export.add_argument("id")
    media_export.add_argument("approval_id")
    media_export.add_argument("file")
    capacity = commands.add_parser(
        "capacity", help="Estimate raw model weight memory from TOTAL parameters"
    )
    capacity.add_argument("parameters_billions", type=float)
    capacity.add_argument("--bits", type=int, choices=[2, 3, 4, 8, 16, 32], default=4)
    for command, field, help_text in [
        ("persona", "actor", "Select a demo identity explicitly"),
        ("provider-add", "file", "Register immutable local provider from JSON file"),
        ("provider-probe", "id", "Explicitly probe a local provider"),
        ("use", "id", "Select a live lease owned by signed-in account"),
        ("task", "id", "Read a coding task"),
        ("diff", "id", "Read task diff and review hash"),
        ("export-request", "id", "Request permission to export an applied patch"),
        ("review", "id", "Review exact patch bound to export approval"),
        ("close", "id", "Close task and destroy retained content"),
        ("revoke", "id", "Revoke coding lease"),
        ("provider", "id", "Inspect provider profile"),
    ]:
        commands.add_parser(command, help=help_text).add_argument(field)
    register = commands.add_parser(
        "register",
        aliases=["coding-capsule"],
        help="Register measured Capsule and request dual approval",
    )
    register.add_argument(
        "profile", nargs="?", help="Provider profile ID, reference, or legacy ollama"
    )
    register.add_argument("--provider", help="Alias for provider profile ID")
    approve = commands.add_parser("approve", help="Record account's independent approval decision")
    approve.add_argument("id")
    approve.add_argument("decision", choices=["approve", "reject"])
    activate = commands.add_parser("activate", help="Activate Capsule after required approvals")
    activate.add_argument("capsule_id")
    activate.add_argument("approval_id")
    lease = commands.add_parser(
        "lease", aliases=["coding-lease"], help="Issue scoped coding lease (Data Owner)"
    )
    lease.add_argument("--repo", required=True)
    lease.add_argument("--capsule", required=True)
    lease.add_argument("--mode", choices=["ASK", "PLAN", "EXECUTE"], default="PLAN")
    lease.add_argument("--recipient", "--user", dest="recipient", default="operator")
    lease.add_argument("--minutes", type=int, choices=range(1, 16), default=15)
    lease.add_argument(
        "--export",
        action="store_true",
        help="Explicitly permit approved patch export; off by default",
    )
    run = commands.add_parser(
        "run", aliases=["coding-run"], help="Run prompt under selected lease and its bound purpose"
    )
    run.add_argument("text", nargs="*")
    run.add_argument("--prompt", help="Legacy explicit prompt option")
    run.add_argument("--lease", help="Explicit lease; otherwise use selected lease")
    run.add_argument("--purpose", help="Optional assertion; must match lease purpose")
    run.add_argument("--parent-task", help="Continue an APPLIED task under the same lease")
    imp = commands.add_parser(
        "import", help="Import explicit UTF-8 files or one directory into encrypted snapshot"
    )
    imp.add_argument("paths", nargs="+")
    imp.add_argument("--name", required=True)
    imp.add_argument(
        "--compartment",
        choices=["Engineering", "Maintenance", "Finance", "HR", "Public"],
        default="Engineering",
    )
    imp.add_argument("--classification", choices=["PUBLIC", "INTERNAL"], default="INTERNAL")
    for name in ("apply", "revert"):
        apply = commands.add_parser(
            name,
            help=f"{name.title()} reviewed hash in encrypted snapshot; host checkout untouched",
        )
        apply.add_argument("id")
        apply.add_argument("diff_hash")
    export = commands.add_parser(
        "export", help="Export approved patch to a new local file (never overwrite)"
    )
    export.add_argument("id")
    export.add_argument("approval_id")
    export.add_argument("file")
    commands.add_parser("verify", help="Verify receipt chain, or legacy task receipt").add_argument(
        "id", nargs="?"
    )
    api = commands.add_parser(
        "api", help="Local API escape hatch; endpoints lists operations and schemas"
    )
    api.add_argument("method", type=str.upper, choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    api.add_argument("endpoint", help="An /api/... path on selected loopback server")
    api.add_argument("file", nargs="?", help="Optional UTF-8 JSON request file")
    return parser
