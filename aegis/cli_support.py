"""Local operator guidance and read-only diagnostics; no model calls or downloads."""
import re


GUIDES = {
    "start": [
        "doctor — inspect local API, identity, lockdown, receipts and image dependencies",
        "login operator — sign in with a hidden password prompt",
        "context — inspect your selected lease and its current authorization",
        "help coding | images | models | security | recovery | accounts — workflow guides",
        "help <command> — exact arguments; --help — full command reference",
        "In the shell: /compose for multiline input; /exit to leave. No command history is saved.",
    ],
    "coding": [
        "Data Owner: import <directory> --name <name>; private/generated files are excluded",
        "Operator: register <provider-id>; note the Capsule and approval IDs",
        "Model Custodian and Security Officer each: approve <approval-id> approve",
        "Model Custodian: activate <capsule-id> <approval-id>",
        "Data Owner: lease --repo <id> --capsule <id> --recipient operator --mode PLAN",
        "Operator: use <lease-id>, then context and run <prompt> (or /compose in the shell)",
        "EXECUTE only: diff <task-id>, then apply <task-id> <exact-diff-hash>",
        "Export requires an export-enabled lease, export-request, independent review/approvals, then export.",
    ],
    "images": [
        "media-capabilities — check decoder, operations and current limitations",
        "Operator: media-register <provider-id>; approve and activate the Capsule with independent reviewers",
        "media-prepare request.json --image <local-image> — prepare exact content for review",
        "Data Owner and Security Officer: media-review <task-id>, then approve <approval-id> approve",
        "Operator: media-run <task-id>; media-export-request <task-id> for an approved local export",
        "media-revoke <task-id> — revoke retained image content",
        "Understanding, generation and editing require their configured local servers; no automatic downloads.",
    ],
    "models": [
        "bundle-verify <directory> --trust-policy <file> — verify an independently signed offline bundle",
        "Model Custodian: provider-add profile.json; providers lists registered connections",
        "provider-probe <id> explicitly contacts that local model server",
        "provider-qualify <id> suite.json explicitly runs PUBLIC text candidate tests",
        "Candidate tests do not approve a model or prove its serving process, retention or network isolation.",
    ],
    "security": [
        "lockdown status — inspect the persistent incident stop",
        "Security Officer: lockdown enable — stop governed execution and content release",
        "lockdown disable permits fresh authorization; old leases and media tasks stay invalid",
        "verify — verify local receipt-chain integrity; no independent hardware witness is claimed",
        "close <task-id>, revoke <lease-id>, media-revoke <task-id> — explicit cleanup/revocation",
        "Application lockdown cannot terminate model processes, retract sent data or silence Windows networking.",
    ],
    "recovery": [
        "backup create <new-file> — create an encrypted archive with a hidden local passphrase prompt",
        "backup verify <file> — authenticate the archive and its database/receipt chain",
        "backup drill <file> <new-directory> — restore and verify files without replacing live data",
        "Keep a verified copy on separate offline media and its passphrase separately.",
        "Restores revoke sessions and require fresh execution approvals; check historical lockdown state.",
    ],
    "accounts": [
        "users roles — list the fixed local account roles",
        "Local administrator: users set <actor> — provision/reset with hidden password prompts",
        "login <actor>, whoami, logout — local session operations",
        "Password resets revoke that account's sessions; use independent credentials for reviewers.",
        "persona is only for explicitly enabled demo mode before accounts exist.",
    ],
}

CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def terminal_text(value):
    """Make terminal controls and bidi overrides visible, preserving lines/tabs."""
    return CONTROL_TEXT.sub(lambda match: f"\\u{ord(match[0]):04x}", str(value))


def doctor(client, error_type):
    checks = []

    def check(name, endpoint, inspect, *, public=False):
        try:
            result = client.call(endpoint, public=public)
            if not isinstance(result, dict):
                raise error_type("Server returned an unexpected diagnostic response")
            state, detail, next_step = inspect(result)
        except error_type as error:
            state, detail, next_step = "UNAVAILABLE", str(error), "Check the local server/session, then retry doctor."
        checks.append({"check": name, "status": state, "detail": detail, "next_step": next_step})

    check("accounts", "/auth/status", lambda r: (
        "PASS" if r.get("configured") else "ATTENTION",
        "Local accounts configured" if r.get("configured") else "No accounts; demo identity is not authentication",
        "login <actor>" if r.get("configured") else "users set <actor>"), public=True)
    check("local_api", "/coding/status", lambda r: (
        "PASS" if r.get("enabled") else "ATTENTION", "Local API responded; this does not validate a model", "help coding"), public=True)
    if client.session.value.get("access_token") or client.session.value.get("demo_persona"):
        check("identity", "/auth/me", lambda r: ("PASS", f"{r.get('id')} / {r.get('role')}", "whoami"))
        check("lockdown", "/security/lockdown", lambda r: (
            "BLOCKED" if r.get("enabled") is True else "PASS" if r.get("enabled") is False else "ATTENTION",
            "Execution stopped" if r.get("enabled") else "See generation when selecting a lease", "lockdown status"))
        check("receipt_chain", "/control/receipts/verify", lambda r: (
            "PASS" if r.get("is_valid") is True else "BLOCKED", r.get("status", "Unknown integrity"), "verify"))
        check("image_decoder", "/media/capabilities", lambda r: (
            "PASS" if r.get("image_decoder") else "ATTENTION",
            "Decoder installed; model quality untested" if r.get("image_decoder") else "Pillow is not installed",
            "Use the reviewed offline requirements-media.txt setup; media-capabilities for details."))
    else:
        checks.append({"check": "authenticated_checks", "status": "UNAVAILABLE",
                       "detail": "Sign in to check identity, lockdown, receipts and image dependencies", "next_step": "login <actor>"})
    return {"kind": "diagnostics", "status": "PASS" if all(c["status"] == "PASS" for c in checks) else "NEEDS_ATTENTION",
            "api_url": client.url, "checks": checks, "model_calls": 0,
            "scope": "Local application checks only; no model, firewall, backup or production assurance is inferred."}
