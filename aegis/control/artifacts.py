"""Encrypted retained artifacts and a mandatory, audited local export gateway."""
import json
import time
from cryptography.fernet import Fernet, InvalidToken
from aegis import config
from aegis.control.store import Denied, LOCK, all_objects, canonical, digest, encryption_key, get, put, require, receipt, uid, event
from aegis.control.policy import actor, authorize_label, approved, LEVELS
from aegis.control.data import tripwire, context_check
from aegis.control import leases, packages, capsules
from aegis.storage.paths import contained_file


def retain(task, payload, expires_at):
    identity = uid("ART")
    key = Fernet.generate_key()
    key_ref = uid("RETENTION-KEY")
    encrypted = Fernet(key).encrypt(canonical(payload).encode())
    path = contained_file(config.ARTIFACTS_DIR, identity + ".enc")
    path.write_bytes(encrypted)
    put("artifact-key", key_ref, {"wrapped": Fernet(encryption_key("retention-broker")).encrypt(key).decode()})
    value = {"id": identity, "task_id": task["id"], "owner": task["user"], "label": task["label"],
             "key_ref": key_ref, "expires_at": expires_at, "derivatives": [], "status": "RETAINED",
             "retention_policy": "lease-expiry-or-15-minutes", "filename": path.name,
             "content_hash": digest(payload), "capsule_id": task["capsule_id"], "lease_id": task["lease_id"],
             "skill": task["skill"], "purpose": task["purpose"], "output_type": task["output_type"],
             "source_ids": task["source_ids"], "package_id": task["package_id"]}
    return put("artifact", identity, value)


def erase(value):
    # Revoke the wrapped key first, even if deleting ciphertext fails.
    put("artifact-key", value["key_ref"], {"status": "DESTROYED"})
    try:
        path = contained_file(config.ARTIFACTS_DIR, value["filename"])
        path.unlink(missing_ok=True)
        value["status"] = "DESTROYED"
    except OSError:
        value["status"] = "CLEANUP_FAILED"
        event("TASK_HYGIENE_FAILURE", value["task_id"])
    put("artifact", value["id"], value)
    receipt("RETENTION_DESTRUCTION", artifact_id=value["id"], task_id=value["task_id"],
            key_release_state="DESTROYED", status=value["status"], derivatives=value["derivatives"],
            caches="TASK_LOCAL_CACHES_ALREADY_CLEARED", physical_zeroization="NOT_CLAIMED")
    for child in value["derivatives"]:
        related = require("artifact", child)
        if related["status"] != "DESTROYED":
            erase(related)


def sweep():
    destroyed = []
    with LOCK:
        for value in all_objects("artifact"):
            if value["status"] == "CLEANUP_FAILED" or (value["status"] == "RETAINED" and value["expires_at"] <= time.time()):
                erase(value)
                destroyed.append(value["id"])
    return {"destroyed": destroyed}


def export_binding(value, identity, recipient):
    return {"artifact_id": value["id"], "content_hash": value["content_hash"], "user": identity,
            "recipient": recipient, "output_type": value["output_type"], "lease_id": value["lease_id"]}


def export_artifact(artifact_id, identity, recipient, approval_id=None, restore=False):
    decision = "EXPORT BLOCKED"
    details = {"artifact_id": artifact_id, "recipient": recipient}
    try:
        with LOCK:
            value = require("artifact", artifact_id)
            details.update(task_id=value["task_id"], capsule_id=value["capsule_id"], purpose=value["purpose"],
                           skill=value["skill"], label=value["label"], source_ids=value["source_ids"])
            if identity != value["owner"]:
                raise Denied("UNAUTHORIZED_EXPORT", "Only the artifact's requesting user may export", artifact_id)
            if value["expires_at"] <= time.time():
                if value["status"] == "RETAINED":
                    erase(value)
                raise Denied("EXPIRED_PURPOSE_LEASE", "Artifact retention has expired", artifact_id)
            if value["status"] != "RETAINED":
                raise Denied("UNAUTHORIZED_EXPORT", "Artifact is no longer available", artifact_id)
            task = require("task", value["task_id"])
            if task["status"] != "COMPLETED" or task["hygiene"]["workspace"] != "DESTROYED":
                raise Denied("TASK_HYGIENE_FAILURE", "Export requires verified task cleanup", value["task_id"])
            details["hygiene"] = task["hygiene"]
            authorize_label(identity, value["label"])
            authorize_label(recipient, value["label"])
            leases.validate(value["lease_id"], user=identity, capsule_id=value["capsule_id"], skill=value["skill"],
                purpose=value["purpose"], source_ids=value["source_ids"], compartments=value["label"]["compartments"],
                output_type=value["output_type"], export=True, recipient=recipient)
            package = packages.executable(value["package_id"], value["skill"])
            capsules.attest(value["capsule_id"], capsules.active_components(package, value["skill"]),
                            {"offline": True, "firewall": True, "hygiene": True, "training": False})
            wrapped = require("artifact-key", value["key_ref"])
            if "wrapped" not in wrapped:
                raise Denied("DESTROYED_TASK_KEY", "Artifact key was destroyed")
            key = Fernet(encryption_key("retention-broker")).decrypt(wrapped["wrapped"].encode())
            payload = json.loads(Fernet(key).decrypt(contained_file(config.ARTIFACTS_DIR, value["filename"]).read_bytes()))
            if digest(payload) != value["content_hash"]:
                raise Denied("ARTIFACT_INTEGRITY_FAILURE", "Artifact content changed", artifact_id)
            text = payload["text"]
            tripwire(text, actor(recipient)["compartments"])
            scan = context_check(text, value["label"]["compartments"], value["source_ids"])
            if scan["action"] in {"BLOCK", "QUARANTINE"}:
                raise Denied("UNAUTHORIZED_EXPORT", "Export contains prohibited content", artifact_id)
            binding = export_binding(value, identity, recipient)
            if (LEVELS[value["label"]["classification"]] >= 2 or len(value["label"]["compartments"]) > 1) and not approved(approval_id, "export", binding):
                decision = "EXPORT REQUIRES SECOND APPROVAL"
                return {"decision": decision, "binding": binding, "artifact_id": artifact_id}
            redacted = False
            for private in sorted(payload["protected"], key=len, reverse=True):
                if private and private in text:
                    text = text.replace(private, "[REDACTED]")
                    redacted = True
            if restore:
                # Bound recipient is checked above; only explicit recipient-only/pseudonym tokens can be restored.
                for token, field in payload["restoration"].items():
                    text = text.replace(token, field["value"])
                tripwire(text, actor(recipient)["compartments"])
                if context_check(text, value["label"]["compartments"], value["source_ids"])["action"] in {"BLOCK", "QUARANTINE"}:
                    raise Denied("UNAUTHORIZED_EXPORT", "Restored output contains prohibited content")
            decision = "EXPORT APPROVED WITH REDACTION" if redacted or (payload["protected"] and not restore) else "EXPORT APPROVED"
            return {"decision": decision, "artifact_id": artifact_id, "text": text, "label": value["label"],
                    "recipient": recipient, "output_type": value["output_type"], "sha256": digest(text)}
    except Denied as error:
        details["reason"] = error.code
        return {"decision": decision, "reason": error.code, "event_id": error.event_id, "artifact_id": artifact_id}
    except (InvalidToken, OSError, ValueError, KeyError, TypeError):
        details["reason"] = "ARTIFACT_INTEGRITY_FAILURE"
        event_id = event("ARTIFACT_INTEGRITY_FAILURE", artifact_id)
        return {"decision": "EXPORT BLOCKED", "reason": details["reason"], "event_id": event_id, "artifact_id": artifact_id}
    finally:
        receipt("EXPORT_ATTEMPT", identity, export_decision=decision, **details)
