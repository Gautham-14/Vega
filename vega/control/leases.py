"""Signed purpose leases. All dimensions are checked again before export."""
import hmac
import time
from vega.control.store import Denied, uid, sign, put, require, receipt
from vega.control.policy import actor, authorize_label, SKILLS

FIELDS = {"source_ids", "compartments", "purpose", "capsule_id", "skill", "user", "role", "expires_at",
          "allow_export", "allow_persistent_memory", "allow_training", "output_type", "recipient"}


def issue(spec, issuer):
    actor(issuer, ["Data Owner"])
    if set(spec) != FIELDS:
        raise ValueError("Lease fields are incomplete or unknown")
    principal = actor(spec["user"])
    if principal["role"] != spec["role"] or not time.time() < spec["expires_at"] <= time.time() + 86400:
        raise ValueError("Lease role or expiry is invalid (maximum 24 hours)")
    if spec["allow_training"] or spec["allow_persistent_memory"]:
        raise Denied("LEARNING_DISABLED", "Training and persistent chat memory are disabled")
    capsule = require("capsule", spec["capsule_id"])
    skill = SKILLS.get(spec["skill"])
    if (capsule["status"] != "APPROVED" or not skill or spec["purpose"] not in skill["purposes"]
            or spec["output_type"] not in skill["output_types"] or not spec["source_ids"]):
        raise Denied("INVALID_LEASE", "Capsule, purpose, skill, sources or output is not approved")
    compartments = set()
    for source_id in spec["source_ids"]:
        document = require("source", source_id)
        authorize_label(spec["user"], {"compartments": [document["compartment"]], "classification": document["classification"]})
        if spec["skill"] not in document["permitted_skills"] or document["compartment"] not in skill["compartments"]:
            raise Denied("INVALID_LEASE", "Skill cannot use this source", source_id)
        compartments.add(document["compartment"])
    if compartments != set(spec["compartments"]):
        raise Denied("COMPARTMENT_VIOLATION", "Lease compartments must match its sources")
    actor(spec["recipient"])
    value = {"id": uid("LEASE"), "issuer": issuer, "issued_at": time.time(), **spec}
    value["signature"] = sign(value, "purpose-lease")
    put("lease", value["id"], value)
    receipt("LEASE_ISSUED", issuer, lease_id=value["id"], user=spec["user"], purpose=spec["purpose"],
            capsule_id=spec["capsule_id"], source_ids=spec["source_ids"])
    return value


def validate(lease_id, *, user, capsule_id, skill, purpose, source_ids, compartments, output_type,
             export=False, recipient=None, training=False, persistent_memory=False):
    value = require("lease", lease_id)
    body = {k: v for k, v in value.items() if k != "signature"}
    if not hmac.compare_digest(value["signature"], sign(body, "purpose-lease")):
        raise Denied("INVALID_LEASE_SIGNATURE", "Purpose lease was modified", lease_id)
    if value["expires_at"] <= time.time():
        raise Denied("EXPIRED_PURPOSE_LEASE", "Purpose lease has expired", lease_id)
    expected = {"user": user, "role": actor(user)["role"], "capsule_id": capsule_id,
                "skill": skill, "purpose": purpose, "output_type": output_type}
    if any(value[k] != v for k, v in expected.items()):
        raise Denied("PURPOSE_LEASE_MISMATCH", "Purpose, Capsule, skill, identity or output does not match", lease_id)
    if not set(source_ids).issubset(value["source_ids"]) or not set(compartments).issubset(value["compartments"]):
        raise Denied("COMPARTMENT_VIOLATION", "Requested data is outside the lease", lease_id)
    if (training and not value["allow_training"]) or (persistent_memory and not value["allow_persistent_memory"]):
        raise Denied("LEARNING_DISABLED", "Lease denies learning or persistent memory", lease_id)
    if export and (not value["allow_export"] or recipient != value["recipient"]):
        raise Denied("UNAUTHORIZED_EXPORT", "Lease denies this export or recipient", lease_id)
    return value
