"""Governed policy updates, default-off learning and the simulated OT/network boundary."""
from vega.control import packages
from vega.control.policy import actor, approved, tool_guard, POLICY_VERSION
from vega.control.store import Denied, require, get, put, receipt


def network_call(destination):
    # Intentional refusal before any socket or DNS resolver can be invoked.
    raise Denied("PROHIBITED_NETWORK_CALL", "External calls are disabled in the mock runtime")


def version_policy(family, minimum, revoked, approval_id, identity):
    actor(identity, ["Security Officer"])
    value = require("package-policy", family)
    binding = {"family": family, "minimum": minimum, "revoked": sorted(set(revoked))}
    if minimum < value["minimum"] or not set(value["revoked"]).issubset(revoked):
        raise Denied("ROLLBACK_ATTEMPT", "Version floors and revocations cannot be weakened")
    if not approved(approval_id, "policy-change", binding):
        raise Denied("APPROVAL_REQUIRED", "Version policy changes require two-person approval")
    value.update(minimum=minimum, revoked=binding["revoked"])
    put("package-policy", family, value)
    receipt("VERSION_POLICY_CHANGED", identity, **binding, policy_version=POLICY_VERSION)
    return value


def learning_plan(spec, identity):
    actor(identity, ["Data Owner"])
    binding = {k: v for k, v in spec.items() if k != "approval_id"}
    for source_id in spec["source_ids"]:
        source = require("source", source_id)
        if source["status"] != "CURRENT_APPROVED" or source["compartment"] != spec["compartment"]:
            raise Denied("LEARNING_DISABLED", "Dataset and compartment are not approved")
    if not spec["source_ids"] or spec["purpose"] != "governed-training" or not approved(spec["approval_id"], "learning", binding):
        raise Denied("LEARNING_DISABLED", "Learning requires explicit dataset and purpose authorization")
    capsule = require("capsule", spec["new_capsule_id"])
    old = require("capsule", spec["previous_capsule_id"])
    if (capsule["status"] != "APPROVED" or capsule["id"] == old["id"]
            or capsule["components"]["adapter"] != spec["adapter_id"]
            or capsule["components"]["adapter"] == old["components"]["adapter"]):
        raise Denied("LEARNING_DISABLED", "A separate adapter and newly approved Capsule are required")
    result = {"status": "AUTHORIZED_FUTURE_PLAN_ONLY", "training_executed": False,
              "automatic_chat_learning": False, "persistent_memory": False}
    receipt("LEARNING_PLAN_REVIEWED", identity, **binding, **result)
    return result
