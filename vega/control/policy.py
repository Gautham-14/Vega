"""Deterministic skills, labels, role simulation and bounded approval decisions."""
import re
import time
from vega.control.store import Denied, LOCK, digest, require, put, receipt, uid

POLICY_VERSION = "vega-prototype-2"
COMPARTMENTS = ["Engineering", "Maintenance", "Finance", "HR", "Public"]
LEVELS = {"PUBLIC": 0, "INTERNAL": 1, "RESTRICTED": 2, "CONFIDENTIAL": 3}
# Personas are a local demo identity simulation, never caller-supplied role claims.
ACTORS = {
    "operator": {"role": "Operator", "compartments": ["Engineering", "Maintenance", "Public"], "clearance": "INTERNAL"},
    "finance-operator": {"role": "Operator", "compartments": ["Finance", "Public"], "clearance": "CONFIDENTIAL"},
    "hr-operator": {"role": "Operator", "compartments": ["HR", "Public"], "clearance": "CONFIDENTIAL"},
    "model-custodian": {"role": "Model Custodian", "compartments": [], "clearance": "PUBLIC"},
    "security-officer": {"role": "Security Officer", "compartments": COMPARTMENTS, "clearance": "CONFIDENTIAL"},
    "data-owner": {"role": "Data Owner", "compartments": COMPARTMENTS, "clearance": "CONFIDENTIAL"},
    "key-custodian": {"role": "Key Custodian", "compartments": [], "clearance": "PUBLIC"},
    "auditor": {"role": "Auditor", "compartments": [], "clearance": "PUBLIC"},
}
SKILLS = {
    "inspection-review-v3": {"name": "Inspection review", "version": 3,
        "task_types": ["inspection"], "purposes": ["maintenance-risk-assessment"],
        "tools": ["search", "calculator", "report", "telemetry"],
        "data_classes": ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"],
        "compartments": ["Engineering", "Maintenance"], "output_types": ["approval-note"],
        "export": "local-recipient-only", "evidence": "authorized-current-source",
        "approval": "high-classification-or-combined"},
    "document-review-v1": {"name": "Document review", "version": 1,
        "task_types": ["review"], "purposes": ["document-review"],
        "tools": ["search", "report"], "data_classes": list(LEVELS),
        "compartments": COMPARTMENTS, "output_types": ["summary"],
        "export": "local-recipient-only", "evidence": "authorized-current-source",
        "approval": "high-classification-or-combined"},
    "ot-advisory-v1": {"name": "OT advisory", "version": 1,
        "task_types": ["telemetry", "action"], "purposes": ["ot-monitoring"],
        "tools": ["telemetry", "report", "record-note", "ot-write"], "data_classes": ["PUBLIC", "INTERNAL"],
        "compartments": ["Engineering", "Maintenance"], "output_types": ["advisory"],
        "export": "local-recipient-only", "evidence": "authorized-current-source",
        "approval": "all-physical-actions"},
}
APPROVAL_ROLES = {
    "capsule": ("Model Custodian", "Security Officer"),
    "package": ("Model Custodian", "Security Officer"),
    "export": ("Data Owner", "Security Officer"),
    "key-release": ("Key Custodian", "Security Officer"),
    "combined-analysis": ("Data Owner", "Security Officer"),
    "ot-write": ("Data Owner", "Security Officer"),
    "policy-change": ("Data Owner", "Security Officer"),
    "rollback-override": ("Model Custodian", "Security Officer"),
    "learning": ("Data Owner", "Security Officer"),
}


def actor(identity, roles=None):
    value = ACTORS.get(identity)
    if not value or (roles and value["role"] not in roles):
        raise Denied("UNAUTHORIZED_ROLE", "This persona cannot perform the action")
    return {"id": identity, **value}


def classify(prompt, documents):
    words = prompt.lower()
    if re.search(r"\b(write|shutdown|shut down|start|stop|actuate|open valve|close valve|setpoint)\b", words):
        kind, skill, purpose = "action", "ot-advisory-v1", "ot-monitoring"
    elif re.search(r"\b(telemetry|sensor|readings)\b", words):
        kind, skill, purpose = "telemetry", "ot-advisory-v1", "ot-monitoring"
    elif re.search(r"\b(pump|inspection|vibration|maintenance)\b", words):
        kind, skill, purpose = "inspection", "inspection-review-v3", "maintenance-risk-assessment"
    else:
        kind, skill, purpose = "review", "document-review-v1", "document-review"
    compartments = sorted({d["compartment"] for d in documents})
    sensitivity = max((d["classification"] for d in documents), key=LEVELS.get, default="PUBLIC")
    return {"task_type": kind, "purpose": purpose, "skill": skill,
            "source_ids": [d["id"] for d in documents], "compartments": compartments,
            "sensitivity": sensitivity, "export_expected": bool(re.search(r"export|report|note|summary", words)),
            "human_approval_required": kind == "action" or LEVELS[sensitivity] >= 2 or len(compartments) > 1,
            "read_only": kind != "action", "authority": "DETERMINISTIC_POLICY"}


def label(documents, kind="generated-summary"):
    return {"compartments": sorted({c for d in documents for c in d.get("compartments", [d.get("compartment")]) if c}),
            "classification": max((d["classification"] for d in documents), key=LEVELS.get, default="PUBLIC"),
            "source_ids": sorted({s for d in documents for s in d.get("source_ids", [d.get("id")]) if s}),
            "kind": kind}


def authorize_label(identity, value):
    principal = actor(identity)
    if not set(value["compartments"]).issubset(principal["compartments"]):
        raise Denied("COMPARTMENT_VIOLATION", "Combined compartment authorization is required")
    if LEVELS[value["classification"]] > LEVELS[principal["clearance"]]:
        raise Denied("UNAUTHORIZED_DATA_REQUEST", "Classification exceeds persona clearance")


def request_approval(action, binding, requester):
    actor(requester)
    if action not in APPROVAL_ROLES:
        raise Denied("INVALID_APPROVAL", "Unknown approval action")
    identity = uid("APR")
    value = {"id": identity, "action": action, "binding": digest(binding), "requester": requester,
             "required_roles": list(APPROVAL_ROLES[action]), "decisions": [], "status": "PENDING",
             "created_at": time.time(), "expires_at": time.time() + 900}
    value["receipt_id"] = receipt("APPROVAL_REQUESTED", requester, approval_id=identity, approval_action=action)["id"]
    return put("approval", identity, value)


def decide(identity, approver, decision):
    with LOCK:
        value = require("approval", identity)
        person = actor(approver, value["required_roles"])
        if (value["status"] != "PENDING" or value["expires_at"] <= time.time()
                or approver == value["requester"] or any(d["actor"] == approver for d in value["decisions"])):
            raise Denied("INVALID_APPROVAL", "Approval is closed, expired, repeated, or self-approved", identity)
        if decision not in {"APPROVE", "REJECT"}:
            raise ValueError("Invalid decision")
        value["decisions"].append({"actor": approver, "role": person["role"], "decision": decision, "timestamp": time.time()})
        if decision == "REJECT":
            value["status"] = "REJECTED"
        elif set(value["required_roles"]).issubset({d["role"] for d in value["decisions"]}):
            value["status"] = "APPROVED"
        value["receipt_id"] = receipt("APPROVAL_DECISION", approver, approval_id=identity, decision=decision)["id"]
        return put("approval", identity, value)


def approved(identity, action, binding):
    if not identity:
        return False
    value = require("approval", identity)
    return (value["status"] == "APPROVED" and value["action"] == action
            and value["binding"] == digest(binding) and value["expires_at"] > time.time())


def tool_guard(skill_id, tool, approval_id=None, binding=None):
    skill = SKILLS.get(skill_id)
    if not skill or tool not in skill["tools"]:
        raise Denied("UNAUTHORIZED_TOOL", "Tool is outside the active skill")
    risk = {"telemetry": "read-only", "search": "read-only", "calculator": "read-only",
            "report": "advisory", "record-note": "low-risk approved action", "ot-write": "high-risk physical action"}[tool]
    if tool == "ot-write" and not approved(approval_id, "ot-write", binding):
        raise Denied("UNAUTHORIZED_HIGH_RISK_ACTION", "Explicit bound human approval required")
    return {"tool": tool, "risk": risk, "mode": "SIMULATED_NO_PHYSICAL_CONNECTION"}
