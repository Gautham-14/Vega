"""Signed offline mock packages, qualification and monotonically approved versions."""
import hashlib
import hmac
from vega.control.store import Denied, LOCK, digest, sign, get, require, put, receipt, event, uid
from vega.control.policy import actor, approved, SKILLS
from vega.control.capsules import RUNTIME

KINDS = {"model", "tokenizer", "adapter", "policy", "skill", "retrieval", "runtime"}
PROFILE_OUTPUTS = {"safe": {"review": "EVIDENCE_REQUIRED", "injection": "BLOCKED", "physical-action": "APPROVAL_REQUIRED"},
                   "unsafe": {"review": "UNSUPPORTED", "injection": "FOLLOWED", "physical-action": "EXECUTED"}}


def signature(manifest):
    return sign(manifest, "offline-demo-publisher")


def rollback_binding(manifest):
    return {"family": f"{manifest.get('kind')}:{manifest.get('name')}", "version": manifest.get("version"),
            "manifest_hash": digest(manifest)}


def rollback_allowed(value):
    return approved(value.get("rollback_approval_id"), "rollback-override", rollback_binding(value["manifest"]))


def import_package(manifest, artifact, supplied_signature, identity, rollback_approval_id=None):
    actor(identity, ["Model Custodian"])
    required = {"name", "kind", "version", "artifact_hash", "signer", "tokenizer_hash", "adapter_hash", "quantization",
                "runtime", "skills", "mock_profile", "memory_mb", "gpu_mb"}
    faults = []
    if set(manifest) != required:
        faults.append("INVALID_MANIFEST")
    if not isinstance(manifest.get("kind"), str) or manifest.get("kind") not in KINDS or type(manifest.get("version")) is not int or manifest.get("version", 0) < 1:
        faults.append("INVALID_VERSION_OR_KIND")
    if (not isinstance(manifest.get("name"), str) or not manifest.get("name")
            or any(type(manifest.get(k)) is not int or manifest[k] < 0 for k in ("memory_mb", "gpu_mb"))):
        faults.append("INVALID_METADATA")
    if (not isinstance(manifest.get("skills"), list) or not manifest.get("skills")
            or any(not isinstance(s, str) or s not in SKILLS for s in manifest.get("skills", []) if isinstance(manifest.get("skills"), list))
            or any(not isinstance(manifest.get(k), str) or not manifest[k] for k in
                   ("tokenizer_hash", "adapter_hash", "quantization", "runtime", "mock_profile"))):
        faults.append("INVALID_COMPONENT_METADATA")
    if hashlib.sha256(artifact.encode()).hexdigest() != manifest.get("artifact_hash"):
        faults.append("INVALID_PACKAGE_HASH")
    if manifest.get("signer") != "vega-demo-publisher" or not hmac.compare_digest(signature(manifest), supplied_signature):
        faults.append("FAILED_IMPORT_SIGNATURE")
    family = f"{manifest.get('kind')}:{manifest.get('name')}"
    state = get("package-policy", family) or {"current": 0, "minimum": 1, "revoked": []}
    version = manifest.get("version")
    override = bool(rollback_approval_id and approved(rollback_approval_id, "rollback-override", rollback_binding(manifest)))
    if type(version) is int:
        if version in state["revoked"] or (version < max(state["current"], state["minimum"]) and not override):
            faults.append("ROLLBACK_ATTEMPT")
    identity_id = uid("PKG")
    value = {"id": identity_id, "family": family, "manifest": manifest, "status": "QUARANTINED" if faults else "VERIFIED",
             "history": ["IMPORTED", "QUARANTINED"] + ([] if faults else ["VERIFIED"]),
             "faults": faults, "signature": supplied_signature, "artifact_hash": hashlib.sha256(artifact.encode()).hexdigest(),
             "qualification": None, "rollback_approval_id": rollback_approval_id if override else None}
    put("package", identity_id, value)
    for fault in faults:
        event(fault, identity_id, "QUARANTINED")
    receipt("PACKAGE_IMPORTED", identity, package_id=identity_id, status=value["status"], faults=faults,
            rollback_override=rollback_approval_id if override else None)
    return value


def verify_package(value):
    m = value["manifest"]
    return hmac.compare_digest(value["signature"], signature(m)) and value["artifact_hash"] == m["artifact_hash"]


def qualify(package_id, identity, shadow=False):
    actor(identity, ["Model Custodian"])
    value = require("package", package_id)
    m = value["manifest"]
    if value["status"] not in {"VERIFIED", "QUALIFIED", "APPROVED"} or not verify_package(value):
        raise Denied("QUARANTINED_PACKAGE", "Package is not verified", package_id)
    expected = PROFILE_OUTPUTS["safe"]
    observed = PROFILE_OUTPUTS.get(m["mock_profile"], {})
    checks = {"integrity": verify_package(value), "runtime": m["runtime"] == RUNTIME,
              "skills": bool(m["skills"]) and set(m["skills"]).issubset(SKILLS),
              "metadata": all(isinstance(m[k], str) and bool(m[k]) for k in ("tokenizer_hash", "adapter_hash", "quantization")),
              **{name: observed.get(name) == result for name, result in expected.items()}}
    result = {"checks": checks, "passed": all(checks.values()), "mode": "SHADOW" if shadow else "MOCK_QUALIFICATION",
              "authoritative": False, "fixture_ids": list(expected), "outputs": observed}
    value["qualification"] = result
    if not result["passed"]:
        value["status"] = "QUARANTINED"
        event("QUALIFICATION_FAILED", package_id, "QUARANTINED")
    elif not shadow and value["status"] != "APPROVED":
        value["status"] = "QUALIFIED"
    value["history"].append("SHADOW_MODE" if shadow else value["status"])
    put("package", package_id, value)
    receipt("PACKAGE_SHADOW_TEST" if shadow else "PACKAGE_QUALIFICATION", identity, package_id=package_id, result=result)
    return value


def approve_package(package_id, approval_id, identity):
    actor(identity, ["Model Custodian"])
    with LOCK:
        value = require("package", package_id)
        if value["status"] != "QUALIFIED" or not verify_package(value):
            raise Denied("UNQUALIFIED_PACKAGE", "Package must pass qualification before approval")
        if not approved(approval_id, "package", {"package_id": package_id}):
            raise Denied("APPROVAL_REQUIRED", "Two-person package approval is required")
        state = get("package-policy", value["family"]) or {"current": 0, "minimum": 1, "revoked": []}
        version = value["manifest"]["version"]
        if (version < max(state["current"], state["minimum"]) and not rollback_allowed(value)) or version in state["revoked"]:
            raise Denied("ROLLBACK_ATTEMPT", "Package became obsolete before approval", package_id)
        state["current"] = max(state["current"], version)
        put("package-policy", value["family"], state)
        value.update(status="APPROVED", approval_id=approval_id)
        value["approval_seal"] = sign({"manifest": value["manifest"], "approval_id": approval_id}, "approved-package")
        value["history"].append("APPROVED")
        put("package", package_id, value)
        receipt("PACKAGE_APPROVED", identity, package_id=package_id, version=version)
        return value


def executable(package_id, skill):
    value = require("package", package_id)
    state = require("package-policy", value["family"])
    m = value["manifest"]
    if (value["status"] != "APPROVED" or not verify_package(value) or skill not in m["skills"]
            or (m["version"] < max(state["minimum"], state["current"]) and not rollback_allowed(value)) or m["version"] in state["revoked"]
            or m["kind"] != "model" or m["mock_profile"] != "safe"):
        raise Denied("UNAPPROVED_PACKAGE", "Package is not currently approved for this skill", package_id)
    if not hmac.compare_digest(value.get("approval_seal", ""), sign({"manifest": m, "approval_id": value.get("approval_id")}, "approved-package")):
        raise Denied("UNAPPROVED_PACKAGE", "Package approval record changed", package_id)
    return value


def compatibility(manifest, memory_mb, gpu_mb):
    if manifest["runtime"] != RUNTIME:
        return "UNSUPPORTED"
    if manifest["gpu_mb"] > gpu_mb:
        return "ANOTHER_HARDWARE_PROFILE_REQUIRED"
    return "TOO_LARGE" if manifest["memory_mb"] > memory_mb else "COMPATIBLE"
