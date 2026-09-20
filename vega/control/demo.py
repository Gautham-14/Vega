"""Explicit, synthetic fixtures. Nothing is seeded during application startup."""
import hashlib
import time
from copy import deepcopy
from vega.control import capsules, packages, leases
from vega.control.data import add_source, canaries, IsolatedCache, tripwire
from vega.control.policy import request_approval, decide, SKILLS
from vega.control.store import get, put, require, Denied, receipt, digest
from vega.control.runtime import GovernedRunner


def package_spec(version=3, profile="safe", name="vega-offline-demo"):
    artifact = f"Synthetic offline model fixture v{version}; profile={profile}"
    manifest = {"name": name, "kind": "model", "version": version, "artifact_hash": hashlib.sha256(artifact.encode()).hexdigest(),
                "signer": "vega-demo-publisher", "tokenizer_hash": digest("mock-tokenizer-v1"), "adapter_hash": digest("no-adapter"),
                "quantization": "MOCK-Q4", "runtime": capsules.RUNTIME, "skills": list(SKILLS),
                "mock_profile": profile, "memory_mb": 64, "gpu_mb": 0}
    return manifest, artifact


def source_spec(identity="DEMO-P204-REV8", compartment="Engineering", classification="INTERNAL"):
    return {"id": identity, "title": "Pump P-204 inspection", "family": "pump-inspection", "revision": "8",
            "status": "CURRENT_APPROVED", "owner": "Synthetic maintenance team", "authority": "Synthetic data owner",
            "equipment": "P-204", "compartment": compartment, "classification": classification,
            "effective_date": "2024-01-01", "permitted_skills": list(SKILLS),
            "fields": {"finding": "Synthetic inspection: P-204 vibration is 7.20 mm/s RMS; human review is required.",
                       "supplier": "Deccan Industrial Systems", "contact": "Demo recipient 204",
                       "account": "SYNTHETIC-PRIVATE-ACCOUNT", "internal": "SYNTHETIC-TOOL-ONLY", "obsolete": "REMOVE-THIS-FIELD"},
            "field_rules": {"finding": "expose", "supplier": "pseudonymize", "contact": "recipient-only",
                            "account": "mask", "internal": "tool-only", "obsolete": "remove"}}


def prepare():
    existing = get("demo", "main")
    if existing:
        for index, action in enumerate(("package", "capsule")):
            request = require("approval", existing["approval_ids"][index])
            if request["status"] == "REJECTED" or (request["status"] == "PENDING" and request["expires_at"] <= time.time()):
                key = action + "_id"
                existing["approval_ids"][index] = request_approval(action, {key: existing[key]}, "operator")["id"]
        put("demo", "main", existing)
        return existing
    manifest, artifact = package_spec()
    package = packages.import_package(manifest, artifact, packages.signature(manifest), "model-custodian")
    packages.qualify(package["id"], "model-custodian")
    capsule = capsules.register(capsules.active_components(package, "inspection-review-v3"), "model-custodian")
    if not get("source", "DEMO-P204-REV8"):
        add_source(source_spec(), "data-owner")
    approvals = [request_approval("package", {"package_id": package["id"]}, "operator"),
                 request_approval("capsule", {"capsule_id": capsule["id"]}, "operator")]
    return put("demo", "main", {"package_id": package["id"], "capsule_id": capsule["id"],
                                "source_ids": ["DEMO-P204-REV8"], "approval_ids": [a["id"] for a in approvals]})


def activate(identity):
    value = require("demo", "main")
    p, c = value["approval_ids"]
    if require("package", value["package_id"])["status"] != "APPROVED":
        packages.approve_package(value["package_id"], p, identity)
    if require("capsule", value["capsule_id"])["status"] != "APPROVED":
        capsules.approve(value["capsule_id"], c, identity)
    return value


def lease_spec(demo, user="operator", compartments=None):
    return {"source_ids": demo["source_ids"], "compartments": compartments or ["Engineering"],
            "purpose": "maintenance-risk-assessment", "capsule_id": demo["capsule_id"], "skill": "inspection-review-v3",
            "user": user, "role": "Operator", "expires_at": time.time() + 900,
            "allow_export": True, "allow_persistent_memory": False, "allow_training": False,
            "output_type": "approval-note", "recipient": user}


def issue_demo_lease(identity):
    demo = require("demo", "main")
    lease = leases.issue(lease_spec(demo), identity)
    demo["lease_id"] = lease["id"]
    put("demo", "main", demo)
    return demo


def task_request(demo):
    if "lease_id" not in demo:
        raise Denied("PURPOSE_LEASE_REQUIRED", "Issue a purpose lease as Data Owner before running this demonstration")
    return {"prompt": "Review pump P-204 inspection and prepare an approval note", "equipment": "P-204",
            "package_id": demo["package_id"], "capsule_id": demo["capsule_id"], "lease_id": demo["lease_id"],
            "source_ids": demo["source_ids"], "output_type": "approval-note", "recipient": "operator", "export": True}


def run_scenario(scenario, identity):
    value = require("demo", "main")
    if scenario == "success":
        return GovernedRunner().run(task_request(value), identity)
    if scenario == "capsule-change":
        components = deepcopy(require("capsule", value["capsule_id"])["components"])
        components["quantization"] = "CHANGED-Q8"
        changed = capsules.register(components, "model-custodian")
        difference = capsules.compare(value["capsule_id"], components)
        try:
            capsules.TaskKey(value["capsule_id"], components, {"offline": True, "firewall": True, "hygiene": True, "training": False})
        except Denied as error:
            receipt("ATTESTATION_DENIED", identity, capsule_id=value["capsule_id"], reason=error.code, key_release_state="NOT_RELEASED")
            return {**difference, "status": "EXPECTED BLOCK", "reason": error.code, "key_release_state": "NOT_RELEASED",
                    "protected_assets": "REMAIN_ENCRYPTED", "candidate_id": changed["id"]}
        raise RuntimeError("Changed Capsule was unexpectedly accepted")
    if scenario == "tripwire":
        class LeakingMock(GovernedRunner):
            def infer(self, sources, disclosed):
                claims = super().infer(sources, disclosed)
                claims[0]["text"] += " " + canaries()["Finance"]
                return claims
        return LeakingMock().run(task_request(value), identity)
    if scenario == "cache-isolation":
        cache = IsolatedCache()
        cache.set("demo", "operator", ["Finance"], "identical prefix", "private Finance state")
        return {"finance_key": cache.key("operator", ["Finance"], "identical prefix"),
                "engineering_key": cache.key("operator", ["Engineering"], "identical prefix"),
                "cross_compartment_hit": cache.read("demo", "operator", ["Engineering"], "identical prefix"),
                "status": "EXPECTED BLOCK"}
    if scenario == "wrong-purpose":
        request = task_request(value)
        request["prompt"] = "Summarize this document"
        request["output_type"] = "summary"
        return GovernedRunner().run(request, identity)
    raise ValueError("Unknown scenario")
