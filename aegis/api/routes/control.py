"""Local-only, opt-in simulation API. Persona IDs simulate identity, not authentication."""
import os
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from aegis.api.demo import require_demo_mode
from aegis.control import artifacts, capsules, data, demo, leases, packages, policy, store
from aegis.control.runtime import GovernedRunner

router = APIRouter(prefix="/api/control", tags=["Sovereign control plane"])


def principal(x_aegis_actor: str = Header(default="operator")):
    require_demo_mode()
    return policy.actor(x_aegis_actor)["id"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CapsuleRequest(Strict):
    components: dict


class ApprovalRequest(Strict):
    action: Literal["capsule", "package", "export", "key-release", "combined-analysis", "ot-write", "policy-change", "rollback-override", "learning"]
    binding: dict


class Decision(Strict):
    decision: Literal["APPROVE", "REJECT"]


class ApprovalReference(Strict):
    approval_id: str


class ImportRequest(Strict):
    manifest: dict
    artifact: str = Field(max_length=1048576)
    signature: str = Field(max_length=256)
    rollback_approval_id: str | None = None


class SourceRequest(Strict):
    id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=1, max_length=200)
    family: str = Field(min_length=1, max_length=100)
    revision: str = Field(min_length=1, max_length=30)
    status: Literal["CURRENT_APPROVED", "SUPERSEDED", "DRAFT"] = "DRAFT"
    owner: str = Field(min_length=1, max_length=100)
    authority: str = Field(min_length=1, max_length=100)
    equipment: str = Field(min_length=1, max_length=100)
    compartment: Literal["Engineering", "Maintenance", "Finance", "HR", "Public"]
    classification: Literal["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"]
    effective_date: str
    permitted_skills: list[str] = Field(min_length=1, max_length=10)
    fields: dict[str, str]
    field_rules: dict[str, Literal["expose", "mask", "pseudonymize", "remove", "tool-only", "recipient-only"]]


class LeaseRequest(Strict):
    source_ids: list[str] = Field(min_length=1, max_length=100)
    compartments: list[str] = Field(min_length=1, max_length=5)
    purpose: str
    capsule_id: str
    skill: str
    user: str
    role: str
    expires_at: float
    allow_export: bool = False
    allow_persistent_memory: bool = False
    allow_training: bool = False
    output_type: str
    recipient: str


class TaskRequest(Strict):
    prompt: str = Field(min_length=1, max_length=20000)
    equipment: str = Field(min_length=1, max_length=100)
    package_id: str
    capsule_id: str
    lease_id: str
    source_ids: list[str] = Field(min_length=1, max_length=100)
    output_type: str
    recipient: str
    export: bool = True
    combined_approval_id: str | None = None
    key_approval_id: str | None = None
    action_approval_id: str | None = None


class ExportRequest(Strict):
    recipient: str
    approval_id: str | None = None
    restore: bool = False


class Scenario(Strict):
    scenario: Literal["success", "capsule-change", "tripwire", "cache-isolation", "wrong-purpose"]


class VersionPolicy(Strict):
    family: str
    minimum: int = Field(ge=1)
    revoked: list[int]
    approval_id: str


class LearningPlan(Strict):
    source_ids: list[str] = Field(min_length=1)
    compartment: str
    purpose: str
    adapter_id: str
    previous_capsule_id: str
    new_capsule_id: str
    approval_id: str


@router.get("/status")
def status():
    return {"enabled": os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") == "1", "mode": "Software-simulated attestation",
            "identity": "LOCAL_DEMO_PERSONAS_NOT_AUTHENTICATION", "policy_version": policy.POLICY_VERSION,
            "training": "DISABLED", "automatic_chat_learning": "DISABLED", "persistent_memory": "DISABLED",
            "hardware_attestation": False, "physical_zeroization": False, "os_network_isolation": False}


@router.get("/state")
def state(identity=Depends(principal)):
    return {"actors": policy.ACTORS, "skills": policy.SKILLS, "demo": store.get("demo", "main"),
            "capsules": store.all_objects("capsule"), "packages": store.all_objects("package"),
            "sources": [data.public_source(s) for s in store.all_objects("source")],
            "approvals": store.all_objects("approval"), "leases": store.all_objects("lease"),
            "tasks": store.all_objects("task"), "artifacts": store.all_objects("artifact"),
            "receipts": store.receipts(), "chain": store.verify_chain()}


@router.post("/capsules")
def create_capsule(req: CapsuleRequest, identity=Depends(principal)):
    return capsules.register(req.components, identity)


@router.post("/capsules/{capsule_id}/compare")
def compare_capsule(capsule_id: str, req: CapsuleRequest, identity=Depends(principal)):
    return capsules.compare(capsule_id, req.components)


@router.post("/capsules/{capsule_id}/approve")
def approve_capsule(capsule_id: str, req: ApprovalReference, identity=Depends(principal)):
    return capsules.approve(capsule_id, req.approval_id, identity)


@router.post("/approvals")
def approval(req: ApprovalRequest, identity=Depends(principal)):
    return policy.request_approval(req.action, req.binding, identity)


@router.post("/approvals/{approval_id}/decide")
def decision(approval_id: str, req: Decision, identity=Depends(principal)):
    return policy.decide(approval_id, identity, req.decision)


@router.post("/packages/import")
def import_package(req: ImportRequest, identity=Depends(principal)):
    return packages.import_package(req.manifest, req.artifact, req.signature, identity, req.rollback_approval_id)


@router.post("/packages/{package_id}/qualify")
def qualify(package_id: str, identity=Depends(principal)):
    return packages.qualify(package_id, identity)


@router.post("/packages/{package_id}/shadow")
def shadow(package_id: str, identity=Depends(principal)):
    return packages.qualify(package_id, identity, shadow=True)


@router.post("/packages/{package_id}/approve")
def approve_package(package_id: str, req: ApprovalReference, identity=Depends(principal)):
    return packages.approve_package(package_id, req.approval_id, identity)


@router.get("/packages/{package_id}/compatibility")
def hardware(package_id: str, identity=Depends(principal)):
    from aegis.hardware.simulation import HARDWARE_PROFILES
    manifest = store.require("package", package_id)["manifest"]
    return {key: packages.compatibility(manifest, p["available_ram_mb"], p["gpu"]["vram_mb"])
            for key, p in HARDWARE_PROFILES.items() if key != "REAL"}


@router.post("/sources")
def source(req: SourceRequest, identity=Depends(principal)):
    if sum(len(v) for v in req.fields.values()) > 1000000:
        raise HTTPException(413, "Source is too large")
    return data.add_source(req.model_dump(), identity)


@router.post("/leases")
def lease(req: LeaseRequest, identity=Depends(principal)):
    return leases.issue(req.model_dump(), identity)


@router.post("/tasks")
def task(req: TaskRequest, identity=Depends(principal)):
    return GovernedRunner().run(req.model_dump(), identity)


@router.post("/tasks/classify")
def classify_task(req: TaskRequest, identity=Depends(principal)):
    sources = [store.require("source", source_id) for source_id in req.source_ids]
    for source in sources:
        policy.authorize_label(identity, policy.label([source]))
    binding = {"lease_id": req.lease_id, "capsule_id": req.capsule_id, "user": identity, "source_ids": sorted(req.source_ids)}
    return {"classification": policy.classify(req.prompt, sources), "key_and_combined_approval_binding": binding,
            "action_approval_binding": {**binding, "equipment": req.equipment, "action_hash": store.digest(req.prompt)}}


@router.post("/artifacts/{artifact_id}/export")
def export(artifact_id: str, req: ExportRequest, identity=Depends(principal)):
    return artifacts.export_artifact(artifact_id, identity, req.recipient, req.approval_id, req.restore)


@router.post("/retention/sweep")
def retention(identity=Depends(principal)):
    policy.actor(identity, ["Key Custodian", "Security Officer"])
    return artifacts.sweep()


@router.get("/receipts/verify")
def verify(identity=Depends(principal)):
    return store.verify_chain()


@router.post("/demo/prepare")
def prepare(identity=Depends(principal)):
    policy.actor(identity, ["Operator"])
    return demo.prepare()


@router.post("/demo/activate")
def activate(identity=Depends(principal)):
    return demo.activate(identity)


@router.post("/demo/lease")
def demo_lease(identity=Depends(principal)):
    return demo.issue_demo_lease(identity)


@router.post("/demo/run")
def run_demo(req: Scenario, identity=Depends(principal)):
    policy.actor(identity, ["Operator"])
    return demo.run_scenario(req.scenario, identity)


@router.post("/self-test")
def self_test(identity=Depends(principal)):
    from aegis.control.self_test import run_self_test
    return run_self_test()


@router.post("/policies/versions")
def update_versions(req: VersionPolicy, identity=Depends(principal)):
    from aegis.control.governance import version_policy
    return version_policy(req.family, req.minimum, req.revoked, req.approval_id, identity)


@router.post("/learning/review")
def learning(req: LearningPlan, identity=Depends(principal)):
    from aegis.control.governance import learning_plan
    return learning_plan(req.model_dump(), identity)
