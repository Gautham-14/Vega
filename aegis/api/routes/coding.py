"""Opt-in local coding workbench. Persona selection is not authentication."""
import os
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from aegis.api.routes.control import principal
from aegis.coding import service

router = APIRouter(prefix="/api/coding", tags=["Governed coding prototype"])


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RepositoryRequest(Strict):
    name: str = Field(min_length=1, max_length=120)
    files: dict[str, str] = Field(min_length=1, max_length=64)
    compartment: Literal["Engineering", "Maintenance", "Finance", "HR", "Public"] = "Engineering"
    classification: Literal["PUBLIC", "INTERNAL"] = "INTERNAL"


class CapsuleRequest(Strict):
    provider: Literal["reference", "ollama"]


class LeaseRequest(Strict):
    repository_id: str
    capsule_id: str
    user: str = "operator"
    mode: Literal["ASK", "PLAN", "EXECUTE"] = "PLAN"
    minutes: int = Field(default=15, ge=1, le=15)
    allow_export: bool = False


class RunRequest(Strict):
    lease_id: str
    prompt: str = Field(min_length=1, max_length=8000)
    purpose: str = Field(min_length=1, max_length=80)


class ApplyRequest(Strict):
    diff_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ExportRequest(Strict):
    approval_id: str


@router.get("/status")
def status():
    return {"enabled": os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") == "1", "identity": "LOCAL_DEMO_PERSONAS_NOT_AUTHENTICATION",
            "workspace": "ENCRYPTED_SNAPSHOTS", "shell": "BLOCKED_NO_OS_SANDBOX", "semantic_search": False,
            "ollama_configured": bool(os.environ.get("AEGIS_OLLAMA_MODEL")), "automatic_downloads": False}


@router.get("/state")
def state(identity=Depends(principal)):
    return service.state(identity)


@router.post("/repositories")
def repository(req: RepositoryRequest, identity=Depends(principal)):
    return service.add_repository(**req.model_dump(), identity=identity)


@router.post("/demo/repository")
def fixture(identity=Depends(principal)):
    return service.add_repository("Port validation sample", service.DEMO_FILES, "Engineering", "INTERNAL", identity)


@router.post("/capsules")
def capsule(req: CapsuleRequest, identity=Depends(principal)):
    return service.register_capsule(req.provider, identity)


@router.post("/leases")
def lease(req: LeaseRequest, identity=Depends(principal)):
    return service.issue_lease(**req.model_dump(), identity=identity)


@router.post("/leases/{lease_id}/revoke")
def revoke(lease_id: str, identity=Depends(principal)):
    return service.revoke(lease_id, identity)


@router.post("/tasks")
def run(req: RunRequest, identity=Depends(principal)):
    return service.run(**req.model_dump(), identity=identity)


@router.get("/tasks/{task_id}")
def task(task_id: str, identity=Depends(principal)):
    return service.view(task_id, identity)


@router.post("/tasks/{task_id}/apply")
def apply(task_id: str, req: ApplyRequest, identity=Depends(principal)):
    return service.apply(task_id, req.diff_hash, identity)


@router.post("/tasks/{task_id}/close")
def close(task_id: str, identity=Depends(principal)):
    return service.close(task_id, identity)


@router.post("/tasks/{task_id}/export-request")
def export_request(task_id: str, identity=Depends(principal)):
    return service.export(task_id, identity, request=True)


@router.post("/tasks/{task_id}/export")
def export(task_id: str, req: ExportRequest, identity=Depends(principal)):
    return service.export(task_id, identity, approval_id=req.approval_id)


@router.post("/validation")
def validation(identity=Depends(principal)):
    from aegis.control.self_test import run_self_test
    return run_self_test(include_coding=True)


@router.get("/approvals/{approval_id}/review")
def review_export(approval_id: str, identity=Depends(principal)):
    return service.review_export(approval_id, identity)
