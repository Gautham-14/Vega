"""Authenticated advisory operations, available without demonstration mode."""
from fastapi import APIRouter, Depends
from pydantic import Field
from aegis.advisory import service
from aegis.coding import retrieval
from aegis.control import data, policy, store
from aegis.security.auth import principal

router = APIRouter(prefix="/api/advisory", tags=["Purpose-bound advisory"])


class CapsuleRequest(service.Strict):
    provider: str = Field(min_length=1, max_length=100)


class ExportRequest(service.Strict):
    approval_id: str


@router.get("/capabilities")
def capabilities(identity=Depends(principal)):
    return {"operations": ["source-import", "lease", "advisory", "reviewed-export"], "tools": [],
            "ot_write": False, "automatic_model_loading": False, "automatic_downloads": False,
            "retrieval": retrieval.configuration(), "hardware_attestation": False,
            "live_model_quality": "REQUIRES_LATER_QUALIFICATION", "physical_zeroization": False}


@router.post("/sources", status_code=201)
def source(req: service.SourceRequest, identity=Depends(principal)):
    return service.add_source(req, identity)


@router.get("/sources")
def sources(identity=Depends(principal)):
    result = []
    for source in store.all_objects("source"):
        try:
            policy.authorize_label(identity, policy.label([source]))
        except store.Denied:
            continue
        result.append(data.public_source(source))
    return result


@router.post("/capsules")
def capsule(req: CapsuleRequest, identity=Depends(principal)):
    return service.register_capsule(req.provider, identity)


@router.post("/leases")
def lease(req: service.LeaseRequest, identity=Depends(principal)):
    return service.issue_lease(req, identity)


@router.post("/leases/review")
def lease_review(req: service.LeaseRequest, identity=Depends(principal)):
    return service.lease_review(req, identity)


@router.get("/leases")
def leases(identity=Depends(principal)):
    return [service.public(service.read("lease", item["id"])) for item in store.all_objects("advisory-lease")
            if item["user"] == identity or item["issuer"] == identity]


@router.post("/leases/{lease_id}/revoke")
def revoke(lease_id: str, identity=Depends(principal)):
    return service.revoke(lease_id, identity)


@router.post("/tasks")
def run(req: service.RunRequest, identity=Depends(principal)):
    return service.run(req, identity)


@router.get("/tasks")
def tasks(identity=Depends(principal)):
    service.sweep()
    return [service.public(service.read("task", item["id"])) for item in store.all_objects("advisory-task")
            if item["user"] == identity]


@router.get("/tasks/{task_id}")
def task(task_id: str, identity=Depends(principal)):
    return service.view(task_id, identity)


@router.post("/tasks/{task_id}/close")
def close(task_id: str, identity=Depends(principal)):
    return service.close(task_id, identity)


@router.post("/tasks/{task_id}/export-request")
def export_request(task_id: str, identity=Depends(principal)):
    return service.export(task_id, identity)


@router.post("/tasks/{task_id}/export")
def export(task_id: str, req: ExportRequest, identity=Depends(principal)):
    return service.export(task_id, identity, req.approval_id)
