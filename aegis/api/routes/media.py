"""Authenticated media approval, preview and local execution."""
import base64
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from aegis.media import service
from aegis.security.auth import principal

router = APIRouter(prefix="/api/media", tags=["Governed local images"])


class CapsuleRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    provider: str = Field(min_length=1, max_length=100)


class ExportRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    approval_id: str = Field(min_length=1, max_length=100)


@router.get("/capabilities")
def capabilities(identity=Depends(principal)):
    return service.capabilities()


@router.post("/capsules")
def capsule(req: CapsuleRequest, identity=Depends(principal)):
    return service.register_capsule(req.provider, identity)


@router.post("/tasks", status_code=201)
def prepare(req: service.MediaRequest, identity=Depends(principal)):
    return service.prepare(req.model_dump(), identity)


@router.get("/tasks/{task_id}")
def view(task_id: str, identity=Depends(principal)):
    return service.view(task_id, identity)


@router.get("/tasks/{task_id}/images/{phase}/{index}")
def preview(task_id: str, phase: str, index: int, identity=Depends(principal)):
    value = service.view(task_id, identity)
    candidates = value["request"]["images"] if phase == "input" else value.get("result", {}).get("images", []) if phase == "output" else []
    if not 0 <= index < len(candidates):
        raise HTTPException(404, "Image not available")
    return Response(base64.b64decode(candidates[index]["data"], validate=True), media_type="image/png",
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Disposition": "inline"})


@router.post("/tasks/{task_id}/run")
def run(task_id: str, identity=Depends(principal)):
    return service.run(task_id, identity)


@router.post("/tasks/{task_id}/revoke")
def revoke(task_id: str, identity=Depends(principal)):
    return service.revoke(task_id, identity)


@router.post("/tasks/{task_id}/export-request")
def request_export(task_id: str, identity=Depends(principal)):
    return service.request_export(task_id, identity)


@router.post("/tasks/{task_id}/export")
def export(task_id: str, req: ExportRequest, identity=Depends(principal)):
    return service.export(task_id, req.approval_id, identity)
