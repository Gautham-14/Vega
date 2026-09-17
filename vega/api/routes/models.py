"""
Vega Sovereign AI Runtime - Models API Route
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel
from vega.models.manifest import ModelManifest
from vega.api.demo import require_demo_mode
from vega.models.registry import (
    get_all_models,
    get_model_by_id,
    import_model_manifest,
    run_simulated_qualification,
    run_shadow_mode_simulation
)

router = APIRouter(prefix="/api/models", tags=["Models"])

ModelManifestImportRequest = ModelManifest

@router.get("")
def list_models() -> List[Dict[str, Any]]:
    return get_all_models()

@router.get("/{model_id}")
def get_model(model_id: str) -> Dict[str, Any]:
    model = get_model_by_id(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return model

@router.post("/import")
def import_manifest(req: ModelManifestImportRequest) -> Dict[str, Any]:
    try:
        res = import_model_manifest(req.model_dump())
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{model_id}/qualify")
def qualify_model(model_id: str) -> Dict[str, Any]:
    require_demo_mode()
    try:
        return run_simulated_qualification(model_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/{model_id}/shadow")
def shadow_model(model_id: str, baseline_id: str = "VEGA-DEMO-TEXT") -> Dict[str, Any]:
    require_demo_mode()
    try:
        return run_shadow_mode_simulation(model_id, baseline_model_id=baseline_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
