"""
Aegis Sovereign AI Runtime - Hardware API Route
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List
from aegis.hardware.detector import detect_hardware
from aegis.hardware.simulation import (
    list_hardware_profiles,
    set_active_hardware_profile_name,
    get_active_hardware_profile_name
)
from aegis.hardware.scheduler import get_effective_hardware, evaluate_model_eligibility
from aegis.api.demo import require_demo_mode
import os

router = APIRouter(prefix="/api/hardware", tags=["Hardware"])


@router.get("/capacity")
def model_capacity(parameters_billions: float = Query(gt=0, le=100000, allow_inf_nan=False), bits: int = 4):
    from aegis.hardware.capacity import estimate
    return estimate(parameters_billions, bits)

@router.get("")
def get_hardware_telemetry() -> Dict[str, Any]:
    return get_effective_hardware()

@router.get("/raw-host")
def get_raw_host_detection() -> Dict[str, Any]:
    return detect_hardware()

@router.get("/profiles")
def get_profiles() -> List[Dict[str, Any]]:
    profiles = list_hardware_profiles()
    return profiles if os.environ.get("AEGIS_ENABLE_DEMO_ENDPOINTS") == "1" else [profile for profile in profiles if profile["id"] == "REAL"]

@router.post("/profiles/{profile_id}")
def switch_profile(profile_id: str) -> Dict[str, Any]:
    if profile_id != "REAL":
        require_demo_mode()
    try:
        set_active_hardware_profile_name(profile_id)
        return {
            "status": "SUCCESS",
            "active_profile": profile_id,
            "effective_hardware": get_effective_hardware()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/eligibility")
def get_model_eligibility() -> List[Dict[str, Any]]:
    return evaluate_model_eligibility()
