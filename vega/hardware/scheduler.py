"""
Vega Sovereign AI Runtime - Resource-Aware Model Scheduler & Eligibility
Evaluates whether candidate models can safely execute on detected or simulated hardware.
"""
from typing import Dict, Any, List
from vega.hardware.detector import detect_hardware
from vega.hardware.simulation import HARDWARE_PROFILES, get_active_hardware_profile_name
from vega.models.registry import get_all_models

def get_effective_hardware() -> Dict[str, Any]:
    """
    Get effective hardware specifications, either from real host telemetry
    or from the selected simulation profile.
    """
    profile_name = get_active_hardware_profile_name()
    if profile_name == "REAL":
        detected = detect_hardware()
        detected["active_profile_id"] = "REAL"
        detected["active_profile_name"] = "Host System Hardware (Live Telemetry)"
        detected["is_simulated_profile"] = False
        return detected
    else:
        profile = dict(HARDWARE_PROFILES.get(profile_name, HARDWARE_PROFILES["REAL"]))
        profile["active_profile_id"] = profile_name
        profile["active_profile_name"] = profile["name"]
        profile["is_simulated_profile"] = True
        return profile

def evaluate_model_eligibility() -> List[Dict[str, Any]]:
    """
    Evaluate all models in the offline registry against current effective hardware.
    Determines status: ELIGIBLE, DEGRADED, or INELIGIBLE.
    """
    hw = get_effective_hardware()
    available_ram_mb = hw.get("available_ram_mb", hw.get("total_ram_mb", 8192))
    total_ram_mb = hw.get("total_ram_mb", 8192)
    cpu_cores = hw.get("cpu_logical_cores", 4)
    vram_mb = hw.get("gpu", {}).get("vram_mb", 0)

    models = get_all_models()
    evaluations = []

    for model in models:
        req_ram = model["memory_req_mb"]
        req_cores = model["cpu_cores_req"]
        req_vram = model["gpu_vram_req_mb"]

        # Check eligibility
        reasons = []
        if total_ram_mb < req_ram:
            eligibility = "INELIGIBLE"
            reasons.append(f"Insufficient total RAM: needs {req_ram/1024:.1f}GB, system has {total_ram_mb/1024:.1f}GB")
        elif available_ram_mb < req_ram:
            eligibility = "INELIGIBLE"
            reasons.append(f"Insufficient available RAM: {available_ram_mb/1024:.1f}GB < {req_ram/1024:.1f}GB. No quantization fallback is implemented.")
        elif cpu_cores < req_cores:
            eligibility = "DEGRADED"
            reasons.append(f"CPU threads constrained: {cpu_cores} < {req_cores}. Slower throughput expected.")
        else:
            eligibility = "ELIGIBLE"
            reasons.append(f"Fits within available RAM ({req_ram/1024:.1f}GB / {available_ram_mb/1024:.1f}GB available).")

        # Check GPU VRAM requirements
        if req_vram > 0 and vram_mb < req_vram:
            eligibility = "INELIGIBLE"
            reasons.append(f"Insufficient GPU VRAM: requires {req_vram/1024:.1f}GB; available {vram_mb/1024:.1f}GB. No CPU offload is implemented.")

        evaluations.append({
            "model_id": model["id"],
            "model_name": model["name"],
            "parameters": model["parameters"],
            "capabilities": model["capabilities"],
            "qualification_status": model["status"],
            "memory_req_mb": req_ram,
            "cpu_cores_req": req_cores,
            "eligibility": eligibility,
            "reasons": reasons,
            "hardware_headroom_mb": round(available_ram_mb - req_ram, 1)
        })

    return evaluations
