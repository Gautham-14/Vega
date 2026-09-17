"""
Vega Hardware Package
"""
from vega.hardware.detector import detect_hardware
from vega.hardware.simulation import (
    HARDWARE_PROFILES,
    get_active_hardware_profile_name,
    set_active_hardware_profile_name,
    list_hardware_profiles
)
from vega.hardware.scheduler import get_effective_hardware, evaluate_model_eligibility

__all__ = [
    "detect_hardware",
    "HARDWARE_PROFILES",
    "get_active_hardware_profile_name",
    "set_active_hardware_profile_name",
    "list_hardware_profiles",
    "get_effective_hardware",
    "evaluate_model_eligibility"
]
