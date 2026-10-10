"""
Aegis Hardware Package
"""

from aegis.hardware.detector import detect_hardware
from aegis.hardware.scheduler import evaluate_model_eligibility, get_effective_hardware
from aegis.hardware.simulation import (
    HARDWARE_PROFILES,
    get_active_hardware_profile_name,
    list_hardware_profiles,
    set_active_hardware_profile_name,
)

__all__ = [
    "detect_hardware",
    "HARDWARE_PROFILES",
    "get_active_hardware_profile_name",
    "set_active_hardware_profile_name",
    "list_hardware_profiles",
    "get_effective_hardware",
    "evaluate_model_eligibility",
]
