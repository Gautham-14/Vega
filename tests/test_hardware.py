"""
Tests for Vega Hardware Detection, Simulation Profiles, and Scheduler
"""
import pytest
from vega.storage.database import init_db
from vega.models.registry import seed_model_registry
from vega.hardware.detector import detect_hardware
from vega.hardware.simulation import (
    list_hardware_profiles,
    set_active_hardware_profile_name,
    get_active_hardware_profile_name
)
from vega.hardware.scheduler import get_effective_hardware, evaluate_model_eligibility

@pytest.fixture(autouse=True)
def setup_env():
    init_db()
    seed_model_registry()

def test_hardware_detector():
    hw = detect_hardware()
    assert "cpu_physical_cores" in hw
    assert "cpu_logical_cores" in hw
    assert "total_ram_mb" in hw
    assert "available_ram_mb" in hw
    assert "gpu" in hw
    assert hw["is_cpu_only_capable"] is True

def test_hardware_simulation_profiles():
    profiles = list_hardware_profiles()
    assert len(profiles) >= 4
    profile_ids = [p["id"] for p in profiles]
    assert "PROFILE_EDGE" in profile_ids
    assert "PROFILE_LAPTOP" in profile_ids
    assert "PROFILE_WORKSTATION" in profile_ids

    # Switch to Edge Profile
    set_active_hardware_profile_name("PROFILE_EDGE")
    assert get_active_hardware_profile_name() == "PROFILE_EDGE"

    eff = get_effective_hardware()
    assert eff["active_profile_id"] == "PROFILE_EDGE"
    assert eff["total_ram_mb"] == 4096

    # Switch back to REAL
    set_active_hardware_profile_name("REAL")
    assert get_active_hardware_profile_name() == "REAL"

def test_resource_aware_eligibility():
    # In Edge mode (4GB RAM), huge 70B model should be INELIGIBLE
    set_active_hardware_profile_name("PROFILE_EDGE")
    evals = evaluate_model_eligibility()

    eval_map = {e["model_id"]: e for e in evals}
    if "UNVERIFIED-EXPERIMENTAL-70B" in eval_map:
        assert eval_map["UNVERIFIED-EXPERIMENTAL-70B"]["eligibility"] == "INELIGIBLE"

    # Reset
    set_active_hardware_profile_name("REAL")
