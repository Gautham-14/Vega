"""
Vega Sovereign AI Runtime - Hardware Simulation Mode
Defines realistic industrial hardware deployment profiles.
"""
from typing import Dict, Any, List
from vega.storage.database import query_one, execute_write

HARDWARE_PROFILES: Dict[str, Dict[str, Any]] = {
    "REAL": {
        "id": "REAL",
        "name": "Host System Hardware (Live Telemetry)",
        "description": "Uses live CPU, RAM, and GPU detection from host environment.",
        "simulated": False
    },
    "PROFILE_EDGE": {
        "id": "PROFILE_EDGE",
        "name": "Industrial Edge Gateway (Refinery Field Unit)",
        "description": "Ultra-constrained edge computer deployed in field junction boxes.",
        "simulated": True,
        "cpu_physical_cores": 2,
        "cpu_logical_cores": 4,
        "cpu_frequency_mhz": 1800.0,
        "cpu_usage_percent": 18.5,
        "total_ram_mb": 4096,
        "available_ram_mb": 2800,
        "ram_usage_percent": 31.6,
        "gpu": {
            "present": False,
            "name": "None",
            "vram_mb": 0,
            "required": False,
            "status": "NOT REQUIRED"
        }
    },
    "PROFILE_LAPTOP": {
        "id": "PROFILE_LAPTOP",
        "name": "Industrial Rugged Laptop (Field Inspection)",
        "description": "Standard technician field laptop used for local turnaround inspection.",
        "simulated": True,
        "cpu_physical_cores": 4,
        "cpu_logical_cores": 8,
        "cpu_frequency_mhz": 2600.0,
        "cpu_usage_percent": 24.0,
        "total_ram_mb": 8192,
        "available_ram_mb": 5600,
        "ram_usage_percent": 31.6,
        "gpu": {
            "present": False,
            "name": "Integrated Iris Xe (CPU-only execution)",
            "vram_mb": 0,
            "required": False,
            "status": "NOT REQUIRED"
        }
    },
    "PROFILE_WORKSTATION": {
        "id": "PROFILE_WORKSTATION",
        "name": "Control Room Workstation (16GB RAM)",
        "description": "Dedicated on-premise supervisory workstation in main control center.",
        "simulated": True,
        "cpu_physical_cores": 8,
        "cpu_logical_cores": 16,
        "cpu_frequency_mhz": 3400.0,
        "cpu_usage_percent": 32.0,
        "total_ram_mb": 16384,
        "available_ram_mb": 12400,
        "ram_usage_percent": 24.3,
        "gpu": {
            "present": False,
            "name": "None (Dedicated High-Memory CPU)",
            "vram_mb": 0,
            "required": False,
            "status": "NOT REQUIRED"
        }
    },
    "PROFILE_AI_NODE": {
        "id": "PROFILE_AI_NODE",
        "name": "Sovereign AI Server (32GB + RTX 4090)",
        "description": "High-throughput on-premise sovereign AI accelerator rack.",
        "simulated": True,
        "cpu_physical_cores": 16,
        "cpu_logical_cores": 32,
        "cpu_frequency_mhz": 4200.0,
        "cpu_usage_percent": 15.0,
        "total_ram_mb": 32768,
        "available_ram_mb": 27200,
        "ram_usage_percent": 17.0,
        "gpu": {
            "present": True,
            "name": "NVIDIA RTX 4090 24GB",
            "vram_mb": 24576,
            "required": False,
            "status": "DETECTED_OPTIONAL"
        }
    }
}

def get_active_hardware_profile_name() -> str:
    """Get the currently active profile key."""
    row = query_one("SELECT value FROM system_config WHERE key = 'hardware_profile'")
    return row["value"] if row else "REAL"

def set_active_hardware_profile_name(profile_name: str) -> None:
    """Set the active hardware profile key."""
    if profile_name not in HARDWARE_PROFILES:
        raise ValueError(f"Unknown hardware profile: {profile_name}")
    execute_write("UPDATE system_config SET value = ? WHERE key = 'hardware_profile'", (profile_name,))

def list_hardware_profiles() -> List[Dict[str, Any]]:
    """Return all available profiles with active flag."""
    active = get_active_hardware_profile_name()
    result = []
    for k, v in HARDWARE_PROFILES.items():
        copy = dict(v)
        copy["is_active"] = (k == active)
        result.append(copy)
    return result
