"""
Vega Sovereign AI Runtime - Hardware Detector
Reads real system CPU, RAM, and GPU availability without external dependencies.
"""
import platform
import psutil
from typing import Dict, Any

def detect_hardware() -> Dict[str, Any]:
    """Detect actual hardware specifications of the host machine."""
    # CPU
    physical_cores = psutil.cpu_count(logical=False) or 2
    logical_cores = psutil.cpu_count(logical=True) or 4
    cpu_freq = psutil.cpu_freq()
    freq_mhz = round(cpu_freq.current, 1) if (cpu_freq and cpu_freq.current is not None) else 2400.0

    # RAM
    vmem = psutil.virtual_memory()
    total_ram_mb = round(vmem.total / (1024 * 1024), 1)
    available_ram_mb = round(vmem.available / (1024 * 1024), 1)
    ram_usage_pct = vmem.percent

    # GPU Check
    gpu_info = {
        "present": False,
        "name": "None (Vega runs CPU-only local sovereignty)",
        "vram_mb": 0,
        "required": False,
        "status": "NOT REQUIRED"
    }

    try:
        import torch
        if torch.cuda.is_available():
            gpu_info["present"] = True
            gpu_info["name"] = torch.cuda.get_device_name(0)
            gpu_info["vram_mb"] = round(torch.cuda.get_device_properties(0).total_memory / (1024 * 1024), 1)
            gpu_info["status"] = "DETECTED_OPTIONAL"
    except Exception:
        pass

    return {
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "processor": platform.processor() or "x86_64 Compatible",
        "cpu_physical_cores": physical_cores,
        "cpu_logical_cores": logical_cores,
        "cpu_frequency_mhz": freq_mhz,
        "cpu_usage_percent": psutil.cpu_percent(interval=None),
        "total_ram_mb": total_ram_mb,
        "available_ram_mb": available_ram_mb,
        "ram_usage_percent": ram_usage_pct,
        "gpu": gpu_info,
        "is_cpu_only_capable": True,
        "air_gap_compliant": False
    }
