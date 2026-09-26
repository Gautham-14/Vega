"""
Aegis Sovereign AI Runtime - Hardware Detector
Reads real system CPU, RAM, and GPU availability without external dependencies.
"""
import platform
import psutil
import csv
import io
import os
import shutil
import subprocess
from typing import Dict, Any

def detect_hardware() -> Dict[str, Any]:
    """Detect actual hardware specifications of the host machine."""
    # CPU
    physical_cores = psutil.cpu_count(logical=False) or 2
    logical_cores = psutil.cpu_count(logical=True) or 4
    try:
        cpu_freq = psutil.cpu_freq()
    except (NotImplementedError, OSError, AttributeError):
        cpu_freq = None
    freq_mhz = round(cpu_freq.current, 1) if (cpu_freq and cpu_freq.current is not None) else None

    # RAM
    vmem = psutil.virtual_memory()
    total_ram_mb = round(vmem.total / (1024 * 1024), 1)
    available_ram_mb = round(vmem.available / (1024 * 1024), 1)
    ram_usage_pct = vmem.percent

    # GPU Check
    gpu_info = {
        "present": False,
        "name": "GPU availability has not been measured",
        "vram_mb": 0,
        "required": False,
        "status": "UNAVAILABLE",
        "devices": [],
        "inference_compatibility": "NOT_VERIFIED"
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

    # Detect installed NVIDIA hardware even when the optional torch package is absent.
    executable = shutil.which("nvidia-smi")
    if executable:
        try:
            result = subprocess.run([executable, "--query-gpu=name,memory.total,memory.free", "--format=csv,noheader,nounits"],
                                    capture_output=True, text=True, timeout=3, check=True,
                                    creationflags=0x08000000 if os.name == "nt" else 0)
            devices = []
            if len(result.stdout) > 16000:
                raise ValueError("GPU inventory exceeds limit")
            for row in csv.reader(io.StringIO(result.stdout)):
                if len(row) != 3 or len(devices) >= 32:
                    raise ValueError("Invalid GPU inventory")
                total, free = int(row[1].strip()), int(row[2].strip())
                if not 0 <= free <= total:
                    raise ValueError("Invalid GPU memory")
                devices.append({"name": row[0].strip()[:160], "vram_mb": total, "free_vram_mb": free})
            if devices:
                gpu_info.update(present=True, name=devices[0]["name"], vram_mb=devices[0]["vram_mb"],
                                devices=devices, status="MEASURED_NVIDIA_SMI")
        except (OSError, ValueError, subprocess.SubprocessError):
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
