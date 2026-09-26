"""Transparent weight-memory arithmetic, never an inference benchmark or fit promise."""
import math
import psutil


def estimate(parameters_billions, bits=4):
    if (type(parameters_billions) not in (int, float) or not math.isfinite(parameters_billions)
            or not 0 < parameters_billions <= 100_000 or type(bits) is not int or bits not in {2, 3, 4, 8, 16, 32}):
        raise ValueError("Use positive TOTAL parameters in billions and 2/3/4/8/16/32 bits per weight")
    weights = parameters_billions * 1_000_000_000 * bits / 8
    memory = psutil.virtual_memory()
    return {"total_parameters_billions": parameters_billions, "bits_per_weight": bits,
            "raw_weights_gb": round(weights / 1e9, 3), "raw_weights_gib": round(weights / 2**30, 3),
            "host_ram_gib": round(memory.total / 2**30, 3), "host_available_ram_gib": round(memory.available / 2**30, 3),
            "host_ram_assessment": "RAW_WEIGHTS_EXCEED_AVAILABLE_RAM" if weights >= memory.available else "RAW_WEIGHTS_ONLY_FIT_RUNTIME_UNVERIFIED",
            "excluded_memory": ["quantization metadata", "KV cache", "activations", "vision encoder/projector", "runtime workspace", "OS reserve"],
            "moe": "Use total parameters for weight storage; active parameters describe per-token compute, not total storage.",
            "scope": "Arithmetic lower bound. GPU compatibility, bandwidth, offloading and distributed inference are not validated."}
