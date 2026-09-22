"""
Aegis Sovereign AI Runtime - Demo Model Profiles & Manifest Definitions
"""
import hashlib
from typing import Dict, Any, List

def compute_simulated_sha256(seed_str: str) -> str:
    """Generate deterministic SHA-256 hash for simulated packages."""
    return hashlib.sha256(seed_str.encode("utf-8")).hexdigest()

DEMO_MODEL_PROFILES: List[Dict[str, Any]] = [
    {
        "id": "AEGIS-DEMO-TEXT",
        "name": "Aegis Industrial Text & Reasoning Engine",
        "version": "v1.4.0",
        "architecture": "Llama-3-Industrial-Sim",
        "parameters": "8B",
        "quantization": "Q4_K_M",
        "capabilities": ["text", "reasoning", "document analysis"],
        "license": "Apache-2.0",
        "sha256": compute_simulated_sha256("AEGIS-DEMO-TEXT-MANIFEST-v1.4.0"),
        "status": "QUALIFIED",
        "memory_req_mb": 4096,
        "cpu_cores_req": 2,
        "gpu_vram_req_mb": 0,
        "qualification_score": 98.6,
        "shadow_agreement_score": 99.1,
        "benchmark_summary": {
            "prompt_injection_robustness": "99.8%",
            "sop_factual_recall": "99.4%",
            "hallucination_rate": "0.4%",
            "inference_latency_sim_ms": 142
        }
    },
    {
        "id": "AEGIS-DEMO-VISION",
        "name": "Aegis Vision & Engineering P&ID Engine",
        "version": "v2.1.0",
        "architecture": "Qwen2-VL-Engineering-Sim",
        "parameters": "7B",
        "quantization": "Q4_K_S",
        "capabilities": ["image analysis", "scanned document workflow", "P&ID workflow"],
        "license": "Apache-2.0",
        "sha256": compute_simulated_sha256("AEGIS-DEMO-VISION-MANIFEST-v2.1.0"),
        "status": "QUALIFIED",
        "memory_req_mb": 8192,
        "cpu_cores_req": 4,
        "gpu_vram_req_mb": 0,
        "qualification_score": 96.2,
        "shadow_agreement_score": 97.8,
        "benchmark_summary": {
            "pid_symbol_accuracy": "97.1%",
            "scanned_doc_ocr_fidelity": "98.9%",
            "injection_in_image_scan": "100%",
            "inference_latency_sim_ms": 280
        }
    },
    {
        "id": "AEGIS-DEMO-CODE",
        "name": "Aegis Python & Logic Execution Engine",
        "version": "v1.2.0",
        "architecture": "Qwen-Coder-Sim",
        "parameters": "7B",
        "quantization": "Q4_K_M",
        "capabilities": ["coding", "debugging", "Python"],
        "license": "Apache-2.0",
        "sha256": compute_simulated_sha256("AEGIS-DEMO-CODE-MANIFEST-v1.2.0"),
        "status": "QUALIFIED",
        "memory_req_mb": 6144,
        "cpu_cores_req": 2,
        "gpu_vram_req_mb": 0,
        "qualification_score": 97.4,
        "shadow_agreement_score": 98.5,
        "benchmark_summary": {
            "math_calculation_accuracy": "100%",
            "safe_code_sandbox_execution": "100%",
            "syntax_validation_rate": "99.2%",
            "inference_latency_sim_ms": 110
        }
    },
    {
        "id": "UNVERIFIED-EXPERIMENTAL-70B",
        "name": "Untested Massive Frontier Candidate",
        "version": "v0.9.0-rc",
        "architecture": "Llama-3-70B-Sim",
        "parameters": "70B",
        "quantization": "Q4_K_M",
        "capabilities": ["text", "reasoning", "complex planning"],
        "license": "Community-Trial",
        "sha256": compute_simulated_sha256("UNVERIFIED-EXPERIMENTAL-70B-UNVETTED"),
        "status": "QUARANTINED",
        "memory_req_mb": 40960,
        "cpu_cores_req": 16,
        "gpu_vram_req_mb": 24576,
        "qualification_score": None,
        "shadow_agreement_score": None,
        "benchmark_summary": {
            "status": "Pending air-gapped security qualification and shadow verification."
        }
    }
]
