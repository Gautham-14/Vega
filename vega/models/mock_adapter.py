"""
Vega Sovereign AI Runtime - Mock Model Adapter
Deterministic, lightweight, CPU-only simulated model inference.
Clearly labeled with SIMULATION MODE.
"""
import time
import math
import hashlib
from typing import Dict, Any, List
from vega.models.base import ModelAdapter, ModelRequest, ModelResponse

class MockModelAdapter(ModelAdapter):
    """
    Deterministic Mock Model Adapter for Vega Prototype.
    Simulates sovereign on-premise execution without downloading weights or using GPU.
    """
    def __init__(self, model_id: str = "VEGA-DEMO-TEXT"):
        self.model_id = model_id

    def generate(self, request: ModelRequest) -> ModelResponse:
        start_time = time.time()

        # Check prompt intent and generate deterministic industrial AI response
        prompt_lower = request.prompt.lower()

        if "p-204" in prompt_lower or "pump" in prompt_lower or "vibration" in prompt_lower:
            response_text = (
                "[SIMULATION MODE - VEGA SOVEREIGN RUNTIME]\n\n"
                "### Engineering Assessment: Centrifugal Pump P-204 Vibration Excursion\n\n"
                "**1. Operational Observations:**\n"
                "- Equipment Under Review: Slurry Feed Pump P-204 (Tag # P-204-A, Unit 02).\n"
                "- Drive End (DE) Horizontal Bearing Vibration: Measured at 7.20 mm/s RMS.\n"
                "- Non-Drive End (NDE) Bearing Vibration: Measured at 2.80 mm/s RMS (Nominal).\n"
                "- Bearing Housing Temperature: 74.5°C (Within acceptable thermal ceiling < 85°C).\n\n"
                "**2. Authoritative SOP Baseline Compliance:**\n"
                "- Applicable SOP: Pump_SOP_Rev8 (Effective 2024-01, Authoritative & Approved).\n"
                "- Permitted Limit for ISO 10816-3 Class II (Rigid Foundation, >15kW): 4.50 mm/s RMS.\n"
                "- Excursion Delta: Measured 7.20 mm/s exceeds permitted ceiling of 4.50 mm/s.\n\n"
                "**3. Deterministic Quantitative Verification:**\n"
                "- Vibration Excursion Ratio: 7.20 / 4.50 = 1.60x (160.0% of allowable ceiling).\n"
                "- Exceedance Margin: +2.70 mm/s RMS.\n\n"
                "**4. Diagnostic Deduction:**\n"
                "- High 1X and 2X radial vibration peaks indicate impending bearing race degradation, dynamic unbalance, or mechanical looseness.\n\n"
                "**5. Corrective Recommendations:**\n"
                "- Restrict continuous operating load on Unit 02.\n"
                "- Schedule non-destructive vibration spectral analysis within 48 hours.\n"
                "- Prepare redundant spare pump P-204-B for primary process takeover."
            )
            reasoning = [
                "Evaluated input report against authorized SOP (Pump_SOP_Rev8).",
                "Rejected historical superseded SOPs (Rev2: 6.0 mm/s, Rev5: 5.2 mm/s).",
                "Calculated vibration excursion ratio deterministically: 7.2 / 4.5 = 1.60x.",
                "Separated verified empirical observations from diagnostic inferences.",
                "Discarded ungrounded hallucination claims during evidence synthesis."
            ]
        elif "code" in prompt_lower or "python" in prompt_lower or "calculate" in prompt_lower:
            response_text = (
                "[SIMULATION MODE - VEGA SOVEREIGN RUNTIME]\n\n"
                "```python\n"
                "# Deterministic ISO 10816-3 Vibration Severity Calculator\n"
                "def calculate_vibration_severity(measured_rms: float, permitted_limit: float = 4.5) -> dict:\n"
                "    ratio = round(measured_rms / permitted_limit, 4)\n"
                "    delta = round(measured_rms - permitted_limit, 4)\n"
                "    status = 'EXCEEDED' if delta > 0 else 'ACCEPTABLE'\n"
                "    return {\n"
                "        'measured_rms': measured_rms,\n"
                "        'permitted_limit': permitted_limit,\n"
                "        'exceedance_delta': delta,\n"
                "        'severity_ratio': ratio,\n"
                "        'status': status\n"
                "    }\n"
                "\n"
                "result = calculate_vibration_severity(7.2, 4.5)\n"
                "# Output: {'measured_rms': 7.2, 'permitted_limit': 4.5, 'exceedance_delta': 2.7, 'severity_ratio': 1.6, 'status': 'EXCEEDED'}\n"
                "```"
            )
            reasoning = [
                "Generated deterministic Python verification function.",
                "Executed calculation within isolated simulated sandbox.",
                "Output matches empirical math verification test."
            ]
        elif "p&id" in prompt_lower or "vision" in prompt_lower or "scanned" in prompt_lower:
            response_text = (
                "[SIMULATION MODE - VEGA SOVEREIGN RUNTIME]\n\n"
                "### Multimodal Engineering Drawing (P&ID) Analysis\n\n"
                "- Document: P&ID Drawing P204-ISO-004-RevC\n"
                "- Detected Components: Centrifugal Pump P-204, Suction Valve V-102, Discharge Check Valve CV-108.\n"
                "- Sensor Instrumentation: PT-204 (Suction Pressure), TT-204 (Discharge Temp), VT-204 (Vibration Transmitter).\n"
                "- Interlock Tag: I-204-SHUTDOWN connected to distributed control system (DCS).\n"
                "- Status: Fully mapped against industrial plant schematics without cloud vision API."
            )
            reasoning = [
                "Simulated vision-language engineering layout detection.",
                "Mapped sensor tags to industrial topology graph.",
                "No external OCR or cloud vision API invoked."
            ]
        else:
            response_text = (
                f"[SIMULATION MODE - VEGA SOVEREIGN RUNTIME]\n\n"
                f"Sovereign AI execution for: {request.prompt[:100]}...\n\n"
                "Vega processed this request locally inside an isolated task enclave. "
                "All assertions are cross-referenced with authorized local knowledge and zero external egress."
            )
            reasoning = [
                "Local sovereign simulation executed.",
                "Zero external network calls made."
            ]

        latency_ms = round((time.time() - start_time) * 1000 + 45.0, 2)  # realistic local CPU latency sim
        tokens = len(response_text.split())

        return ModelResponse(
            content=response_text,
            model_id=self.model_id,
            tokens_generated=tokens,
            latency_ms=latency_ms,
            is_simulation=True,
            reasoning_steps=reasoning,
            metadata={"zero_egress": True, "backend": "MockModelAdapter"}
        )

    def embed(self, text: str) -> List[float]:
        """
        Deterministic pseudo-embedding for local prototype testing.
        Generates 128 normalized float dimensions based on SHA-256 seed.
        """
        seed_hash = hashlib.sha256(text.encode("utf-8")).digest()
        raw_values = [((b / 255.0) * 2.0 - 1.0) for b in seed_hash[:32]]
        # Repeat to 128 dims
        repeated = (raw_values * 4)[:128]
        norm = math.sqrt(sum(x * x for x in repeated)) or 1.0
        return [round(x / norm, 5) for x in repeated]

    def capabilities(self) -> List[str]:
        if "VISION" in self.model_id:
            return ["image analysis", "scanned document workflow", "P&ID workflow"]
        elif "CODE" in self.model_id:
            return ["coding", "debugging", "Python"]
        return ["text", "reasoning", "document analysis"]

    def health(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "status": "HEALTHY",
            "runtime_mode": "SIMULATION",
            "is_local": True,
            "memory_resident": True
        }
