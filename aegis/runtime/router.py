"""
Aegis Sovereign AI Runtime - Model Router
Routes tasks to qualified, eligible models based on modality, risk, and hardware headroom.
"""
from typing import Dict, Any, Optional
from aegis.models.registry import get_all_models, get_model_by_id, model_integrity_verified, APPROVED_SOVEREIGN_LICENSES
from aegis.hardware.scheduler import evaluate_model_eligibility
from aegis.models.mock_adapter import MockModelAdapter

class ModelRouter:
    """
    Selects the most suitable qualified local model for a task.
    """
    def __init__(self):
        pass

    def route_task(
        self,
        task_type: str = "text",
        required_capability: Optional[str] = None,
        risk_level: str = "HIGH"
    ) -> Dict[str, Any]:
        """
        Evaluate candidate models and select the optimal qualified eligible model.
        """
        eligibility_list = {e["model_id"]: e for e in evaluate_model_eligibility()}
        models = get_all_models()

        # Preferred model mapping based on task type
        preferred_id = "AEGIS-DEMO-TEXT"
        if task_type in ["vision", "pid", "scanned_doc"]:
            preferred_id = "AEGIS-DEMO-VISION"
        elif task_type in ["code", "math", "calculator"]:
            preferred_id = "AEGIS-DEMO-CODE"

        capability = required_capability or {
            "AEGIS-DEMO-TEXT": "text", "AEGIS-DEMO-CODE": "coding",
            "AEGIS-DEMO-VISION": "image analysis"
        }[preferred_id]
        candidates = sorted(models, key=lambda model: (model["id"] != preferred_id, model["memory_req_mb"], model["id"]))
        selected_model = None
        routing_notes = []

        # Find preferred model and check constraints
        for candidate in candidates:
            model_id = candidate["id"]
            elig = eligibility_list.get(model_id, {})
            if candidate["status"] != "DEMO_QUALIFIED":
                routing_notes.append(f"Rejected {model_id}: not demo-qualified.")
            elif capability not in candidate["capabilities"]:
                routing_notes.append(f"Rejected {model_id}: missing capability {capability}.")
            elif not model_integrity_verified(candidate) or candidate["license"] not in APPROVED_SOVEREIGN_LICENSES:
                routing_notes.append(f"Rejected {model_id}: manifest checksum or license metadata check failed.")
            elif elig.get("eligibility") not in {"ELIGIBLE", "DEGRADED"}:
                routing_notes.append(f"Rejected {model_id}: hardware requirements not met.")
            else:
                selected_model = candidate
                routing_notes.append(f"Selected {model_id} (Hardware: {elig['eligibility']}).")
                break

        # Fallback to AEGIS-DEMO-TEXT if needed
        if not selected_model:
            raise RuntimeError(f"No demo-qualified, eligible fixture with capability '{capability}' available.")

        adapter = MockModelAdapter(model_id=selected_model["id"])

        return {
            "selected_model": selected_model,
            "adapter": adapter,
            "routing_notes": routing_notes
        }

    def route_multi_model_pipeline(
        self,
        task_type: str = "engineering_review",
        risk_level: str = "HIGH",
        modalities: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Coordinates multi-model routing across specialized qualified models
        for complex high-assurance industrial tasks.
        Demonstrates multi-model synergy across text, code/math, and vision.
        """
        modalities = modalities or ["text", "code", "vision"]
        pipeline = {}
        routing_manifest = []

        if "text" in modalities:
            text_route = self.route_task(task_type="text", risk_level=risk_level)
            pipeline["primary_reasoning"] = text_route
            routing_manifest.append({
                "role": "Primary Reasoning & SOP Compliance",
                "model_id": text_route["selected_model"]["id"],
                "adapter": text_route["adapter"]
            })

        if "code" in modalities:
            code_route = self.route_task(task_type="code", risk_level=risk_level)
            pipeline["calculation_engine"] = code_route
            routing_manifest.append({
                "role": "Deterministic Calculation & Formula Validation",
                "model_id": code_route["selected_model"]["id"],
                "adapter": code_route["adapter"]
            })

        if "vision" in modalities:
            vision_route = self.route_task(task_type="vision", risk_level=risk_level)
            pipeline["visual_inspector"] = vision_route
            routing_manifest.append({
                "role": "Scanned Inspection Document & P&ID Analysis",
                "model_id": vision_route["selected_model"]["id"],
                "adapter": vision_route["adapter"]
            })

        return {
            "pipeline": pipeline,
            "routing_manifest": routing_manifest,
            "models_engaged": [r["model_id"] for r in routing_manifest]
        }
