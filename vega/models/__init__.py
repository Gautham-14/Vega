"""
Vega Models Package
"""
from vega.models.base import ModelAdapter, ModelRequest, ModelResponse, OllamaAdapter, LlamaCppAdapter, VLLMAdapter
from vega.models.mock_adapter import MockModelAdapter
from vega.models.registry import (
    seed_model_registry,
    get_all_models,
    get_model_by_id,
    import_model_manifest,
    run_simulated_qualification,
    run_shadow_mode_simulation
)

__all__ = [
    "ModelAdapter",
    "ModelRequest",
    "ModelResponse",
    "OllamaAdapter",
    "LlamaCppAdapter",
    "VLLMAdapter",
    "MockModelAdapter",
    "seed_model_registry",
    "get_all_models",
    "get_model_by_id",
    "import_model_manifest",
    "run_simulated_qualification",
    "run_shadow_mode_simulation"
]
