"""
Aegis Models Package
"""

from aegis.models.base import (
    LlamaCppAdapter,
    ModelAdapter,
    ModelRequest,
    ModelResponse,
    OllamaAdapter,
    VLLMAdapter,
)
from aegis.models.mock_adapter import MockModelAdapter
from aegis.models.registry import (
    get_all_models,
    get_model_by_id,
    import_model_manifest,
    run_shadow_mode_simulation,
    run_simulated_qualification,
    seed_model_registry,
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
    "run_shadow_mode_simulation",
]
