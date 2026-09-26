"""
Aegis Sovereign AI Runtime - Model Adapter Base Interfaces
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from enum import Enum

class ModelModality(str, Enum):
    TEXT = "text"
    VISION = "vision"
    CODE = "code"
    EMBEDDING = "embedding"

@dataclass
class ModelRequest:
    prompt: str
    system_instruction: Optional[str] = None
    context_documents: List[Dict[str, Any]] = field(default_factory=list)
    temperature: float = 0.2
    max_tokens: int = 2048
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ModelResponse:
    content: str
    model_id: str
    tokens_generated: int
    latency_ms: float
    is_simulation: bool = True
    reasoning_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class ModelAdapter(ABC):
    """
    Abstract Model Adapter Interface.
    Every inference backend in Aegis (mock or future local LLM runtime) implements this interface.
    """
    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        """Generate response from model for given request."""
        pass

    @abstractmethod
    def embed(self, text: str) -> List[float]:
        """Generate vector embedding for given text."""
        pass

    @abstractmethod
    def capabilities(self) -> List[str]:
        """Return list of capabilities supported by this model."""
        pass

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        """Check adapter status and health."""
        pass


# =====================================================================
# Future-Compatible Backend Stubs (Modular Extension Architecture)
# These represent future real on-premise inference engines.
# In this prototype, they serve as architecture contracts.
# =====================================================================

class OllamaAdapter(ModelAdapter):
    """
    Future adapter for local Ollama HTTP engine.
    Connects to http://localhost:11434 without altering the Aegis pipeline.
    """
    def __init__(self, base_url: str = "http://localhost:11434", model_name: str = "llama3:8b"):
        self.base_url = base_url
        self.model_name = model_name

    def generate(self, request: ModelRequest) -> ModelResponse:
        raise NotImplementedError("Real Ollama inference is marked Not Included in Aegis Prototype Scope.")

    def embed(self, text: str) -> List[float]:
        raise NotImplementedError("Real embedding generation is marked Not Included in Aegis Prototype Scope.")

    def capabilities(self) -> List[str]:
        return ["text", "reasoning"]

    def health(self) -> Dict[str, Any]:
        return {"backend": "Ollama", "status": "NOT_IMPLEMENTED_USE_PROVIDER_PROFILES", "is_mock": True}


class LlamaCppAdapter(ModelAdapter):
    """
    Future adapter for direct GGUF / llama.cpp in-process C++ inference.
    """
    def __init__(self, model_path: str):
        self.model_path = model_path

    def generate(self, request: ModelRequest) -> ModelResponse:
        raise NotImplementedError("Real llama.cpp GGUF inference is marked Not Included in Aegis Prototype Scope.")

    def embed(self, text: str) -> List[float]:
        raise NotImplementedError("Real embedding generation is marked Not Included in Aegis Prototype Scope.")

    def capabilities(self) -> List[str]:
        return ["text", "quantized_gguf"]

    def health(self) -> Dict[str, Any]:
        return {"backend": "LlamaCpp", "status": "NOT_IMPLEMENTED_USE_PROVIDER_PROFILES", "is_mock": True}


class VLLMAdapter(ModelAdapter):
    """
    Future adapter for high-throughput vLLM engine.
    """
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url

    def generate(self, request: ModelRequest) -> ModelResponse:
        raise NotImplementedError("Real vLLM distributed inference is marked Not Included in Aegis Prototype Scope.")

    def embed(self, text: str) -> List[float]:
        raise NotImplementedError("Real embedding generation is marked Not Included in Aegis Prototype Scope.")

    def capabilities(self) -> List[str]:
        return ["text", "batched_throughput", "paged_attention"]

    def health(self) -> Dict[str, Any]:
        return {"backend": "vLLM", "status": "NOT_IMPLEMENTED_USE_PROVIDER_PROFILES", "is_mock": True}
