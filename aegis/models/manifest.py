"""Canonical model metadata checksum shared by the CLI and backend."""
import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field


class ModelManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    parameters: str = Field(min_length=1)
    quantization: str = Field(min_length=1)
    capabilities: list[str] = Field(min_length=1)
    license: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    memory_req_mb: int = Field(default=8192, gt=0)
    cpu_cores_req: int = Field(default=4, gt=0)
    gpu_vram_req_mb: int = Field(default=0, ge=0)


def compute_manifest_sha256(manifest: dict) -> str:
    fields = ModelManifest.model_fields
    core = {key: manifest.get(key, fields[key].default)
            for key in sorted(fields) if key != "sha256"}
    return hashlib.sha256(json.dumps(core, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
