"""
Tests for Aegis Model Registry, Mock Adapters, and Lifecycle
"""
import pytest
from aegis.storage.database import init_db
from aegis.models.registry import (
    seed_model_registry,
    get_all_models,
    get_model_by_id,
    import_model_manifest,
    run_simulated_qualification,
    run_shadow_mode_simulation
)
from aegis.models.mock_adapter import MockModelAdapter
from aegis.models.base import ModelRequest
from aegis.models.registry import compute_manifest_sha256

@pytest.fixture(autouse=True)
def setup_database():
    init_db()
    seed_model_registry()

def test_model_seeding():
    models = get_all_models()
    assert len(models) >= 3
    model_ids = [m["id"] for m in models]
    assert "AEGIS-DEMO-TEXT" in model_ids
    assert "AEGIS-DEMO-VISION" in model_ids
    assert "AEGIS-DEMO-CODE" in model_ids

def test_mock_adapter_inference():
    adapter = MockModelAdapter(model_id="AEGIS-DEMO-TEXT")
    req = ModelRequest(prompt="Analyze Pump P-204 vibration reading of 7.2 mm/s against SOP.")
    resp = adapter.generate(req)

    assert "[SIMULATION MODE" in resp.content
    assert "7.20 mm/s" in resp.content
    assert "Pump_SOP_Rev8" in resp.content
    assert resp.is_simulation is True
    assert resp.model_id == "AEGIS-DEMO-TEXT"
    assert len(resp.reasoning_steps) > 0

def test_model_import_and_quarantine():
    manifest = {
        "id": "TEST-IMPORTED-MODEL",
        "name": "Test Candidate Engine",
        "version": "v1.0",
        "architecture": "Llama-3-Sim",
        "parameters": "8B",
        "quantization": "Q4",
        "capabilities": ["text", "reasoning"],
        "license": "MIT",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }
    result = import_model_manifest(manifest)
    assert result["model_id"] == "TEST-IMPORTED-MODEL"
    assert result["status"] == "QUARANTINED"

    imported = get_model_by_id("TEST-IMPORTED-MODEL")
    assert imported is not None
    assert imported["status"] == "QUARANTINED"

def test_model_qualification():
    manifest = {
        "id": "QUALIFY-TEST-MODEL",
        "name": "Qualify Candidate Engine",
        "version": "v1.0",
        "architecture": "Llama-3-Sim",
        "parameters": "8B",
        "quantization": "Q4",
        "capabilities": ["text"],
        "license": "Apache-2.0",
        "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    }
    manifest["sha256"] = compute_manifest_sha256(manifest)
    import_model_manifest(manifest)

    # Run qualification
    qual_res = run_simulated_qualification("QUALIFY-TEST-MODEL")
    assert qual_res["new_status"] == "DEMO_QUALIFIED"
    assert qual_res["production_eligible"] is False
    assert qual_res["qualification_score"] >= 90.0

    model = get_model_by_id("QUALIFY-TEST-MODEL")
    assert model["status"] == "DEMO_QUALIFIED"
    assert model["artifact_integrity_verified"] is False

def test_tampered_model_cannot_be_qualified():
    tampered_manifest = {
        "id": "TAMPERED-CANDIDATE-8B",
        "name": "Corrupted Weight Manifest",
        "version": "v1.0",
        "architecture": "Llama-3-Sim",
        "parameters": "8B",
        "quantization": "Q4",
        "capabilities": ["text"],
        "license": "Apache-2.0",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    import_res = import_model_manifest(tampered_manifest)
    assert import_res["status"] == "QUARANTINED"
    assert import_res["integrity_verified"] is False

    # Attempting to qualify a corrupt package must be blocked
    with pytest.raises(ValueError, match="Manifest SHA-256 checksum mismatch"):
        run_simulated_qualification("TAMPERED-CANDIDATE-8B")

def test_shadow_mode_simulation():
    shadow_res = run_shadow_mode_simulation("AEGIS-DEMO-VISION", baseline_model_id="AEGIS-DEMO-TEXT")
    assert shadow_res["shadow_agreement_score"] > 90.0
    assert len(shadow_res["divergence_details"]) > 0
