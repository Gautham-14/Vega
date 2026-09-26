"""
Aegis Sovereign AI Runtime - Offline Model Registry
Manages model manifests, integrity verification, quarantine lifecycle,
simulated qualifications, and shadow-mode benchmarking.
"""
import json
import time
from typing import Dict, Any, List, Optional
from aegis.storage.database import query_all, query_one, execute_write
from aegis.models.profiles import DEMO_MODEL_PROFILES
from aegis.models.manifest import ModelManifest, compute_manifest_sha256

def seed_model_registry() -> None:
    """Add missing demo profiles without replacing existing model records."""
    for profile in DEMO_MODEL_PROFILES:
        execute_write("""
            INSERT OR IGNORE INTO models (
                id, name, version, architecture, parameters, quantization,
                capabilities, license, sha256, status, memory_req_mb,
                cpu_cores_req, gpu_vram_req_mb, qualification_score,
                shadow_agreement_score, benchmark_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile["id"],
            profile["name"],
            profile["version"],
            profile["architecture"],
            profile["parameters"],
            profile["quantization"],
            json.dumps(profile["capabilities"]),
            profile["license"],
            compute_manifest_sha256(profile),
            profile["status"],
            profile["memory_req_mb"],
            profile["cpu_cores_req"],
            profile["gpu_vram_req_mb"],
            profile.get("qualification_score"),
            profile.get("shadow_agreement_score"),
            json.dumps({**profile.get("benchmark_summary", {}),
                        "integrity_check": "SYNTHETIC_PROFILE_ONLY",
                        "qualification_mode": "DETERMINISTIC_FIXTURE",
                        "score_is_measured": False,
                        "artifact_integrity_verified": False,
                        "license_compliant": profile["license"] in APPROVED_SOVEREIGN_LICENSES})
        ))

def _describe_assurance(record: Dict[str, Any]) -> Dict[str, Any]:
    # This registry holds metadata and deterministic fixtures, never model bytes.
    # Normalize records written by older versions that called a demo "QUALIFIED".
    if record["status"] == "QUALIFIED":
        record["status"] = "DEMO_QUALIFIED"
    record["verification_scope"] = "MANIFEST_METADATA_ONLY"
    record["manifest_checksum_matches"] = model_manifest_checksum_matches(record)
    record["artifact_integrity_verified"] = False
    record["publisher_signature_verified"] = False
    record["runtime_binding_verified"] = False
    record["production_eligible"] = False
    return record


def get_all_models() -> List[Dict[str, Any]]:
    """Retrieve all models from the offline registry."""
    rows = query_all("SELECT * FROM models ORDER BY id")
    for r in rows:
        r["capabilities"] = json.loads(r["capabilities"]) if isinstance(r["capabilities"], str) else r["capabilities"]
        r["benchmark_summary"] = json.loads(r["benchmark_summary"]) if isinstance(r["benchmark_summary"], str) else r["benchmark_summary"]
    return [_describe_assurance(row) for row in rows]

def get_model_by_id(model_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve specific model profile."""
    r = query_one("SELECT * FROM models WHERE id = ?", (model_id,))
    if r:
        r["capabilities"] = json.loads(r["capabilities"]) if isinstance(r["capabilities"], str) else r["capabilities"]
        r["benchmark_summary"] = json.loads(r["benchmark_summary"]) if isinstance(r["benchmark_summary"], str) else r["benchmark_summary"]
    return _describe_assurance(r) if r else None

APPROVED_SOVEREIGN_LICENSES = [
    "Apache-2.0",
    "MIT",
    "BSD-3-Clause",
    "BSD-2-Clause",
    "CC-BY-4.0",
    "OpenRAIL-M",
    "Llama-3-Community",
    "Llama-3.1-Community"
]

RESTRICTED_LICENSES = [
    "Proprietary-Cloud-API",
    "Commercial-Egress-Required",
    "GPL-3.0-Network-Restricted"
]

def model_manifest_checksum_matches(model: Dict[str, Any]) -> bool:
    if compute_manifest_sha256(model) == model["sha256"]:
        return True
    # Read compatibility for the original bundled synthetic profiles only.
    return any(model["sha256"] == profile["sha256"] and all(
        model.get(key) == profile.get(key) for key in ModelManifest.model_fields
    ) for profile in DEMO_MODEL_PROFILES)


def model_integrity_verified(model: Dict[str, Any]) -> bool:
    """Compatibility name: checks manifest metadata only, never model bytes."""
    return model_manifest_checksum_matches(model)

def import_model_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """
    Store demo model metadata, check its self-declared checksum, and quarantine it.
    No model artifact is imported or verified here.
    """
    manifest = ModelManifest.model_validate(manifest).model_dump()
    if any(not cap.strip() for cap in manifest["capabilities"]):
        raise ValueError("Capabilities cannot be empty strings")
    # License metadata check
    declared_license = manifest["license"]
    if declared_license in APPROVED_SOVEREIGN_LICENSES:
        license_verdict = "APPROVED_DEMO_METADATA (Allowlisted identifier only)"
        license_compliant = True
    elif declared_license in RESTRICTED_LICENSES:
        license_verdict = "RESTRICTED (Network/Egress Constraint Detected)"
        license_compliant = False
    else:
        license_verdict = "COMMUNITY_UNVETTED (Requires Legal Sign-off)"
        license_compliant = False

    # Check only canonical manifest metadata; no model bytes are available.
    computed_hash = compute_manifest_sha256(manifest)

    # Integrity verification check
    integrity_pass = manifest["sha256"].lower() == computed_hash

    initial_status = "QUARANTINED"
    quarantine_reasons = ["Mandatory staging quarantine for unvetted sovereign packages."]
    if not integrity_pass:
        quarantine_reasons.append("Manifest SHA-256 checksum mismatch; model artifact was not checked.")
    if not license_compliant:
        quarantine_reasons.append(f"License constraint: {license_verdict}")

    execute_write("""
        INSERT INTO models (
            id, name, version, architecture, parameters, quantization,
            capabilities, license, sha256, status, memory_req_mb,
            cpu_cores_req, gpu_vram_req_mb, qualification_score,
            shadow_agreement_score, benchmark_summary, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, CURRENT_TIMESTAMP)
    """, (
        manifest["id"],
        manifest["name"],
        manifest["version"],
        manifest["architecture"],
        manifest["parameters"],
        manifest["quantization"],
        json.dumps(manifest["capabilities"]),
        manifest["license"],
        manifest["sha256"].lower(),
        initial_status,
        manifest.get("memory_req_mb", 8192),
        manifest.get("cpu_cores_req", 4),
        manifest.get("gpu_vram_req_mb", 0),
        json.dumps({
            "manifest_validation": "PASS",
            "integrity_check": "MANIFEST_CHECKSUM_PASS" if integrity_pass else "FAIL_MANIFEST_CHECKSUM",
            "license_check": license_verdict,
            "license_compliant": license_compliant,
            "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "quarantine_reasons": quarantine_reasons
        })
    ))

    return {
        "model_id": manifest["id"],
        "status": initial_status,
        "manifest_valid": True,
        "integrity_verified": False,
        "manifest_checksum_matches": integrity_pass,
        "artifact_integrity_verified": False,
        "publisher_signature_verified": False,
        "production_eligible": False,
        "license_check": license_verdict,
        "sha256": manifest["sha256"],
        "quarantine_reasons": quarantine_reasons
    }


def run_simulated_qualification(model_id: str) -> Dict[str, Any]:
    """
    Run simulated offline qualification suite on a quarantined model.
    Tests: prompt injection immunity, industrial vocabulary recall, hallucination rate.
    Transitions model from QUARANTINED -> DEMO_QUALIFIED using fixture scores.
    This does not inspect model bytes or grant production eligibility.
    """
    model = get_model_by_id(model_id)
    if not model:
        raise ValueError(f"Model not found: {model_id}")

    # Check if model integrity check failed
    summary = model.get("benchmark_summary") or {}
    if isinstance(summary, str):
        summary = json.loads(summary)
    if not model_manifest_checksum_matches(model):
        raise ValueError(f"Cannot demo-qualify model '{model_id}': Manifest SHA-256 checksum mismatch.")
    if model["license"] not in APPROVED_SOVEREIGN_LICENSES:
        raise ValueError(f"Cannot demo-qualify model '{model_id}': License metadata restriction ({model['license']}).")

    # Simulated qualification benchmark
    sim_score = 97.2
    benchmark_results = {
        **summary,
        "prompt_injection_resistance": "99.1%",
        "industrial_sop_comprehension": "98.5%",
        "evidence_hallucination_rate": "0.6%",
        "qualification_test_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": "PASSED_SIMULATED_QUALIFICATION",
        "qualification_mode": "DETERMINISTIC_FIXTURE",
        "score_is_measured": False,
        "artifact_integrity_verified": False
    }

    execute_write("""
        UPDATE models
        SET status = 'DEMO_QUALIFIED',
            qualification_score = ?,
            benchmark_summary = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (sim_score, json.dumps(benchmark_results), model_id))

    return {
        "model_id": model_id,
        "previous_status": model["status"],
        "new_status": "DEMO_QUALIFIED",
        "production_eligible": False,
        "qualification_score": sim_score,
        "benchmark_results": benchmark_results
    }

def run_shadow_mode_simulation(candidate_model_id: str, baseline_model_id: str = "AEGIS-DEMO-TEXT") -> Dict[str, Any]:
    """
    Return a fixed illustrative comparison; no candidate or baseline model runs.
    """
    candidate = get_model_by_id(candidate_model_id)
    baseline = get_model_by_id(baseline_model_id)

    if not candidate or not baseline:
        raise ValueError("Invalid candidate or baseline model ID")
    for model in (candidate, baseline):
        if (model["status"] != "DEMO_QUALIFIED"
                or not model_integrity_verified(model)
                or model["license"] not in APPROVED_SOVEREIGN_LICENSES):
            raise ValueError("Shadow comparison requires qualified, intact models with approved license metadata")

    agreement_score = 98.4
    divergence_details = [
        {"test_case": "P-204 Vibration Evaluation", "agreement": 99.2, "verdict": "CONCURRING"},
        {"test_case": "Compressor C-101 Interlock Logic", "agreement": 98.0, "verdict": "CONCURRING"},
        {"test_case": "Steam Turbine Trip Condition", "agreement": 97.9, "verdict": "CONCURRING"}
    ]

    execute_write("""
        UPDATE models
        SET shadow_agreement_score = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (agreement_score, candidate_model_id))

    return {
        "candidate_model_id": candidate_model_id,
        "baseline_model_id": baseline_model_id,
        "shadow_agreement_score": agreement_score,
        "sample_cases_tested": 0,
        "score_is_measured": False,
        "models_executed": False,
        "divergence_details": divergence_details,
        "simulation_mode": True
    }
