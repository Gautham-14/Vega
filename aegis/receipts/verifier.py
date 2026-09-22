"""
Aegis Sovereign AI Runtime - Receipt Cryptographic Verifier
Validates receipt integrity, compares declared SHA-256 with recalculations,
and checks the simulated task call counters recorded in the receipt.
"""
import json
import hashlib
from typing import Dict, Any

def verify_receipt(receipt_dict: Dict[str, Any], artifact_text: str) -> Dict[str, Any]:
    """
    Verify stored hashes and demo counters. A self-hash is not authentication.
    """
    declared_receipt_hash = receipt_dict.get("receipt_sha256")
    deliverable = receipt_dict.get("deliverable_verification", {})
    declared_artifact_hash = deliverable.get("artifact_sha256")

    # Recalculate artifact hash
    recalculated_artifact_hash = hashlib.sha256(artifact_text.encode("utf-8")).hexdigest()
    artifact_valid = (recalculated_artifact_hash == declared_artifact_hash)

    # Recalculate receipt hash (excluding receipt_sha256 key itself)
    clean_dict = {k: v for k, v in receipt_dict.items() if k != "receipt_sha256"}
    recalculated_receipt_hash = hashlib.sha256(json.dumps(clean_dict, indent=2, sort_keys=True).encode("utf-8")).hexdigest()

    receipt_valid = (recalculated_receipt_hash == declared_receipt_hash)

    zero_egress = receipt_dict.get("zero_egress_proof", {})
    zero_egress_valid = all(type(zero_egress.get(key)) is int and zero_egress[key] == 0
                            for key in ("external_dns_requests", "external_http_requests",
                                        "external_api_calls", "network_egress_bytes"))

    all_valid = artifact_valid and receipt_valid and zero_egress_valid

    return {
        "is_valid": all_valid,
        "artifact_hash_verified": artifact_valid,
        "receipt_hash_verified": receipt_valid,
        "zero_egress_verified": zero_egress_valid,
        "verification_scope": "RECEIPT_AND_SIMULATED_TASK_CALLS",
        "os_network_isolation_verified": False,
        "declared_receipt_hash": declared_receipt_hash,
        "recalculated_receipt_hash": recalculated_receipt_hash,
        "declared_artifact_hash": declared_artifact_hash,
        "recalculated_artifact_hash": recalculated_artifact_hash,
        "status": "TAMPERED" if not (artifact_valid and receipt_valid) else ("VALID" if zero_egress_valid else "COUNTERS_NOT_ZERO_OR_UNKNOWN")
    }
