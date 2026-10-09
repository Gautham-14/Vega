"""Legacy interfaces fail closed; active custody verifies signed offline bundles.

Installing a package does not verify evidence. These interfaces have no trusted
SLSA/Cosign/TUF verification or signing authority. Use offline_bundle.verify_bundle
and the governed bundle/release workflows.
"""
from typing import Dict, Any
from aegis.control.store import Denied

def verify_slsa_provenance(artifact_path: str, expected_builder_id: str) -> bool:
    raise Denied("SLSA_VERIFICATION_UNAVAILABLE", "No independently configured SLSA verifier; use the signed offline bundle workflow")

def generate_tuf_metadata(targets: Dict[str, Any]) -> Dict[str, Any]:
    raise Denied("TUF_SIGNING_UNAVAILABLE", "No trusted TUF root or signing authority; unsigned metadata cannot authorize an update")

def verify_cosign_signature(artifact_path: str, pubkey_path: str) -> bool:
    raise Denied("COSIGN_VERIFICATION_UNAVAILABLE", "No independently configured Cosign verifier; use the signed offline bundle workflow")
