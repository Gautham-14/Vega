"""
Tests for Aegis Sovereignty Receipts and Verification
"""
import pytest
from aegis.storage.database import init_db
from aegis.receipts.generator import generate_sovereignty_receipt, get_all_receipts
from aegis.receipts.verifier import verify_receipt

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_receipt_generation_and_verification():
    task_record = {
        "id": "TEST-TASK-99",
        "title": "Slurry Pump Inspection Note",
        "risk_level": "HIGH",
        "model_id": "AEGIS-DEMO-TEXT",
        "model_sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        "sop_sha256": "aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000",
        "authoritative_sop": "Pump_SOP_Rev8.txt",
        "rejected_sops": [{"filename": "Pump_SOP_Rev2.txt", "reason": "SUPERSEDED"}],
        "blocked_contexts": [],
        "claims_stats": {"verified": 4, "calculated": 1, "inferred": 1, "unsupported": 1, "blocked_from_output": 1},
        "zero_egress_metrics": {"external_dns_queries": 0, "external_http_requests": 0, "external_api_calls": 0, "egress_bytes": 0},
        "result_artifact": "Pump_Note.md"
    }
    deliverable_text = "# ENGINEERING NOTE: Pump P-204 Verified Findings"

    receipt = generate_sovereignty_receipt(task_record, deliverable_text)

    assert receipt["receipt_id"] == "REC-TEST-TASK-99"
    assert len(receipt["receipt_sha256"]) == 64
    assert len(receipt["artifact_sha256"]) == 64

    # Verify receipt cryptographically
    verification = verify_receipt(receipt["json_content"], deliverable_text)
    assert verification["is_valid"] is True
    assert verification["artifact_hash_verified"] is True
    assert verification["receipt_hash_verified"] is True
    assert verification["zero_egress_verified"] is True
    assert verification["status"] == "VALID"
