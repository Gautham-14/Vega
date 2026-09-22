"""
Aegis Sovereign AI Runtime - Sovereignty Receipts API Route
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from aegis.receipts.generator import get_all_receipts, get_receipt_by_task_id
from aegis.receipts.verifier import verify_receipt
from aegis.runtime.task_runner import get_task_by_id
from aegis import config
from aegis.storage.paths import contained_file
import json

router = APIRouter(prefix="/api/receipts", tags=["Receipts"])

@router.get("")
def list_receipts() -> List[Dict[str, Any]]:
    return get_all_receipts()

@router.get("/{task_id}")
def get_receipt(task_id: str) -> Dict[str, Any]:
    receipt = get_receipt_by_task_id(task_id)
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found for task")
    return receipt

@router.post("/{task_id}/verify")
def verify_task_receipt(task_id: str) -> Dict[str, Any]:
    receipt = get_receipt_by_task_id(task_id)
    if not receipt:
        raise HTTPException(status_code=404, detail="Receipt not found")

    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] != "COMPLETED":
        return {"is_valid": False, "status": "TASK_NOT_COMPLETED",
                "artifact_hash_verified": False, "receipt_hash_verified": False,
                "zero_egress_verified": False, "os_network_isolation_verified": False}

    # Verify exported bytes, not just the cached database copy.
    try:
        artifact_path = contained_file(config.ARTIFACTS_DIR, task["result_artifact"])
        if not artifact_path.exists():
            legacy_dir = contained_file(config.WORKSPACES_DIR, f"enclave_{task_id}")
            artifact_path = contained_file(legacy_dir, task["result_artifact"])
        artifact_text = artifact_path.read_bytes().decode("utf-8")
        receipt_path = contained_file(config.RECEIPTS_DIR, f"receipt_{task_id}.json")
        exported_receipt = json.loads(receipt_path.read_bytes())
        verification = verify_receipt(exported_receipt, artifact_text)
        verification["stored_receipt_matches_export"] = exported_receipt == receipt["json_content"]
        markdown_path = contained_file(config.RECEIPTS_DIR, f"receipt_{task_id}.md")
        verification["markdown_export_matches"] = markdown_path.read_text(encoding="utf-8") == receipt["markdown_content"]
        exports_match = verification["stored_receipt_matches_export"] and verification["markdown_export_matches"]
        verification["is_valid"] &= exports_match
        if not exports_match:
            verification["status"] = "TAMPERED"
    except (OSError, ValueError, TypeError, AttributeError):
        return {"is_valid": False, "status": "MISSING_OR_INVALID_EXPORT",
                "artifact_hash_verified": False, "receipt_hash_verified": False,
                "zero_egress_verified": False, "os_network_isolation_verified": False}
    return verification
