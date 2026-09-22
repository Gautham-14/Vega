"""
Aegis Sovereign AI Runtime - Sovereignty Receipt Generator
Creates self-hashed execution receipts in both JSON and Markdown format.
Records model hashes, evidence classifications, and simulated task call counters.
"""
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from aegis.config import RECEIPTS_DIR
from aegis.storage.paths import contained_file, safe_filename
from aegis.storage.database import execute_write, query_all, query_one

def compute_sha256(data: str) -> str:
    """Calculate SHA-256 hash of string data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def generate_sovereignty_receipt(task_record: Dict[str, Any], final_artifact_content: str) -> Dict[str, Any]:
    """
    Generate dual-format sovereignty receipt for a completed task.
    """
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    task_id = safe_filename(task_record["id"])
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Calculate Artifact Hash
    artifact_hash = compute_sha256(final_artifact_content)

    # Model and SOP hashes
    model_hash = task_record["model_sha256"]
    sop_hash = task_record["sop_sha256"]

    # Zero-egress metrics
    egress_metrics = task_record.get("zero_egress_metrics", {})

    # Claims summary
    claims_stats = task_record.get("claims_stats", {})

    # Build JSON Receipt Payload
    receipt_dict = {
        "aegis_sovereign_receipt_version": "1.0",
        "timestamp": timestamp,
        "task_id": task_id,
        "task_title": task_record.get("title", "Industrial Task Execution"),
        "risk_level": task_record.get("risk_level", "HIGH"),
        "runtime_mode": "SIMULATION",
        "operator": "AEGIS-SOVEREIGN-LOCAL-ENGINE",
        "zero_egress_proof": {
            "external_dns_requests": egress_metrics.get("external_dns_queries"),
            "external_http_requests": egress_metrics.get("external_http_requests"),
            "external_api_calls": egress_metrics.get("external_api_calls"),
            "network_egress_bytes": egress_metrics.get("egress_bytes"),
            "air_gap_enforced": False,
            "metrics_scope": "SIMULATED_TASK_CALLS"
        },
        "model_provenance": {
            "pipeline_models": task_record.get("model_hashes", []),
            "model_id": task_record.get("model_id", "AEGIS-DEMO-TEXT"),
            "model_manifest_sha256": model_hash,
            "qualification_status": "QUALIFIED",
            "execution_backend": "MockModelAdapter (Deterministic Local Sim)"
        },
        "knowledge_authority": {
            "input_hashes": task_record.get("input_hashes", []),
            "selected_sop": task_record.get("authoritative_sop", "Pump_SOP_Rev8"),
            "sop_sha256": sop_hash,
            "superseded_sops_rejected": task_record.get("rejected_sops", []),
            "malicious_context_blocked": task_record.get("blocked_contexts", [])
        },
        "evidence_gate_audit": {
            "verified_claims": claims_stats.get("verified", 0),
            "calculated_claims": claims_stats.get("calculated", 0),
            "inferred_claims": claims_stats.get("inferred", 0),
            "conflicting_claims_blocked": claims_stats.get("conflicting_blocked", 0),
            "unsupported_claims_blocked": claims_stats.get("unsupported_blocked", 0),
            "total_claims_blocked": claims_stats.get("blocked_from_output", 0),
            "evidence_gate_verdict": "DEMO_POLICY_APPLIED" if claims_stats else "NOT_EVALUATED",
            "retained_claims": task_record.get("approved_claims", [])
        },
        "deliverable_verification": {
            "artifact_filename": task_record.get("result_artifact", f"{task_id}_Approval_Note.md"),
            "artifact_sha256": artifact_hash
        }
    }

    # Compute Receipt Self Hash
    receipt_json_str = json.dumps(receipt_dict, indent=2, sort_keys=True)
    receipt_hash = compute_sha256(receipt_json_str)
    receipt_dict["receipt_sha256"] = receipt_hash

    # Save JSON file
    json_path = contained_file(RECEIPTS_DIR, f"receipt_{task_id}.json")
    with json_path.open("xb") as stream:
        stream.write(json.dumps(receipt_dict, indent=2).encode("utf-8"))

    # Build Markdown Receipt
    markdown_content = f"""# AEGIS EXECUTION RECEIPT

**Task ID:** `{task_id}`<br>
**Task Title:** {task_record.get('title', 'Industrial Task Execution')}<br>
**Execution Timestamp:** `{timestamp}`<br>
**Runtime Mode:** `SIMULATION`<br>
**Receipt Hash (SHA-256):** `{receipt_hash}`<br>

---

### Simulated Task Network Call Counters
- **External DNS Requests:** `{egress_metrics.get('external_dns_queries', 'UNKNOWN')}`
- **External HTTP Requests:** `{egress_metrics.get('external_http_requests', 'UNKNOWN')}`
- **External API Calls:** `{egress_metrics.get('external_api_calls', 'UNKNOWN')}`
- **Network Egress:** `{egress_metrics.get('egress_bytes', 'UNKNOWN')} bytes`
- **OS Network Isolation:** `NOT VERIFIED`

### Model Provenance
- **Model ID:** `{task_record.get('model_id', 'AEGIS-DEMO-TEXT')}`
- **Model SHA-256:** `{model_hash[:24]}...`
- **Status:** `QUALIFIED`

### Knowledge & Authority Layer
- **Authoritative SOP Selected:** `{task_record.get('authoritative_sop', 'Pump_SOP_Rev8')}`
- **SOP Hash (SHA-256):** `{sop_hash[:24]}...`
- **Superseded SOPs Rejected:** `{len(task_record.get('rejected_sops', []))}`
- **Malicious Contexts Blocked:** `{len(task_record.get('blocked_contexts', []))}`

### Evidence Gate Audit
- **Verified Claims:** `{claims_stats.get('verified', 0)}`
- **Calculated Claims:** `{claims_stats.get('calculated', 0)}`
- **Inferred Claims:** `{claims_stats.get('inferred', 0)}`
- **Conflicting Claims Blocked:** `{claims_stats.get('conflicting_blocked', 0)}`
- **Unsupported Claims Blocked:** `{claims_stats.get('unsupported_blocked', 0)}`
- **Total Blocked Claims:** `{claims_stats.get('blocked_from_output', 0)}`
- **Gate Verdict:** `{receipt_dict['evidence_gate_audit']['evidence_gate_verdict']}`

### Deliverable Artifact
- **File:** `{task_record.get('result_artifact', f'{task_id}_Approval_Note.md')}`
- **Artifact SHA-256:** `{artifact_hash}`

---
*Generated by Aegis Sovereign AI Runtime. SHA-256 checks detect changes relative to this stored receipt and artifact; they are not a digital signature or proof of host network isolation.*
"""

    md_path = contained_file(RECEIPTS_DIR, f"receipt_{task_id}.md")
    with md_path.open("xb") as stream:
        stream.write(markdown_content.encode("utf-8"))

    # Record in database
    receipt_id = f"REC-{task_id}"
    execute_write("""
        INSERT INTO receipts (
            id, task_id, receipt_sha256, artifact_sha256,
            model_sha256, sop_sha256, json_content,
            markdown_content, json_path, markdown_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        receipt_id,
        task_id,
        receipt_hash,
        artifact_hash,
        model_hash,
        sop_hash,
        json.dumps(receipt_dict),
        markdown_content,
        str(json_path),
        str(md_path)
    ))

    return {
        "task_id": task_id,
        "receipt_id": receipt_id,
        "receipt_sha256": receipt_hash,
        "artifact_sha256": artifact_hash,
        "json_path": str(json_path),
        "markdown_path": str(md_path),
        "json_content": receipt_dict,
        "markdown_content": markdown_content
    }

def get_all_receipts() -> List[Dict[str, Any]]:
    """Retrieve all sovereignty receipts."""
    return query_all("SELECT id, task_id, receipt_sha256, artifact_sha256, json_path, markdown_path, created_at FROM receipts ORDER BY created_at DESC")

def get_receipt_by_task_id(task_id: str) -> Optional[Dict[str, Any]]:
    """Get receipt by task id."""
    r = query_one("SELECT * FROM receipts WHERE task_id = ?", (task_id,))
    if r and isinstance(r.get("json_content"), str):
        r["json_content"] = json.loads(r["json_content"])
    return r
