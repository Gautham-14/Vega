"""
Vega Sovereign AI Runtime - Authority-Aware Knowledge Registry
Manages revision tracking, equipment applicability, superseded rejection logic,
and department authorization metadata.
"""
import hashlib
from datetime import date
from vega.config import MAX_FILE_SIZE_BYTES
from vega.knowledge.policy import rejection_reason
from vega.storage.paths import safe_filename
from vega.security.firewall import ContextFirewall
from typing import Dict, Any, List, Optional
from vega.storage.database import query_all, query_one, execute_write

def compute_file_sha256(content: str) -> str:
    """Calculate SHA-256 hash of text content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def get_all_documents(include_quarantined: bool = True) -> List[Dict[str, Any]]:
    """Return all documents in the knowledge registry."""
    if include_quarantined:
        return query_all("SELECT * FROM documents ORDER BY equipment_id, title, revision")
    else:
        return query_all("SELECT * FROM documents WHERE is_quarantined = 0 AND status != 'QUARANTINED' ORDER BY equipment_id, title, revision")

def get_document_by_id(doc_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve document by primary key."""
    return query_one("SELECT * FROM documents WHERE id = ?", (doc_id,))

def get_document_by_filename(filename: str) -> Optional[Dict[str, Any]]:
    """Retrieve document by filename."""
    return query_one("SELECT * FROM documents WHERE filename = ?", (filename,))

def add_document(doc_data: Dict[str, Any]) -> str:
    """Validate and scan a new document without replacing existing evidence."""
    safe_filename(doc_data["filename"])
    if doc_data["status"] not in {"CURRENT_APPROVED", "SUPERSEDED", "QUARANTINED", "DRAFT"}:
        raise ValueError("Unknown document status")
    if doc_data.get("classification", "INTERNAL") not in {"INTERNAL", "RESTRICTED", "CONFIDENTIAL", "UNTRUSTED_EXTERNAL"}:
        raise ValueError("Unknown document classification")
    date.fromisoformat(doc_data.get("effective_date", "2024-01-01"))
    if get_document_by_id(doc_data["id"]) or get_document_by_filename(doc_data["filename"]):
        raise ValueError("Document ID or filename already exists; import a new revision")
    content = doc_data["content"]
    if len(content.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
        raise ValueError("Document exceeds the content size limit")
    sha256 = compute_file_sha256(content)
    if doc_data.get("sha256") and doc_data["sha256"] != sha256:
        raise ValueError("Document content hash mismatch")
    is_quarantined = 1 if doc_data.get("status") == "QUARANTINED" or doc_data.get("is_quarantined") else 0
    if not ContextFirewall().scan_text(content, doc_data["filename"])["is_safe"]:
        is_quarantined = 1

    execute_write("""
        INSERT INTO documents (
            id, filename, title, revision, status, equipment_id,
            department, classification, effective_date, sha256,
            content, file_path, is_quarantined, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        doc_data["id"],
        doc_data["filename"],
        doc_data["title"],
        doc_data["revision"],
        "QUARANTINED" if is_quarantined else doc_data["status"],
        doc_data["equipment_id"],
        doc_data["department"],
        doc_data.get("classification", "INTERNAL"),
        doc_data.get("effective_date", "2024-01-01"),
        sha256,
        content,
        doc_data.get("file_path", f"data/knowledge/{doc_data['filename']}"),
        is_quarantined
    ))
    return doc_data["id"]

def find_authoritative_document(
    equipment_id: str,
    department: str,
    doc_family: str = "Pump_SOP",
    user_clearance: str = "INTERNAL"
) -> Dict[str, Any]:
    """
    Demonstrates Vega's Authority-Aware Knowledge Retrieval.
    Even if older documents (Rev2, Rev5) match keywords, Vega filters:
    1. Must match department or be universal
    2. Must match equipment applicability
    3. Rejects any document marked SUPERSEDED
    4. Selects ONLY CURRENT_APPROVED authoritative document
    """
    candidates = query_all("""
        SELECT * FROM documents
        WHERE (equipment_id = ? OR equipment_id = 'ALL')
          AND (department = ? OR department = 'Universal')
          AND is_quarantined = 0
          AND substr(filename, 1, ?) = ?
        ORDER BY effective_date DESC, id
    """, (equipment_id, department, len(doc_family), doc_family))

    rejected_reasons = []
    authoritative = None
    current = []

    for doc in candidates:
        if doc["status"] == "SUPERSEDED":
            rejected_reasons.append({
                "filename": doc["filename"],
                "revision": doc["revision"],
                "reason": f"SUPERSEDED by current active revision (Effective: {doc['effective_date']})"
            })
        elif rejection_reason(doc, department, equipment_id, user_clearance) is None:
            current.append(doc)

    if current:
        latest = [doc for doc in current if doc["effective_date"] == current[0]["effective_date"]]
        if len(latest) == 1:
            authoritative = latest[0]

    return {
        "authoritative_document": authoritative,
        "superseded_documents_rejected": rejected_reasons,
        "total_evaluated": len(candidates)
    }
