"""
Aegis Sovereign AI Runtime - Knowledge API Route
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from aegis.knowledge.registry import (
    get_all_documents,
    get_document_by_id,
    add_document,
    find_authoritative_document
)

router = APIRouter(prefix="/api/knowledge", tags=["Knowledge"])

class DocumentUploadRequest(BaseModel):
    id: str
    filename: str
    title: str
    revision: str
    status: str
    equipment_id: str
    department: str
    classification: str = "INTERNAL"
    effective_date: str = "2024-01-01"
    content: str

@router.get("")
def list_documents(include_quarantined: bool = True) -> List[Dict[str, Any]]:
    return get_all_documents(include_quarantined=include_quarantined)

@router.get("/search/authoritative")
def query_authoritative_sop(
    equipment_id: str,
    department: str,
    doc_family: str
) -> Dict[str, Any]:
    return find_authoritative_document(
        equipment_id=equipment_id,
        department=department,
        doc_family=doc_family
    )

@router.get("/{doc_id}")
def get_doc(doc_id: str) -> Dict[str, Any]:
    doc = get_document_by_id(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc

@router.post("/upload")
def upload_document(req: DocumentUploadRequest) -> Dict[str, Any]:
    try:
        doc_id = add_document(req.model_dump())
        return {"status": "SUCCESS", "document_id": doc_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
