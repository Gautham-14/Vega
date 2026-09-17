"""
Vega Knowledge Package
"""
from vega.knowledge.registry import (
    get_all_documents,
    get_document_by_id,
    get_document_by_filename,
    add_document,
    find_authoritative_document,
    compute_file_sha256
)
from vega.knowledge.demo_data import seed_knowledge_registry, DEMO_DOCUMENTS

__all__ = [
    "get_all_documents",
    "get_document_by_id",
    "get_document_by_filename",
    "add_document",
    "find_authoritative_document",
    "compute_file_sha256",
    "seed_knowledge_registry",
    "DEMO_DOCUMENTS"
]
