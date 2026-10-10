"""
Aegis Knowledge Package
"""

from aegis.knowledge.demo_data import DEMO_DOCUMENTS, seed_knowledge_registry
from aegis.knowledge.registry import (
    add_document,
    compute_file_sha256,
    find_authoritative_document,
    get_all_documents,
    get_document_by_filename,
    get_document_by_id,
)

__all__ = [
    "get_all_documents",
    "get_document_by_id",
    "get_document_by_filename",
    "add_document",
    "find_authoritative_document",
    "compute_file_sha256",
    "seed_knowledge_registry",
    "DEMO_DOCUMENTS",
]
