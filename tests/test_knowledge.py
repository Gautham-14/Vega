"""
Tests for Aegis Authority-Aware Knowledge Registry
"""
import pytest
from aegis.storage.database import init_db
from aegis.knowledge.demo_data import seed_knowledge_registry
from aegis.knowledge.registry import (
    get_all_documents,
    get_document_by_filename,
    find_authoritative_document
)

@pytest.fixture(autouse=True)
def setup_knowledge():
    init_db()
    seed_knowledge_registry()

def test_knowledge_seeding():
    docs = get_all_documents()
    assert len(docs) >= 5
    filenames = [d["filename"] for d in docs]
    assert "Pump_SOP_Rev2.txt" in filenames
    assert "Pump_SOP_Rev5.txt" in filenames
    assert "Pump_SOP_Rev8.txt" in filenames
    assert "P204_Vibration_Inspection_Report_2026_09.txt" in filenames

def test_authority_aware_superseded_filtering():
    result = find_authoritative_document(
        equipment_id="Pump P-204",
        department="Engineering",
        doc_family="Pump_SOP"
    )

    auth = result["authoritative_document"]
    rejected = result["superseded_documents_rejected"]

    assert auth is not None
    assert auth["filename"] == "Pump_SOP_Rev8.txt"
    assert auth["revision"] == "Rev8"
    assert auth["status"] == "CURRENT_APPROVED"

    assert len(rejected) >= 2
    rejected_filenames = [r["filename"] for r in rejected]
    assert "Pump_SOP_Rev2.txt" in rejected_filenames
    assert "Pump_SOP_Rev5.txt" in rejected_filenames
    assert all("SUPERSEDED" in r["reason"] for r in rejected)
