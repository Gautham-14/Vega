"""
Tests for Vega Ephemeral Task Enclave and Least-Privilege Isolation
"""
import pytest
from vega.runtime.enclave import EphemeralEnclave
from vega.knowledge.registry import compute_file_sha256

def test_enclave_isolation_and_mounting():
    enclave = EphemeralEnclave(task_id="TEST-ENCLAVE-01", department="Engineering", equipment_id="Pump P-204")
    enclave.initialize()

    assert enclave.enclave_dir.exists()

    # Authorized engineering document
    auth_doc = {
        "filename": "Pump_SOP_Rev8.txt",
        "revision": "Rev8",
        "status": "CURRENT_APPROVED",
        "department": "Engineering",
        "equipment_id": "Pump P-204",
        "content": "Permitted vibration: 4.5 mm/s."
    }
    auth_doc.update(classification="INTERNAL", effective_date="2024-01-01",
                    sha256=compute_file_sha256(auth_doc["content"]))
    assert enclave.mount_document(auth_doc) is True
    assert len(enclave.mounted_files) == 1

    # Unauthorized HR document
    hr_doc = {
        "filename": "HR_Salaries.txt",
        "revision": "Rev1",
        "status": "CURRENT_APPROVED",
        "department": "HR",
        "equipment_id": "ALL",
        "content": "Secret HR content."
    }
    assert enclave.mount_document(hr_doc) is False
    assert len(enclave.blocked_files) == 1
    assert "Department access violation" in enclave.blocked_files[0]["reason"]

    # Superseded document
    superseded_doc = {
        "filename": "Pump_SOP_Rev2.txt",
        "revision": "Rev2",
        "status": "SUPERSEDED",
        "department": "Engineering",
        "equipment_id": "Pump P-204",
        "content": "Old 6.0 mm/s limit."
    }
    assert enclave.mount_document(superseded_doc) is False
    assert any("Superseded" in b["reason"] for b in enclave.blocked_files)

    # Quarantined document
    quarantined_doc = {
        "filename": "Poisoned.txt",
        "status": "QUARANTINED",
        "department": "Engineering",
        "equipment_id": "Pump P-204",
        "content": "Bad injection.",
        "is_quarantined": True
    }
    assert enclave.mount_document(quarantined_doc) is False

    # Clearance level restriction: user has INTERNAL, doc requires CONFIDENTIAL
    confidential_doc = {
        "filename": "Confidential_Specs.txt",
        "revision": "Rev1",
        "status": "CURRENT_APPROVED",
        "department": "Engineering",
        "classification": "CONFIDENTIAL",
        "equipment_id": "Pump P-204",
        "content": "Proprietary design specs."
    }
    assert enclave.mount_document(confidential_doc) is False
    assert any("Clearance violation" in b["reason"] for b in enclave.blocked_files)
