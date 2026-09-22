"""Shared, fail-closed document policy for retrieval and task mounting."""
from datetime import date

CLEARANCES = {"INTERNAL": 1, "RESTRICTED": 2, "CONFIDENTIAL": 3}


def rejection_reason(doc: dict, department: str, equipment_id: str, clearance: str) -> str | None:
    if doc.get("is_quarantined") or doc.get("status") == "QUARANTINED":
        return "Document is in QUARANTINE"
    if doc.get("status") == "SUPERSEDED":
        return "Superseded revision is not authoritative"
    if doc.get("status") != "CURRENT_APPROVED":
        return "Document is not CURRENT_APPROVED"
    if doc.get("department") not in {department, "Universal"}:
        return "Department access violation"
    if clearance not in CLEARANCES or doc.get("classification") not in CLEARANCES:
        return "Unknown clearance or classification"
    if CLEARANCES[doc["classification"]] > CLEARANCES[clearance]:
        return "Clearance violation"
    if doc.get("equipment_id") not in {equipment_id, "ALL"}:
        return "Equipment applicability mismatch"
    try:
        if date.fromisoformat(doc.get("effective_date", "")) > date.today():
            return "Document is not yet effective"
    except (ValueError, TypeError):
        return "Invalid or missing effective date"
    return None
