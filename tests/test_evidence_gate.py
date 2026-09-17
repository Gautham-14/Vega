"""
Tests for Vega Claim-Level Evidence Gate
"""
import pytest
from vega.runtime.evidence_gate import EvidenceGate, Claim, ClaimState

def test_evidence_gate_classification():
    gate = EvidenceGate()

    c1 = Claim(text="P-204 drive end bearing horizontal vibration measured at 7.20 mm/s RMS.")
    c2 = Claim(text="Permitted vibration ceiling under ISO 10816-3 Class II is 4.50 mm/s RMS.")
    c3 = Claim(text="Vibration excursion ratio is 160.0% of allowable threshold (7.20 / 4.50 = 1.60x).")
    c4 = Claim(text="Drive-end bearing race degradation or dynamic unbalance is likely root cause.")
    c5 = Claim(text="Emergency shutdown of entire electrical grid is immediately mandatory.")
    c6 = Claim(text="Shift log assertion that 7.20 mm/s vibration is acceptable and within normal limits.")

    evaluated = gate.evaluate_claims(
        claims=[c1, c2, c3, c4, c5, c6],
        authorized_sop_content="Permitted vibration ceiling under ISO 10816-3 Class II is 4.50 mm/s RMS.",
        inspection_data_content="Drive End (DE) Bearing Horizontal Vibration: 7.20 mm/s RMS"
    )

    statuses = [c["status"] for c in evaluated]
    assert statuses[0] == ClaimState.VERIFIED.value
    assert statuses[1] == ClaimState.VERIFIED.value
    assert statuses[2] == ClaimState.CALCULATED.value
    assert statuses[3] == ClaimState.INFERRED.value
    assert statuses[4] == ClaimState.UNSUPPORTED.value
    assert statuses[5] == ClaimState.CONFLICTING.value

def test_risk_adaptive_claim_filtering():
    gate = EvidenceGate()
    evaluated = [
        {"text": "Claim 1", "status": "VERIFIED"},
        {"text": "Claim 2", "status": "CALCULATED"},
        {"text": "Claim 3", "status": "INFERRED"},
        {"text": "Claim 4", "status": "CONFLICTING"},
        {"text": "Claim 5", "status": "UNSUPPORTED"}
    ]

    # For HIGH risk, both CONFLICTING and UNSUPPORTED must be stripped
    high_risk_filtered = gate.filter_deliverable_claims(evaluated, risk_level="HIGH")
    assert len(high_risk_filtered["approved_claims"]) == 3
    assert len(high_risk_filtered["blocked_claims"]) == 2
    assert high_risk_filtered["stats"]["blocked_from_output"] == 2
    assert high_risk_filtered["stats"]["conflicting"] == 1
    assert high_risk_filtered["stats"]["unsupported"] == 1
