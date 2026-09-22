"""
Aegis Sovereign AI Runtime - Claim-Level Evidence Gate
Verifies, calculates, or flags individual assertions before deliverable generation.
Supports states: VERIFIED, CALCULATED, INFERRED, UNSUPPORTED, CONFLICTING.
"""
from enum import Enum
from decimal import Decimal
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

class ClaimState(str, Enum):
    VERIFIED = "VERIFIED"
    CALCULATED = "CALCULATED"
    INFERRED = "INFERRED"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICTING = "CONFLICTING"

@dataclass
class Claim:
    text: str
    category: str = "GENERAL"
    status: Optional[str] = None
    citation: Optional[str] = None
    calculation: Optional[str] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "category": self.category,
            "status": self.status,
            "citation": self.citation,
            "calculation": self.calculation,
            "reason": self.reason,
            "metadata": self.metadata
        }

class EvidenceGate:
    """
    Evidence Gate validating each claim in the draft AI deliverable.
    """
    def __init__(self):
        pass

    @staticmethod
    def source_values(sop: str, inspection: str) -> dict:
        """Parse only the supported demo fields; ambiguous or absent fields fail closed."""
        number = r"([0-9]+(?:\.[0-9]+)?)"
        patterns = {
            "measured": (inspection, rf"(?:[0-9]+\. )?Drive End \(DE\) Bearing Horizontal Vibration: {number} mm/s RMS\.?"),
            "limit": (sop, rf"(?:- )?Permitted (?:(?:Continuous Operational Ceiling: )|(?:(?:continuous )?vibration (?:ceiling|limit)(?: under ISO 10816-3 Class II)?(?:: | is ))){number} mm/s(?: RMS)?\.?"),
        }
        values = {}
        for key, (source, pattern) in patterns.items():
            matches = {Decimal(match.group(1)) for line in source.splitlines()
                       if (match := re.fullmatch(pattern, line.strip(), re.I))}
            if len(matches) == 1:
                values[key] = matches.pop()
        if values.get("limit", Decimal(0)) <= 0:
            values.pop("limit", None)
        return values

    def evaluate_claims(
        self, claims: List[Claim], authorized_sop_content: str = "",
        inspection_data_content: str = "", sop_source: str = "Authorized SOP",
        inspection_source: str = "Authorized inspection report"
    ) -> List[Dict[str, Any]]:
        """Conservative demo verification, not general natural-language fact checking."""
        values = self.source_values(authorized_sop_content, inspection_data_content)
        measured, limit = values.get("measured"), values.get("limit")
        number = r"([0-9]+(?:\.[0-9]+)?)"
        results = []
        for claim in claims:
            # A reused claim must not carry a previous successful verification.
            claim.status = ClaimState.UNSUPPORTED.value
            claim.citation = claim.calculation = None
            claim.reason = "No matching fact in the authorized sources or unsupported claim format."
            text = claim.text.strip()
            empirical = re.fullmatch(rf"P-204 drive end bearing horizontal vibration (?:is )?measured at {number} mm/s RMS\.", text, re.I)
            specification = re.fullmatch(rf"Permitted (?:continuous )?vibration ceiling under ISO 10816-3 Class II is {number} mm/s RMS\.", text, re.I)
            calculation = re.fullmatch(rf"Vibration excursion ratio is {number}% of allowable threshold \({number} / {number} = {number}x\)\.", text, re.I)
            conflict = re.fullmatch(rf"Shift log (?:claim|assertion) that {number} mm/s vibration is acceptable and within normal limits\.", text, re.I)
            if empirical and measured is not None and Decimal(empirical.group(1)) == measured:
                claim.status = ClaimState.VERIFIED.value
                claim.citation = inspection_source
                claim.reason = "Matches the drive-end horizontal vibration field in the authorized report."
            elif (specification and limit is not None and Decimal(specification.group(1)) == limit
                  and "iso 10816-3 class ii" in authorized_sop_content.lower()):
                claim.status = ClaimState.VERIFIED.value
                claim.citation = sop_source
                claim.reason = "Matches the permitted ceiling and classification in the synthetic SOP."
            elif calculation and measured is not None and limit is not None:
                percent, numerator, denominator, ratio = map(Decimal, calculation.groups())
                actual = measured / limit
                if (numerator == measured and denominator == limit
                        and ratio == actual.quantize(Decimal("0.01"))
                        and percent == (actual * 100).quantize(Decimal("0.1"))):
                    claim.status = ClaimState.CALCULATED.value
                    claim.calculation = f"{measured} / {limit} = {actual.quantize(Decimal('0.01'))}x"
                    claim.citation = f"{inspection_source} + {sop_source}"
                    claim.reason = "Operands matched to authorized sources; ratio and percent recomputed with Decimal."
            elif (conflict and measured is not None and limit is not None
                  and Decimal(conflict.group(1)) == measured and measured > limit):
                claim.status = ClaimState.CONFLICTING.value
                claim.citation = f"{inspection_source} + {sop_source}"
                claim.reason = "The measured reading exceeds the permitted ceiling."
            elif (text == "Drive-end bearing race degradation or dynamic unbalance is likely root cause."
                  and measured is not None and limit is not None and measured > limit):
                claim.status = ClaimState.INFERRED.value
                claim.citation = "Demo diagnostic hypothesis based on elevated vibration"
                claim.reason = "Possible explanation only; the report does not establish a root cause."
            results.append(claim.to_dict())
        return results

    def filter_deliverable_claims(
        self,
        evaluated_claims: List[Dict[str, Any]],
        risk_level: str = "HIGH"
    ) -> Dict[str, Any]:
        """
        Risk-Adaptive Filtering:
        High risk: UNSUPPORTED claims are strictly BLOCKED from final deliverable.
        Medium risk: UNSUPPORTED claims are flagged with prominent warning disclaimers.
        Low risk: Claims are included with informational notice.
        """
        if risk_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Unknown risk level")
        approved_claims = []
        blocked_claims = []

        for c in evaluated_claims:
            if c["status"] in [ClaimState.VERIFIED.value, ClaimState.CALCULATED.value, ClaimState.INFERRED.value]:
                approved_claims.append(c)
            else:
                if risk_level in ["HIGH", "CRITICAL"]:
                    blocked_claims.append(c)
                else:
                    c_with_warning = dict(c)
                    c_with_warning["warning"] = "UNVERIFIED CLAIM RETAINED UNDER LOW ASSURANCE PROFILE"
                    approved_claims.append(c_with_warning)

        stats = {
            "total_claims": len(evaluated_claims),
            "verified": sum(1 for c in evaluated_claims if c["status"] == ClaimState.VERIFIED.value),
            "calculated": sum(1 for c in evaluated_claims if c["status"] == ClaimState.CALCULATED.value),
            "inferred": sum(1 for c in evaluated_claims if c["status"] == ClaimState.INFERRED.value),
            "unsupported": sum(1 for c in evaluated_claims if c["status"] == ClaimState.UNSUPPORTED.value),
            "conflicting": sum(1 for c in evaluated_claims if c["status"] == ClaimState.CONFLICTING.value),
            "blocked_from_output": len(blocked_claims),
            "conflicting_blocked": sum(c["status"] == "CONFLICTING" for c in blocked_claims),
            "unsupported_blocked": sum(c["status"] == "UNSUPPORTED" for c in blocked_claims)
        }

        return {
            "approved_claims": approved_claims,
            "blocked_claims": blocked_claims,
            "stats": stats
        }
