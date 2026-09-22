"""
Aegis Sovereign AI Runtime - Industrial Context Firewall
Inspects all incoming documents, prompts, RAG context, and files for prompt injections,
hidden instructions, zero-width steganography, and malicious overrides.
"""
import uuid
import time
from typing import Dict, Any, List, Optional
from aegis.security.rules import INJECTION_PATTERNS, ZERO_WIDTH_CHARS
from aegis.storage.database import execute_write, query_all

class ContextFirewall:
    """
    Context Firewall enforcing strict distrust of all external context.
    """
    def __init__(self):
        self.patterns = INJECTION_PATTERNS
        self.zero_width_chars = ZERO_WIDTH_CHARS

    def scan_text(self, text: str, source_identifier: str = "user_input") -> Dict[str, Any]:
        """
        Scan a block of text for prompt injection, hidden instructions, and adversarial payload.
        """
        matched_rules = []
        highest_severity = "NONE"

        # 1. Check Regex Injection Patterns
        for rule in self.patterns:
            matches = rule["pattern"].findall(text)
            if matches:
                matched_rules.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "matched_snippets": [str(m) for m in matches[:3]]
                })
                if rule["severity"] == "CRITICAL":
                    highest_severity = "CRITICAL"
                elif rule["severity"] == "HIGH" and highest_severity != "CRITICAL":
                    highest_severity = "HIGH"

        # 2. Check for hidden zero-width and control characters
        detected_hidden = []
        for char in text:
            if char in self.zero_width_chars:
                detected_hidden.append(self.zero_width_chars[char])

        if detected_hidden:
            matched_rules.append({
                "rule_id": "RULE-HIDDEN-001",
                "rule_name": "Hidden Character Steganography",
                "severity": "HIGH",
                "description": f"Detected {len(detected_hidden)} hidden/zero-width characters.",
                "matched_snippets": detected_hidden[:5]
            })
            if highest_severity == "NONE":
                highest_severity = "HIGH"

        is_safe = len(matched_rules) == 0
        action = "CLEARED" if is_safe else "QUARANTINED"
        risk_score = 0.0
        if highest_severity == "CRITICAL":
            risk_score = 0.98
        elif highest_severity == "HIGH":
            risk_score = 0.75
        elif highest_severity == "MEDIUM":
            risk_score = 0.40

        # Log security event if unsafe
        if not is_safe:
            event_id = f"SEC-{uuid.uuid4().hex[:8]}"
            rule_names = ", ".join(r["rule_name"] for r in matched_rules)
            execute_write("""
                INSERT INTO security_events (
                    id, event_type, severity, description,
                    source_document, matched_rule, raw_payload,
                    action_taken, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                event_id,
                "PROMPT_INJECTION" if any("INJ" in r["rule_id"] for r in matched_rules) else "HIDDEN_INSTRUCTION",
                highest_severity,
                f"Context Firewall blocked suspicious content from: {source_identifier}",
                source_identifier,
                rule_names,
                None,  # Audit rule IDs, never confidential document or query text.
                action
            ))

        return {
            "is_safe": is_safe,
            "action": action,
            "risk_score": risk_score,
            "highest_severity": highest_severity,
            "matched_rules": matched_rules,
            "hidden_char_count": len(detected_hidden),
            "source": source_identifier,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    def scan_document(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a document record from knowledge registry."""
        filename = doc.get("filename", "unknown_doc")
        content = doc.get("content", "")
        return self.scan_text(content, source_identifier=filename)

def get_recent_security_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve security audit events."""
    return query_all("SELECT * FROM security_events ORDER BY created_at DESC LIMIT ?", (limit,))
