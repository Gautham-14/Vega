"""
Aegis Sovereign AI Runtime - Security Heuristics & Injection Rule Definitions
"""
import re
from typing import List, Dict, Any

INJECTION_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "RULE-INJ-001",
        "name": "Directive Override",
        "pattern": re.compile(r"ignore\s+(all\s+|previous\s+|any\s+|system\s+)?instructions?", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Attempt to reset or supersede model system instructions."
    },
    {
        "id": "RULE-INJ-002",
        "name": "Unauthorized File Exfiltration",
        "pattern": re.compile(r"(read|access|exfiltrate|fetch)\s+unauthorized\s+files?", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Attempt to breach enclave boundary and inspect forbidden files."
    },
    {
        "id": "RULE-INJ-003",
        "name": "Confidential Disclosure Request",
        "pattern": re.compile(r"reveal\s+(confidential|secret|private|hidden|password|key|token)", re.IGNORECASE),
        "severity": "HIGH",
        "description": "Attempt to extract confidential organizational data or credentials."
    },
    {
        "id": "RULE-INJ-004",
        "name": "Exfiltration Target",
        "pattern": re.compile(r"(exfiltrate|leak|post|send)\s+.*?\s+(to|url|http|ftp)", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Attempt to establish an egress exfiltration vector."
    },
    {
        "id": "RULE-INJ-005",
        "name": "System Override Command",
        "pattern": re.compile(r"system\s+(override|bypass|disable\s+evidence)", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Attempt to suppress sovereign governance or verification checks."
    },
    {
        "id": "RULE-INJ-006",
        "name": "Jailbreak Token",
        "pattern": re.compile(r"(dan\s+mode|jailbreak|unrestricted\s+developer\s+mode)", re.IGNORECASE),
        "severity": "HIGH",
        "description": "Generic adversarial jailbreak attempt."
    },
    {
        "id": "RULE-INJ-007",
        "name": "Hidden Markup Comment Injection",
        "pattern": re.compile(r"<!--[\s\S]*?(override|ignore|exfiltrate|secret|password)[\s\S]*?-->", re.IGNORECASE),
        "severity": "HIGH",
        "description": "Suspicious hidden HTML/Markdown comment containing prompt override."
    },
    {
        "id": "RULE-INJ-008",
        "name": "Synthetic Delimiter Tampering",
        "pattern": re.compile(r"(<\/?(?:system|instruction|user|assistant)>|\[\/?(?:inst|sys)\]|###\s*(?:system|human|assistant):)", re.IGNORECASE),
        "severity": "HIGH",
        "description": "Attempt to inject chat template delimiters or fake system turns."
    },
    {
        "id": "RULE-INJ-009",
        "name": "Base64 Obfuscated Payload Pattern",
        "pattern": re.compile(r"(?:eval|exec|decode)\s*\(\s*(?:base64|b64decode|atob)", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "Encoded obfuscation construct attempting code execution."
    }
]

# Hidden characters: zero-width spaces, joiners, right-to-left override
ZERO_WIDTH_CHARS = {
    '\u200b': "ZERO_WIDTH_SPACE",
    '\u200c': "ZERO_WIDTH_NON_JOINER",
    '\u200d': "ZERO_WIDTH_JOINER",
    '\ufeff': "ZERO_WIDTH_NO_BREAK_SPACE",
    '\u202e': "RIGHT_TO_LEFT_OVERRIDE",
    '\u2066': "LEFT_TO_RIGHT_ISOLATE"
}
