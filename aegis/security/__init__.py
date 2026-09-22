"""
Aegis Security Package
"""
from aegis.security.rules import INJECTION_PATTERNS, ZERO_WIDTH_CHARS
from aegis.security.firewall import ContextFirewall, get_recent_security_events

def run_security_self_test():
    from aegis.security.self_test import run_security_self_test as run
    return run()

__all__ = [
    "INJECTION_PATTERNS",
    "ZERO_WIDTH_CHARS",
    "ContextFirewall",
    "get_recent_security_events",
    "run_security_self_test"
]
