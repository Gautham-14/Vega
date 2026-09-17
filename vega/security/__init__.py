"""
Vega Security Package
"""
from vega.security.rules import INJECTION_PATTERNS, ZERO_WIDTH_CHARS
from vega.security.firewall import ContextFirewall, get_recent_security_events

def run_security_self_test():
    from vega.security.self_test import run_security_self_test as run
    return run()

__all__ = [
    "INJECTION_PATTERNS",
    "ZERO_WIDTH_CHARS",
    "ContextFirewall",
    "get_recent_security_events",
    "run_security_self_test"
]
