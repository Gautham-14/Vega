"""
Aegis Security Package
"""
from aegis.security.rules import INJECTION_PATTERNS, ZERO_WIDTH_CHARS

def __getattr__(name):
    # Filesystem guards must be usable before configuration/database startup.
    if name in {"ContextFirewall", "get_recent_security_events"}:
        from aegis.security import firewall
        return getattr(firewall, name)
    raise AttributeError(name)

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
