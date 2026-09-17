"""
Tests for Vega 6-Point Security Self-Test Suite
"""
import pytest
from vega.storage.database import init_db
from vega.models.registry import seed_model_registry
from vega.knowledge.demo_data import seed_knowledge_registry
from vega.security.self_test import run_security_self_test

@pytest.fixture(autouse=True)
def setup_all():
    init_db()
    seed_model_registry()
    seed_knowledge_registry()

def test_six_point_security_self_test():
    results = run_security_self_test()
    assert results["all_passed"] is True
    assert results["tests_passed"] == 6
    assert results["tests_total"] == 6
    assert results["summary"] == "6 / 6 SECURITY TESTS PASSED"

    for t in results["tests"]:
        assert t["status"] == "PASS", f"Test {t['id']} ({t['name']}) failed: {t['details']}"
