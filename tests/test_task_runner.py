"""
Tests for Vega End-to-End Task Runner and Main Demo Workflow
"""
import pytest
from vega.storage.database import init_db
from vega.models.registry import seed_model_registry
from vega.knowledge.demo_data import seed_knowledge_registry
from vega.runtime.task_runner import TaskRunner, get_all_tasks

@pytest.fixture(autouse=True)
def setup_task_env():
    init_db()
    seed_model_registry()
    seed_knowledge_registry()

def test_pump_inspection_demo_workflow():
    runner = TaskRunner()
    result = runner.run_pump_inspection_demo(include_poisoned_patch=True)

    assert result["status"] == "COMPLETED"
    assert result["model_id"] == "VEGA-DEMO-TEXT"
    assert result["execution_mode"] == "SIMULATION MODE"
    assert result["authoritative_sop"] == "Pump_SOP_Rev8.txt"
    assert result["superseded_documents_rejected_count"] >= 2
    assert result["malicious_context_blocked_count"] == 1

    summary = result["claims_summary"]
    assert summary["verified"] >= 2
    assert summary["calculated"] >= 1
    assert summary["inferred"] >= 1
    assert summary["conflicting"] >= 1
    assert summary["unsupported"] >= 1
    assert summary["blocked_from_output"] >= 2

    egress = result["zero_egress_metrics"]
    assert egress["external_dns_queries"] == 0
    assert egress["external_http_requests"] == 0
    assert egress["external_api_calls"] == 0
    assert egress["egress_bytes"] == 0

    assert "receipt" in result
    assert result["receipt"]["receipt_sha256"] is not None

    # Verify task was recorded in database with full artifact content
    tasks = get_all_tasks()
    assert len(tasks) > 0
    task_in_db = next(t for t in tasks if t["id"] == result["task_id"])
    assert task_in_db is not None
    assert task_in_db.get("artifact_content") is not None
    assert len(task_in_db["artifact_content"]) > 100
