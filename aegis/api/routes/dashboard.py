"""
Aegis Sovereign AI Runtime - Dashboard API Route
"""
from fastapi import APIRouter
from typing import Dict, Any
from aegis.models.registry import get_all_models
from aegis.knowledge.registry import get_all_documents
from aegis.hardware.scheduler import get_effective_hardware
from aegis.security.firewall import get_recent_security_events
from aegis.receipts.generator import get_all_receipts
from aegis.runtime.task_runner import get_all_tasks
from aegis.security.self_test import get_last_self_test_result

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/status")
def get_dashboard_status() -> Dict[str, Any]:
    """
    Returns high-level system status and live telemetry.
    Matches required industrial operations dashboard specifications.
    """
    models = get_all_models()
    registered_count = len(models)
    demo_qualified_count = sum(1 for m in models if m["status"] == "DEMO_QUALIFIED")
    quarantined_count = sum(1 for m in models if m["status"] == "QUARANTINED")

    hw = get_effective_hardware()
    gpu_status = hw.get("gpu", {}).get("status", "NOT REQUIRED")

    receipts = get_all_receipts()
    tasks = get_all_tasks()
    sec_events = get_recent_security_events(limit=5)

    last_self_test = get_last_self_test_result()
    security_tests_status = (
        f"{last_self_test['tests_passed']} / {last_self_test['tests_total']} "
        f"{'PASS' if last_self_test['all_passed'] else 'FAIL'}"
        if last_self_test else "NOT RUN"
    )

    return {
        "system_name": "AEGIS",
        "tagline": "Sovereign AI Runtime",
        "runtime_mode": "SIMULATION",
        "internet": "NOT VERIFIED",
        "gpu": gpu_status,
        "registered_models": registered_count,
        "registered_documents": len(get_all_documents()),
        "qualified_models": 0,
        "demo_qualified_models": demo_qualified_count,
        "quarantined_models": quarantined_count,
        "security_tests_status": security_tests_status,
        "external_calls": None,
        "network_egress_bytes": None,
        "network_measurement_scope": "NOT_MEASURED",
        "hardware_telemetry": {
            "profile_name": hw.get("active_profile_name", "Host Live Telemetry"),
            "cpu_cores": hw.get("cpu_logical_cores", 4),
            "cpu_usage_pct": hw.get("cpu_usage_percent", 0.0),
            "total_ram_mb": hw.get("total_ram_mb", 8192),
            "available_ram_mb": hw.get("available_ram_mb", 4096),
            "ram_usage_pct": hw.get("ram_usage_percent", 0.0),
            "is_simulated": hw.get("is_simulated_profile", False)
        },
        "recent_tasks_count": len(tasks),
        "recent_receipts_count": len(receipts),
        "recent_security_events_count": len(sec_events),
        "recent_security_events": sec_events
    }
