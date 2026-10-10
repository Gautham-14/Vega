import json
import sys
from pathlib import Path

# Ensure root path is imported
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aegis.hardware.simulation import set_active_hardware_profile_name
from aegis.knowledge.registry import add_document
from aegis.models.profiles import DEMO_MODEL_PROFILES
from aegis.runtime.task_runner import TaskRunner
from aegis.storage.database import execute_write, init_db


def main():
    print("=" * 60)
    print("Aegis Sovereign AI Runtime - End-to-End Pipeline Demo")
    print("=" * 60)
    print("[1/3] Initializing Sovereign Database & Node Profile...")
    init_db()
    set_active_hardware_profile_name("PROFILE_AI_NODE")

    # Seed Demo Knowledge
    print("[2/3] Seeding Knowledge Documents & Demo Models...")
    try:
        add_document(
            {
                "id": "DOC-003",
                "filename": "Pump_SOP_Rev8_NEW.pdf",
                "title": "Pump_SOP",
                "revision": "8",
                "status": "CURRENT_APPROVED",
                "equipment_id": "Pump P-204",
                "department": "Engineering",
                "classification": "INTERNAL",
                "effective_date": "2024-01-01",
                "content": "Permitted continuous vibration limit is 4.5 mm/s RMS.",
                "file_path": "/var/mock/Pump_SOP_Rev8.pdf",
                "is_quarantined": 0,
            }
        )
        add_document(
            {
                "id": "DOC-004",
                "filename": "Pump_SOP_Rev7_NEW.pdf",
                "title": "Pump_SOP",
                "revision": "7",
                "status": "SUPERSEDED",
                "equipment_id": "Pump P-204",
                "department": "Engineering",
                "classification": "INTERNAL",
                "effective_date": "2023-01-01",
                "content": "Superseded SOP.",
                "file_path": "/var/mock/Pump_SOP_Rev7.pdf",
                "is_quarantined": 0,
            }
        )
        add_document(
            {
                "id": "DOC-REPORT-P204-INSPECTION",
                "filename": "DOC-REPORT-P204-INSPECTION.txt",
                "title": "Inspection Report",
                "revision": "1",
                "status": "CURRENT_APPROVED",
                "equipment_id": "Pump P-204",
                "department": "Engineering",
                "classification": "INTERNAL",
                "effective_date": "2024-01-01",
                "content": "Drive End (DE) Bearing Horizontal Vibration: 3.12 mm/s RMS.",
                "file_path": "/var/mock/DOC-REPORT-P204-INSPECTION.txt",
                "is_quarantined": 0,
            }
        )
        add_document(
            {
                "id": "DOC-HR-001",
                "filename": "HR_Salary_Bands_2024.pdf",
                "title": "HR Salary Bands",
                "revision": "1",
                "status": "CURRENT_APPROVED",
                "equipment_id": "ALL",
                "department": "HR",
                "classification": "CONFIDENTIAL",
                "effective_date": "2024-01-01",
                "content": "Confidential HR data.",
                "file_path": "/var/mock/HR_Salary_Bands_2024.pdf",
                "is_quarantined": 0,
            }
        )
    except Exception as e:
        print(f"Document Seed Note: {e}")

    for m in DEMO_MODEL_PROFILES:
        capabilities = m["capabilities"]
        if m["id"] == "AEGIS-DEMO-CODE" and "coding" not in capabilities:
            capabilities.append("coding")
        try:
            execute_write(
                """
                INSERT INTO models (id, name, version, architecture, parameters, quantization, capabilities, license, sha256, status, memory_req_mb, cpu_cores_req, gpu_vram_req_mb, qualification_score, shadow_agreement_score, benchmark_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    m["id"],
                    m["name"],
                    m["version"],
                    m["architecture"],
                    m["parameters"],
                    m["quantization"],
                    json.dumps(capabilities),
                    m["license"],
                    m["sha256"],
                    m["status"],
                    m["memory_req_mb"],
                    m["cpu_cores_req"],
                    m["gpu_vram_req_mb"],
                    m.get("qualification_score"),
                    m.get("shadow_agreement_score"),
                    json.dumps(m.get("benchmark_summary")),
                ),
            )
        except Exception:
            pass

    print("[3/3] Executing 8-Step Sovereign Task Runner...")
    print("-" * 60)
    runner = TaskRunner()
    result = runner.run_pump_inspection_demo()
    for step in result["execution_log"]:
        print(f"[{step['phase']:<20}] ({step['status']:<7}) -> {step['message']}")

    print("-" * 60)
    print(f"Status:          {result.get('status', 'SUCCESS')}")
    print(f"Task ID:         {result.get('task_id', result.get('id'))}")
    print(f"Models Engaged:  {result.get('models_engaged')}")
    print(f"Claims Blocked:  {result.get('claims_summary', {}).get('blocked_from_output')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
