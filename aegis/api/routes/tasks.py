"""
Aegis Sovereign AI Runtime - Tasks API Route
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Literal
from pydantic import BaseModel
from aegis.runtime.task_runner import TaskRunner, get_all_tasks, get_task_by_id
from aegis.api.demo import require_demo_mode

router = APIRouter(prefix="/api/tasks", tags=["Tasks"])
runner = TaskRunner()

class DemoTaskRequest(BaseModel):
    include_poisoned_patch: bool = True
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "CRITICAL"] = "HIGH"
    department: Literal["Engineering"] = "Engineering"
    equipment_id: Literal["Pump P-204"] = "Pump P-204"
    operator_role: str = "Reliability_Engineer"
    user_clearance: Literal["INTERNAL", "RESTRICTED", "CONFIDENTIAL"] = "INTERNAL"

@router.get("")
def list_tasks() -> List[Dict[str, Any]]:
    return get_all_tasks()

@router.get("/{task_id}")
def get_task(task_id: str) -> Dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@router.post("/demo")
def run_demo_task(req: DemoTaskRequest) -> Dict[str, Any]:
    require_demo_mode()
    try:
        result = runner.run_pump_inspection_demo(
            include_poisoned_patch=req.include_poisoned_patch,
            risk_level=req.risk_level,
            department=req.department,
            equipment_id=req.equipment_id,
            operator_role=req.operator_role,
            user_clearance=req.user_clearance
        )
        return result
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
