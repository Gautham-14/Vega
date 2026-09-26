"""
Aegis Sovereign AI Runtime - Security API Route
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Dict, Any, List
from pydantic import BaseModel, ConfigDict
from aegis.security import lockdown
from aegis.security.auth import principal
from aegis.security.firewall import ContextFirewall, get_recent_security_events
from aegis.security.self_test import run_security_self_test
from aegis.api.demo import require_demo_mode

router = APIRouter(prefix="/api/security", tags=["Security"])
firewall = ContextFirewall()


class LockdownRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: bool


@router.get("/lockdown")
def lockdown_status(identity=Depends(principal)):
    return lockdown.status()


@router.post("/lockdown")
def change_lockdown(req: LockdownRequest, identity=Depends(principal)):
    return lockdown.change(req.enabled, identity)

class ScanTextRequest(BaseModel):
    text: str
    source_identifier: str = "interactive_scanner"

@router.post("/scan")
def scan_text(req: ScanTextRequest) -> Dict[str, Any]:
    return firewall.scan_text(req.text, source_identifier=req.source_identifier)

@router.get("/events")
def list_events(limit: int = Query(default=50, ge=1, le=500)) -> List[Dict[str, Any]]:
    return get_recent_security_events(limit=limit)

@router.post("/self-test")
def execute_self_test() -> Dict[str, Any]:
    require_demo_mode()
    return run_security_self_test()
