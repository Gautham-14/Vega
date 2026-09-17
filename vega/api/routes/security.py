"""
Vega Sovereign AI Runtime - Security API Route
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List
from pydantic import BaseModel
from vega.security.firewall import ContextFirewall, get_recent_security_events
from vega.security.self_test import run_security_self_test
from vega.api.demo import require_demo_mode

router = APIRouter(prefix="/api/security", tags=["Security"])
firewall = ContextFirewall()

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
