"""
Aegis Sovereign AI Runtime - Security API Route
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from aegis.api.demo import require_demo_mode
from aegis.security import lockdown
from aegis.security.auth import principal
from aegis.security.firewall import ContextFirewall, get_recent_security_events
from aegis.security.self_test import run_security_self_test

router = APIRouter(prefix="/api/security", tags=["Security"])
firewall = ContextFirewall()


@router.get("/audit-commitments")
def audit_commitments(identity=Depends(principal)):
    from aegis.security.audit_export import snapshot

    return snapshot(identity)


class LockdownRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    enabled: bool


@router.get("/lockdown")
def lockdown_status(identity=Depends(principal)):
    return lockdown.status()


@router.post("/lockdown")
def change_lockdown(req: LockdownRequest, identity=Depends(principal)):
    return lockdown.change(req.enabled, identity)


@router.get("/quotas")
def quotas(identity=Depends(principal)):
    from aegis.control import policy
    from aegis.control.maintenance import quotas

    policy.actor(identity)
    return {"quotas": quotas()}


@router.post("/maintenance")
def maintenance(identity=Depends(principal)):
    from aegis.control import policy
    from aegis.control.maintenance import archive_expired

    policy.actor(identity, ["Security Officer", "Key Custodian"])
    return archive_expired(identity, force=True)


class ScanTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(max_length=65536)
    source_identifier: str = Field(
        default="interactive_scanner", max_length=120, pattern=r"^[A-Za-z0-9_.-]+$"
    )


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
