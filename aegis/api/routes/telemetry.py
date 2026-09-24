"""Authenticated, read-only host measurements and redacted operation metadata."""
import time

from fastapi import APIRouter, Depends, HTTPException, Query

from aegis import telemetry
from aegis.coding import service
from aegis.control import policy, store
from aegis.security.auth import principal

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry dashboard"])
AUDIT_ROLES = {"Auditor", "Security Officer"}


@router.get("/latest")
def latest(identity=Depends(principal)):
    samples = telemetry.history(1)
    value = samples[-1] if samples else telemetry.sample()
    return {**value, "stale": time.time() - value["timestamp"] > 15}


@router.get("/history")
def history(limit: int = Query(default=120, ge=1, le=1200), identity=Depends(principal)):
    return telemetry.history(limit)


@router.get("/events")
def events(limit: int = Query(default=100, ge=1, le=500), identity=Depends(principal)):
    if policy.actor(identity)["role"] not in AUDIT_ROLES:
        raise HTTPException(403, "System request metadata requires an Auditor or Security Officer account")
    return telemetry.events(limit)


def pick(value, fields):
    return {key: value[key] for key in fields if key in value}


@router.get("/workspace")
def workspace(identity=Depends(principal)):
    person = policy.actor(identity)
    audit = person["role"] in AUDIT_ROLES
    state = service.state(identity)
    # service.state applies ownership and compartment rules; allowlist again so
    # future service payload additions cannot enter the telemetry channel.
    tasks = []
    for task in state["tasks"]:
        if task.get("user") != identity:
            continue
        label = task.get("label")
        if label and (not set(label["compartments"]).issubset(person["compartments"])
                      or policy.LEVELS[label["classification"]] > policy.LEVELS[person["clearance"]]):
            continue
        summary = pick(task, ("id", "status", "mode", "provider", "created_at", "expires_at", "tests"))
        summary["decisions"] = {decision: sum(step.get("decision") == decision for step in task.get("trace", []))
                                for decision in ("ALLOW", "DENY")}
        tasks.append(summary)
    tasks.sort(key=lambda value: value.get("created_at", 0), reverse=True)
    approvals = [pick(value, ("id", "action", "status", "created_at", "expires_at")) |
                 {"decisions_received": len(value.get("decisions", [])),
                  "decisions_required": len(value.get("required_roles", []))}
                 for value in store.all_objects("approval") if audit or value.get("requester") == identity]
    approvals.sort(key=lambda value: value.get("created_at", 0), reverse=True)
    receipts = [pick(value, ("id", "action", "timestamp"))
                for value in store.receipts() if audit or value.get("actor") == identity]
    # A global receipt count is system metadata. Normal users see only their own
    # receipt count, and verifying the chain must not mutate the security ledger.
    chain = store.verify_chain(record_failure=False)
    return {"scope": "OWN_TASKS_AND_SYSTEM_AUDIT" if audit else "OWN_RECORDS",
            "tasks": tasks[:100], "approvals": approvals[:100], "receipts": receipts[:100],
            "counts": {"tasks": len(tasks), "approvals_pending": sum(a["status"] == "PENDING" and a.get("expires_at", 0) > time.time() for a in approvals),
                       "receipts": len(receipts)},
            "chain": {"is_valid": chain["is_valid"], "scope": chain["scope"]},
            "system_events_allowed": audit, "timestamp": time.time()}
