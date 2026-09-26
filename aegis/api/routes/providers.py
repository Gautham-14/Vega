"""Authenticated inventory and immutable local model-provider profiles."""
from fastapi import APIRouter, Depends

from aegis.coding import providers
from aegis.control import policy
from aegis.security.auth import principal
from aegis.security.model_qualification import QualificationSuite, run_candidate_suite

router = APIRouter(prefix="/api/providers", tags=["Local model providers"])


@router.get("")
def catalog(identity=Depends(principal)):
    return providers.catalog(identity)


@router.post("", status_code=201)
def register(req: providers.ProviderRequest, identity=Depends(principal)):
    return providers.register(identity, **req.model_dump())


@router.get("/{provider_id}")
def profile(provider_id: str, identity=Depends(principal)):
    policy.actor(identity)
    return providers.profile(provider_id)


@router.post("/{provider_id}/probe")
def probe(provider_id: str, identity=Depends(principal)):
    return providers.probe(provider_id, identity)


@router.post("/{provider_id}/qualify")
def qualify_candidate(provider_id: str, req: QualificationSuite, identity=Depends(principal)):
    return run_candidate_suite(provider_id, req.model_dump(), identity)
