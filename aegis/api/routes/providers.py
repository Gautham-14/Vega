"""Authenticated inventory and immutable local model-provider profiles."""

from fastapi import APIRouter, Depends, Query

from aegis.advisory import qualification as advisory_qualification
from aegis.coding import providers
from aegis.control import policy
from aegis.security import media_qualification, provider_assurance
from aegis.security.auth import principal
from aegis.security.model_qualification import QualificationSuite, run_candidate_suite

router = APIRouter(prefix="/api/providers", tags=["Local model providers"])


@router.post("/{provider_id}/attest-supervised")
def supervised_attestation(provider_id: str, identity=Depends(principal)):
    return provider_assurance.import_supervised_attestation(provider_id, identity)


@router.post("/{provider_id}/refresh-supervised")
def supervised_refresh(provider_id: str, identity=Depends(principal)):
    return provider_assurance.refresh_supervised_attestation(provider_id, identity)


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


@router.get("/{provider_id}/preflight")
def preflight(provider_id: str, identity=Depends(principal)):
    return providers.preflight(provider_id, identity)


@router.post("/{provider_id}/qualify")
def qualify_candidate(provider_id: str, req: QualificationSuite, identity=Depends(principal)):
    return run_candidate_suite(provider_id, req.model_dump(), identity)


@router.post("/{provider_id}/qualify-media")
def qualify_media(
    provider_id: str, req: media_qualification.MediaSuite, identity=Depends(principal)
):
    return media_qualification.run(provider_id, req, identity)


@router.post("/{provider_id}/qualify-advisory")
def qualify_advisory(
    provider_id: str, req: advisory_qualification.Suite, identity=Depends(principal)
):
    return advisory_qualification.run(provider_id, req, identity)


@router.get("/{provider_id}/assurance")
def assurance(provider_id: str, identity=Depends(principal)):
    return provider_assurance.status(provider_id, identity)


@router.post("/{provider_id}/attestations", status_code=201)
def import_runtime_attestation(
    provider_id: str, req: provider_assurance.AttestationImportRequest, identity=Depends(principal)
):
    return provider_assurance.import_attestation(provider_id, req, identity)


@router.post("/{provider_id}/release")
def activate_release(
    provider_id: str, req: provider_assurance.ReleaseActivationRequest, identity=Depends(principal)
):
    return provider_assurance.activate(provider_id, req.approval_id, identity)


@router.get("/{provider_id}/release-candidates/{candidate_id}")
def review_release_candidate(provider_id: str, candidate_id: str, identity=Depends(principal)):
    return provider_assurance.review_candidate(provider_id, candidate_id, identity)


@router.post("/{provider_id}/release/revoke")
def revoke_release(provider_id: str, identity=Depends(principal)):
    return provider_assurance.revoke(provider_id, identity)


@router.get("/{provider_id}/measurement")
def measure_runtime(provider_id: str, pid: int = Query(gt=0), identity=Depends(principal)):
    return provider_assurance.measurement(provider_id, pid, identity)


@router.post("/{provider_id}/release/refresh")
def refresh_release(
    provider_id: str, req: provider_assurance.AttestationImportRequest, identity=Depends(principal)
):
    return provider_assurance.refresh(provider_id, req, identity)
