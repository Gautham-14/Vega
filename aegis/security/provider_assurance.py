"""Short-lived provider releases bound to independent Ed25519 evidence.

The host administrator provisions AEGIS_PROVIDER_TRUST_POLICY separately. Local
measurements check executable/process identity and the listening endpoint; the
independent attestor remains responsible for loaded weights and OS isolation.
Neither a provider profile nor a successful candidate test grants a release.
"""

import base64
import hashlib
import ipaddress
import os
import time
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import psutil
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.coding import providers
from aegis.control import policy, store
from aegis.security import bundle_custody, lockdown, model_qualification, offline_bundle
from aegis.security.private_files import no_links

HEX = r"^[a-f0-9]{64}$"
SCOPE = "Local process checks plus independently signed assertions; no hardware attestation"


class ProcessIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    pid: int = Field(gt=0)
    created_at: float = Field(gt=0, allow_inf_nan=False)
    executable_sha256: str = Field(pattern=HEX)


class RuntimeAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["aegis-provider-attestation-v1"]
    signer_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,120}$")
    provider_id: str = Field(pattern=r"^PROVIDER-[a-f0-9]{32}$")
    provider_configuration_sha256: str = Field(pattern=HEX)
    bundle_record_id: str = Field(pattern=r"^BUNDLE-[a-f0-9]{32}$")
    manifest_sha256: str = Field(pattern=HEX)
    weights_inventory_sha256: str = Field(pattern=HEX)
    qualification_id: str = Field(pattern=r"^QUAL-[a-f0-9]{32}$")
    qualification_sha256: str = Field(pattern=HEX)
    process: ProcessIdentity
    loaded_weights_verified: Literal[True]
    network_isolation_verified: Literal[True]
    server_retention_disabled: Literal[True]
    issued_at: float = Field(gt=0, allow_inf_nan=False)
    expires_at: float = Field(gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def short_lifetime(self):
        if not self.issued_at < self.expires_at <= self.issued_at + 900:
            raise ValueError("Attestations have a maximum fifteen-minute lifetime")
        return self


class AttestationImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    attestation: RuntimeAttestation
    signature: str = Field(min_length=1, max_length=128)


class ReleaseActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    approval_id: str = Field(pattern=r"^APR-[a-f0-9]{32}$")


class AttestorPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["aegis-provider-trust-v1"]
    signers: dict[str, offline_bundle.TrustedSigner] = Field(min_length=1, max_length=32)
    expires_at: float = Field(gt=0, allow_inf_nan=False)
    revoked_attestation_sha256: list[str] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def digests(self):
        import re

        if any(not re.fullmatch(HEX, value) for value in self.revoked_attestation_sha256):
            raise ValueError("Invalid revoked attestation digest")
        return self


def _save(kind, value):
    body = {key: item for key, item in value.items() if key != "seal"}
    return store.put(kind, body["id"], {**body, "seal": store.sign(body, kind + "-v1")})


def _read(kind, identity):
    value = store.require(kind, identity)
    body = {key: item for key, item in value.items() if key != "seal"}
    if (
        body.get("id") != identity
        or not isinstance(value.get("seal"), str)
        or not store.verify_signature(body, kind + "-v1", value["seal"])
    ):
        raise store.Denied(
            "MODEL_ASSURANCE_INTEGRITY_FAILURE", "Provider evidence changed", identity
        )
    return body


def _measure(spec, pid):
    if os.environ.get("AEGIS_ATTESTOR_SOCKET"):
        from aegis.security.attestor import remote

        try:
            observed = remote("measure", spec)
            measured = ProcessIdentity.model_validate(observed["process"]).model_dump()
            if measured["pid"] != pid or any(
                observed.get(name) is not True
                for name in (
                    "network_isolation_verified",
                    "loaded_weights_verified",
                    "server_retention_disabled",
                )
            ):
                raise ValueError("Independent process/isolation measurement differs")
            return measured
        except (OSError, ValueError, RuntimeError, KeyError):
            raise store.Denied(
                "PROVIDER_RUNTIME_UNVERIFIED", "Independent supervisor measurement failed"
            ) from None
    from aegis.security.deployment import production

    if production():
        raise store.Denied(
            "PROVIDER_RUNTIME_UNVERIFIED", "Production requires the independent process supervisor"
        )
    try:
        process = psutil.Process(pid)
        created = process.create_time()
        executable = no_links(process.exe())
        size = offline_bundle._regular_file(executable).st_size
        if not 0 < size <= 512 * 1024 * 1024:
            raise ValueError("Runtime executable is too large")
        digest = offline_bundle._sha256_file(executable, size)
        endpoint = urlsplit(spec["endpoint"])
        port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
        listeners = [
            item.laddr
            for item in process.net_connections(kind="inet")
            if item.status == psutil.CONN_LISTEN
        ]
        if (
            not listeners
            or any(not ipaddress.ip_address(item.ip).is_loopback for item in listeners)
            or not any(
                ipaddress.ip_address(item.ip) == ipaddress.ip_address(endpoint.hostname)
                and item.port == port
                for item in listeners
            )
        ):
            raise ValueError("Runtime does not own the configured loopback listener")
        if not process.is_running() or psutil.Process(pid).create_time() != created:
            raise ValueError("Runtime process changed during measurement")
        return {"pid": pid, "created_at": float(created), "executable_sha256": digest}
    except (OSError, ValueError, psutil.Error):
        raise store.Denied(
            "PROVIDER_RUNTIME_UNVERIFIED",
            "Cannot verify the local executable, process and listener",
        ) from None


def measurement(provider_id, pid, identity):
    policy.actor(identity, ["Security Officer", "Model Custodian"])
    spec = providers.specification(provider_id)
    if provider_id in {"reference", "ollama"}:
        raise ValueError("Register an immutable live provider profile first")
    return {
        "process": _measure(spec, pid),
        "provider_configuration_sha256": providers.configuration_hash(spec),
        "network_isolation_verified": False,
        "loaded_weights_verified": False,
        "scope": SCOPE,
    }


def _validate(spec, request):
    evidence = request.attestation
    now = time.time()
    if evidence.issued_at > now + 30 or evidence.expires_at <= now:
        raise store.Denied(
            "MODEL_ASSURANCE_EXPIRED", "Runtime attestation is expired or not yet valid"
        )
    if (
        evidence.provider_id != spec["provider"]
        or evidence.provider_configuration_sha256 != providers.configuration_hash(spec)
        or evidence.bundle_record_id != spec.get("bundle_record_id")
    ):
        raise store.Denied(
            "MODEL_ASSURANCE_MISMATCH", "Evidence does not match the provider profile"
        )
    custody = bundle_custody.revalidate(evidence.bundle_record_id)
    bundle = custody["verification"]
    if (
        evidence.manifest_sha256 != bundle["manifest_sha256"]
        or evidence.weights_inventory_sha256 != bundle["weights_inventory_sha256"]
        or evidence.process.executable_sha256 != bundle["runtime_sha256"]
    ):
        raise store.Denied(
            "MODEL_ASSURANCE_MISMATCH", "Evidence does not match the verified offline bundle"
        )
    qualified = model_qualification.qualification(evidence.qualification_id)
    if (
        qualified["provider"] != spec["provider"]
        or qualified["passed"] != qualified["case_count"]
        or qualified["case_count"] < 1
        or qualified["provider_configuration_sha256"] != providers.configuration_hash(spec)
        or evidence.qualification_sha256 != model_qualification.qualification_hash(qualified)
    ):
        raise store.Denied(
            "MODEL_QUALIFICATION_REQUIRED", "Evidence requires passing bound candidate cases"
        )
    policy_path = os.environ.get("AEGIS_PROVIDER_TRUST_POLICY", "")
    if not policy_path:
        raise store.Denied(
            "MODEL_ASSURANCE_REQUIRED",
            "Host administrator must provision an independent attestor trust policy",
        )
    trust_path = no_links(policy_path)
    trust_json, trust_bytes = offline_bundle._read_json(trust_path, offline_bundle.MAX_POLICY_BYTES)
    trust = AttestorPolicy.model_validate(trust_json)
    raw = offline_bundle.canonical_bytes(evidence.model_dump())
    if (
        trust.expires_at <= now
        or hashlib.sha256(raw).hexdigest() in trust.revoked_attestation_sha256
    ):
        raise store.Denied(
            "MODEL_ASSURANCE_REVOKED", "Attestor trust is expired or evidence is revoked"
        )
    signer = trust.signers.get(evidence.signer_id)
    if signer is None:
        raise store.Denied("MODEL_ASSURANCE_UNTRUSTED", "Attestation signer is not trusted")
    key_path = no_links(signer.public_key_path)
    root = no_links(custody["directory"])
    if (
        not Path(signer.public_key_path).is_absolute()
        or trust_path.is_relative_to(root)
        or key_path.is_relative_to(root)
    ):
        raise ValueError(
            "Attestor trust policy and public key must be provisioned outside the bundle"
        )
    if offline_bundle._regular_file(key_path).st_size > 16384:
        raise ValueError("Attestor public key exceeds the size limit")
    with key_path.open("rb") as stream:
        key_bytes = stream.read(16385)
    if len(key_bytes) > 16384:
        raise ValueError("Attestor public key exceeds the size limit")
    key = serialization.load_pem_public_key(key_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Attestor public key must use Ed25519")
    fingerprint = hashlib.sha256(
        key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    if fingerprint != signer.public_key_sha256 or fingerprint == bundle["signer_public_key_sha256"]:
        raise store.Denied(
            "MODEL_ASSURANCE_UNTRUSTED",
            "Attestor must have a pinned key independent of the bundle publisher",
        )
    try:
        key.verify(base64.b64decode(request.signature, validate=True), raw)
    except (ValueError, InvalidSignature):
        raise store.Denied(
            "MODEL_ASSURANCE_BAD_SIGNATURE", "Runtime attestation signature is invalid"
        ) from None
    if _measure(spec, evidence.process.pid) != evidence.process.model_dump():
        raise store.Denied(
            "PROVIDER_RUNTIME_CHANGED", "Serving process differs from the signed measurement"
        )
    if (
        offline_bundle._sha256_file(trust_path, len(trust_bytes))
        != hashlib.sha256(trust_bytes).hexdigest()
        or offline_bundle._sha256_file(key_path, len(key_bytes))
        != hashlib.sha256(key_bytes).hexdigest()
    ):
        raise store.Denied(
            "MODEL_ASSURANCE_UNTRUSTED", "Attestor trust root changed during verification"
        )
    return evidence.model_dump()


def _binding(value):
    return {key: item for key, item in value.items() if key not in {"issued_at", "expires_at"}}


def import_attestation(provider_id, request, identity):
    policy.actor(identity, ["Security Officer"])
    request = AttestationImportRequest.model_validate(request)
    with store.LOCK:
        generation = lockdown.check()
        spec = providers.specification(provider_id)
        evidence = _validate(spec, request)
        candidate = {
            "id": store.uid("RELEASE"),
            "provider": provider_id,
            "request": request.model_dump(),
            "created_at": time.time(),
            "lockdown_generation": generation,
            "status": "REVIEW_REQUIRED",
        }
        binding = {
            "candidate_id": candidate["id"],
            "evidence_sha256": store.digest(_binding(evidence)),
        }
        approval = policy.request_approval("provider-release", binding, identity)
        candidate.update(approval_id=approval["id"], binding=binding)
        store.receipt(
            "PROVIDER_ATTESTATION_IMPORTED",
            identity,
            provider_id=provider_id,
            candidate_id=candidate["id"],
        )
        _save("provider-release-candidate", candidate)
        return {"candidate": candidate, "approval": approval}


def import_supervised_attestation(provider_id, identity):
    policy.actor(identity, ["Security Officer"])
    from aegis.security.attestor import remote

    spec = providers.specification(provider_id)
    return import_attestation(provider_id, remote("attest", spec), identity)


def refresh_supervised_attestation(provider_id, identity):
    policy.actor(identity, ["Security Officer"])
    from aegis.security.attestor import remote

    spec = providers.specification(provider_id)
    return refresh(provider_id, remote("attest", spec), identity)


def review_candidate(provider_id, candidate_id, identity):
    policy.actor(identity, ["Model Custodian", "Data Owner", "Security Officer", "Auditor"])
    with store.LOCK:
        candidate = _read("provider-release-candidate", candidate_id)
        if candidate["provider"] != provider_id:
            raise store.Denied("MODEL_ASSURANCE_MISMATCH", "Candidate belongs to another provider")
        lockdown.check(candidate["lockdown_generation"])
        _validate(
            providers.specification(provider_id),
            AttestationImportRequest.model_validate(candidate["request"]),
        )
        return {**candidate, "scope": SCOPE}


def activate(provider_id, approval_id, identity):
    policy.actor(identity, ["Model Custodian"])
    with store.LOCK:
        candidates = [
            value
            for value in store.all_objects("provider-release-candidate")
            if value.get("provider") == provider_id and value.get("approval_id") == approval_id
        ]
        if len(candidates) != 1:
            raise store.Denied(
                "MODEL_ASSURANCE_REQUIRED", "Choose a bound release-candidate approval"
            )
        candidate = _read("provider-release-candidate", candidates[0]["id"])
        generation = lockdown.check(candidate["lockdown_generation"])
        evidence = _validate(
            providers.specification(provider_id),
            AttestationImportRequest.model_validate(candidate["request"]),
        )
        binding = {
            "candidate_id": candidate["id"],
            "evidence_sha256": store.digest(_binding(evidence)),
        }
        if not policy.approved(approval_id, "provider-release", binding):
            raise store.Denied(
                "APPROVAL_REQUIRED",
                "Model Custodian and Data Owner must approve this exact evidence",
            )
        approval = policy._read_approval(approval_id)
        if candidate["status"] != "REVIEW_REQUIRED":
            raise store.Denied("MODEL_ASSURANCE_REPLAY", "Release candidate was already activated")
        release = {
            "id": provider_id,
            "release_id": store.uid("RELEASE"),
            "provider": provider_id,
            "candidate_id": candidate["id"],
            "request": candidate["request"],
            "binding": binding,
            "approval_id": approval_id,
            "status": "ACTIVE",
            "activated_at": time.time(),
            "review_expires_at": approval["expires_at"],
            "lockdown_generation": generation,
        }
        store.receipt(
            "PROVIDER_RELEASE_ACTIVATED",
            identity,
            provider_id=provider_id,
            release_id=release["release_id"],
        )
        _save("provider-release", release)
        candidate["status"] = "ACTIVATED"
        _save("provider-release-candidate", candidate)
        return _public_release(release)


def _active(spec):
    value = store.get("provider-release", spec["provider"])
    if value is None:
        raise store.Denied(
            "MODEL_ASSURANCE_REQUIRED",
            "Internal data requires an independently approved live provider release",
        )
    release = _read("provider-release", spec["provider"])
    lockdown.check(release["lockdown_generation"])
    if release["status"] != "ACTIVE":
        raise store.Denied("MODEL_ASSURANCE_REVOKED", "Provider release is revoked")
    if release["review_expires_at"] <= time.time():
        raise store.Denied(
            "MODEL_ASSURANCE_EXPIRED", "Provider release review expired; obtain fresh approvals"
        )
    evidence = _validate(spec, AttestationImportRequest.model_validate(release["request"]))
    if release["binding"]["evidence_sha256"] != store.digest(_binding(evidence)):
        raise store.Denied("MODEL_ASSURANCE_MISMATCH", "Release differs from the reviewed evidence")
    if not policy.approved(release["approval_id"], "provider-release", release["binding"]):
        raise store.Denied("APPROVAL_REQUIRED", "Release approval is no longer valid")
    return release


def _public_release(value):
    return {
        "id": value["release_id"],
        "provider": value["provider"],
        "status": value["status"],
        "expires_at": min(
            value["review_expires_at"], value["request"]["attestation"]["expires_at"]
        ),
        "scope": SCOPE,
    }


def require_active_release(spec):
    with store.LOCK:
        try:
            return _public_release(_active(spec))
        except store.Denied:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise store.Denied(
                "MODEL_ASSURANCE_INVALID", "Provider trust evidence is unavailable or invalid"
            ) from None


def status(provider_id, identity):
    policy.actor(identity)
    spec = providers.specification(provider_id)
    try:
        release = require_active_release(spec)
        return {
            "provider": provider_id,
            "internal_data_allowed": True,
            "release": release,
            "scope": SCOPE,
        }
    except store.Denied as error:
        return {
            "provider": provider_id,
            "internal_data_allowed": False,
            "reason": error.code,
            "scope": SCOPE,
        }


def revoke(provider_id, identity):
    policy.actor(identity, ["Security Officer"])
    with store.LOCK:
        value = _read("provider-release", provider_id)
        store.receipt(
            "PROVIDER_RELEASE_REVOKED",
            identity,
            provider_id=provider_id,
            release_id=value["release_id"],
        )
        value["status"] = "REVOKED"
        _save("provider-release", value)
        return _public_release(value)


def refresh(provider_id, request, identity):
    policy.actor(identity, ["Security Officer"])
    request = AttestationImportRequest.model_validate(request)
    with store.LOCK:
        spec = providers.specification(provider_id)
        value = _active(spec)  # Expired/revoked releases cannot be revived by refresh.
        evidence = _validate(spec, request)
        if store.digest(_binding(evidence)) != value["binding"]["evidence_sha256"]:
            raise store.Denied(
                "MODEL_ASSURANCE_MISMATCH", "Changed evidence requires independent reapproval"
            )
        if evidence["expires_at"] <= value["request"]["attestation"]["expires_at"]:
            raise ValueError("Refresh must extend attestation freshness")
        store.receipt(
            "PROVIDER_RELEASE_REFRESHED",
            identity,
            provider_id=provider_id,
            release_id=value["release_id"],
        )
        value["request"] = request.model_dump()
        _save("provider-release", value)
        return _public_release(value)
