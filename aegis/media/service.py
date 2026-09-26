"""Purpose-bound, reviewed image operations with encrypted and revocable retention."""
import hashlib
import hmac
import importlib.metadata
import json
from pathlib import Path
import threading
import time
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field, model_validator
from aegis.coding import providers, tools
from aegis.control import capsules, policy, store
from aegis.control.runtime import POLICY_STATE
from aegis.media import images, inference
from aegis.security import lockdown

BUSY = threading.Lock()
PATHS = [Path(__file__), Path(images.__file__), Path(inference.__file__), Path(providers.__file__),
         Path(tools.__file__), Path(policy.__file__), Path(capsules.__file__), Path(store.__file__), Path(lockdown.__file__)]
LOADED = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in PATHS}


class MediaRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    capsule_id: str = Field(min_length=1, max_length=100)
    operation: Literal["understand", "generate", "edit"]
    prompt: str = Field(min_length=1, max_length=8000)
    images: list[str] = Field(default_factory=list, max_length=4)
    negative_prompt: str = Field(default="", max_length=2000)
    compartment: Literal["Engineering", "Maintenance", "Finance", "HR", "Public"] = "Engineering"
    classification: Literal["PUBLIC", "INTERNAL"] = "INTERNAL"
    width: int = Field(default=512, ge=64, le=1024, multiple_of=64)
    height: int = Field(default=512, ge=64, le=1024, multiple_of=64)
    steps: int = Field(default=20, ge=1, le=50)
    seed: int = Field(default=0, ge=0, le=2**32 - 1)
    strength: float = Field(default=0.6, ge=0.0, le=1.0, allow_inf_nan=False)
    minutes: int = Field(default=15, ge=1, le=15)

    @model_validator(mode="after")
    def image_count(self):
        if (self.operation == "understand" and not self.images
                or self.operation == "generate" and self.images
                or self.operation == "edit" and len(self.images) != 1):
            raise ValueError("Understand requires 1-4 images, generate none, and edit exactly one")
        if any(not 1 <= len(image) <= images.MAX_BASE64 for image in self.images):
            raise ValueError("Each input image must fit the 2 MB limit")
        if not self.prompt.strip():
            raise ValueError("Prompt must not be blank")
        return self


def capabilities():
    try:
        pillow = importlib.metadata.version("Pillow")
    except importlib.metadata.PackageNotFoundError:
        pillow = None
    return {"operations": ["understand", "generate", "edit"], "image_decoder": pillow,
            "generation_backend": "LOCAL_AUTOMATIC1111_API", "automatic_downloads": False,
            "image_embeddings": "NOT_IMPLEMENTED", "image_generation_quality": "REQUIRES_LIVE_MODEL_VALIDATION",
            "vision_tokenizer": "NATIVE_INFERENCE_SERVER_PROCESSOR", "vision_token_count": "NOT_MEASURED",
            "limits": {"images": 4, "image_bytes": images.MAX_IMAGE_BYTES, "pixels": images.MAX_PIXELS,
                       "output_images": 1, "output_side": 1024, "retention_minutes": 15},
            "scope": "Image content is untrusted. Pixel-level secret detection and OS/server egress isolation are not verified."}


def components(spec):
    measured = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in PATHS}
    if measured != LOADED:
        raise store.Denied("RUNTIME_RESTART_REQUIRED", "Media implementation changed; restart before approving or running")
    return {"model": spec, "tokenizer": "NATIVE_SERVER_PROCESSOR_CUSTODIAN_ASSERTED",
            "quantization": "PINNED_SERVER_MODEL_CUSTODIAN_ASSERTED", "adapter": spec["provider"],
            "system_prompt_hash": store.digest(inference.VISION_SYSTEM),
            "runtime": {"implementation": measured, "capabilities": capabilities()},
            "skill_policy": {"id": "media-v1", "operations": ["understand", "generate", "edit"],
                             "tools": [], "approval": "media-run", "export_approval": "export"},
            "retrieval": "NO_IMAGE_INDEX_OR_CROSS_TASK_MEMORY", "security_policy_version": policy.POLICY_VERSION}


def register_capsule(provider, identity):
    policy.actor(identity, ["Operator"])
    spec = providers.specification(provider)
    if spec.get("protocol") != "sd-webui" and spec.get("vision") is not True:
        raise ValueError("Media needs an explicitly configured vision or diffusion provider")
    value = capsules.register(components(spec), identity)
    return {"capsule": value, "approval": policy.request_approval("capsule", {"capsule_id": value["id"]}, identity)}


def attest(capsule_id):
    capsule = store.require("capsule", capsule_id)
    spec = capsule["components"]["model"]
    if spec != providers.specification(spec["provider"]):
        raise store.Denied("CAPSULE_MISMATCH", "Media provider configuration changed")
    measured = components(spec)
    capsules.attest(capsule_id, measured, POLICY_STATE)
    return spec


def public(job):
    return {k: v for k, v in job.items() if k not in {"ciphertext", "wrapped_key", "seal"}}


def save(job):
    value = {k: v for k, v in job.items() if k != "seal"}
    value["seal"] = store.sign(value, "media-job")
    return store.put("media-job", job["id"], value)


def read(job_id):
    job = store.require("media-job", job_id)
    body = {k: v for k, v in job.items() if k != "seal"}
    if not isinstance(job.get("seal"), str) or not hmac.compare_digest(job["seal"], store.sign(body, "media-job")):
        raise store.Denied("MEDIA_INTEGRITY_FAILURE", "Media task was modified")
    return job


def retain(job, payload):
    key = Fernet.generate_key()
    job["wrapped_key"] = Fernet(store.encryption_key("media-retention")).encrypt(key).decode()
    job["ciphertext"] = Fernet(key).encrypt(store.canonical(payload).encode()).decode()
    return save(job)


def payload(job):
    key = Fernet(store.encryption_key("media-retention")).decrypt(job["wrapped_key"].encode())
    value = json.loads(Fernet(key).decrypt(job["ciphertext"].encode()))
    if store.digest(value["request"]) != job["request_hash"]:
        raise store.Denied("MEDIA_INTEGRITY_FAILURE", "Media request content changed")
    if "result" in value and store.digest(value["result"]) != job["result_hash"]:
        raise store.Denied("MEDIA_INTEGRITY_FAILURE", "Media result content changed")
    return value


def destroy(job, status):
    job.pop("ciphertext", None)
    job.pop("wrapped_key", None)
    job["status"] = status
    save(job)
    store.receipt("MEDIA_CLEANUP", job["user"], task_id=job["id"], status=status, physical_zeroization="NOT_CLAIMED")


def live(job):
    lockdown.check(job.get("lockdown_generation", 0))
    if job["expires_at"] <= time.time():
        if job.get("ciphertext"):
            destroy(job, "EXPIRED")
        raise store.Denied("EXPIRED_MEDIA_TASK", "Media approval and retention have expired")
    if job["status"] in {"REVOKED", "FAILED", "EXPIRED"} or not job.get("ciphertext"):
        raise store.Denied("CLOSED_MEDIA_TASK", "Media task content is no longer available")
    if not store.verify_chain()["is_valid"]:
        raise store.Denied("RECEIPT_CHAIN_FAILURE", "Media content is withheld while the audit chain is invalid")
    spec = attest(job["capsule_id"])
    providers.require_sensitive_boundary(spec, job["label"]["classification"])
    return spec


def authorize(job, identity, *, owner=False):
    actor = policy.actor(identity)
    if job["user"] != identity and (owner or actor["role"] not in {"Data Owner", "Security Officer"}):
        raise store.Denied("UNAUTHORIZED_DATA_REQUEST", "This media task belongs to another account")
    policy.authorize_label(identity, job["label"])


def prepare(request, identity):
    request = MediaRequest.model_validate(request).model_dump()
    policy.actor(identity, ["Operator"])
    generation = lockdown.check()
    spec = attest(request["capsule_id"])
    providers.require_sensitive_boundary(spec, request["classification"])
    inference.require_capability(spec, request["operation"])
    label = {"compartments": [request["compartment"]], "classification": request["classification"], "kind": "media"}
    policy.authorize_label(identity, label)
    tools.inspect_text(request["prompt"] + "\n" + request["negative_prompt"], label["compartments"])
    # Only the sanitized bytes and their hash are approved and sent to the model.
    request["images"] = [images.sanitize(image) for image in request["images"]]
    if capabilities()["image_decoder"] is None:
        raise ValueError("Install requirements-media.txt before preparing image operations")
    now = time.time()
    job = {"id": store.uid("MEDIA"), "user": identity, "capsule_id": request["capsule_id"], "provider": spec["provider"],
           "operation": request["operation"], "label": label, "request_hash": store.digest(request),
           "input_images": [images.metadata(image) for image in request["images"]],
           "status": "AWAITING_APPROVAL", "created_at": now, "expires_at": now + request["minutes"] * 60,
           "local_model_calls": 0, "external_model_calls": 0, "lockdown_generation": generation}
    with store.LOCK:
        sweep()
        active = [record for record in store.all_objects("media-job") if record.get("ciphertext")]
        if len(active) >= 16 or sum(record["user"] == identity for record in active) >= 4:
            raise store.Denied("MEDIA_QUOTA_EXCEEDED", "Close existing media tasks before preparing another")
        approval = policy.request_approval("media-run", {"task_id": job["id"], "request_hash": job["request_hash"]}, identity)
        job["approval_id"] = approval["id"]
        store.receipt("MEDIA_PREPARED", identity, task_id=job["id"], **{k: v for k, v in public(job).items() if k != "id"})
        retain(job, {"request": request})
    return {"task": public(job), "approval": approval}


def view(job_id, identity):
    with store.LOCK:
        job = read(job_id)
        authorize(job, identity)
        live(job)
        return {**public(job), **payload(job)}


def run(job_id, identity):
    with store.LOCK:
        job = read(job_id)
        authorize(job, identity, owner=True)
        spec = live(job)
        if job["status"] != "AWAITING_APPROVAL":
            raise store.Denied("MEDIA_ALREADY_RUN", "Create a new reviewed task to run again")
        binding = {"task_id": job_id, "request_hash": job["request_hash"]}
        if not policy.approved(job["approval_id"], "media-run", binding):
            raise store.Denied("APPROVAL_REQUIRED", "Data Owner and Security Officer must approve this exact media request")
        if not BUSY.acquire(blocking=False):
            raise store.Denied("MEDIA_BUSY", "One media operation may run at a time")
        job["status"] = "RUNNING"
        try:
            value = payload(job)
            save(job)
        except Exception:
            BUSY.release()
            raise
    def reauthorize():
        with store.LOCK:
            current = read(job_id)
            live(current)
            if current["status"] != "RUNNING" or not policy.approved(current["approval_id"], "media-run", binding):
                raise store.Denied("APPROVAL_REQUIRED", "Media authorization changed before the model call")
    try:
        request = value["request"]
        result = (inference.understand(spec, request, before_send=reauthorize) if job["operation"] == "understand"
                  else inference.diffuse(spec, request, before_send=reauthorize))
        tools.inspect_text(result["answer"], job["label"]["compartments"])
        with store.LOCK:
            job = read(job_id)
            live(job)  # revocation, expiry and implementation drift during inference
            if not policy.approved(job["approval_id"], "media-run", binding):
                raise store.Denied("APPROVAL_REQUIRED", "Media approval expired during inference")
            job.update(status="COMPLETED", local_model_calls=1, result_hash=store.digest(result))
            store.receipt("MEDIA_COMPLETED", identity, task_id=job_id, result_hash=job["result_hash"],
                          image_count=len(result["images"]), server_retention="NOT_VERIFIED")
            retain(job, {**value, "result": result})
        return view(job_id, identity)
    except Exception as error:
        with store.LOCK:
            job = read(job_id)
            if job["status"] == "RUNNING":
                job["reason"] = error.code if isinstance(error, store.Denied) else "MEDIA_INFERENCE_FAILED"
                destroy(job, "FAILED")
        if isinstance(error, store.Denied):
            raise
        raise store.Denied("MEDIA_INFERENCE_FAILED", "Local media inference failed; no output was released") from None
    finally:
        value.clear()
        BUSY.release()


def revoke(job_id, identity):
    with store.LOCK:
        job = read(job_id)
        authorize(job, identity)
        if identity != job["user"]:
            policy.actor(identity, ["Data Owner"])
        destroy(job, "REVOKED")
        return public(job)


def export_binding(job):
    return {"media_task_id": job["id"], "result_hash": job["result_hash"], "label": job["label"], "recipient": job["user"]}


def request_export(job_id, identity):
    with store.LOCK:
        job = read(job_id)
        authorize(job, identity, owner=True)
        live(job)
        if job["status"] != "COMPLETED":
            raise ValueError("Only a completed result can be reviewed for export")
        return policy.request_approval("export", export_binding(job), identity)


def export(job_id, approval_id, identity):
    with store.LOCK:
        job = read(job_id)
        authorize(job, identity, owner=True)
        live(job)
        if job["status"] != "COMPLETED" or not policy.approved(approval_id, "export", export_binding(job)):
            raise store.Denied("APPROVAL_REQUIRED", "Export requires review of the exact completed result")
        result = payload(job)["result"]
        store.receipt("MEDIA_EXPORTED", identity, task_id=job_id, result_hash=job["result_hash"], approval_id=approval_id)
        return {"task_id": job_id, "result_hash": job["result_hash"], "result": result}


def sweep():
    with store.LOCK:
        for record in store.all_objects("media-job"):
            if record.get("ciphertext") and record["expires_at"] <= time.time():
                destroy(read(record["id"]), "EXPIRED")
