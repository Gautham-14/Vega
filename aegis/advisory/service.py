"""Live-server-ready advisory workflow; no weight loading or automatic probes.

All inference is deliberately explicit. Capsules bind implementation, provider,
retrieval and policy. Authorization is rechecked before and after each boundary.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import BaseModel, ConfigDict, Field

from aegis.advisory import inference
from aegis.coding import providers, retrieval, tools
from aegis.coding import service as coding
from aegis.control import capsules, data, policy, store
from aegis.control.runtime import POLICY_STATE
from aegis.security import lockdown, revocation

PATHS = [
    *coding.IMPLEMENTATION_PATHS,
    Path(__file__),
    Path(inference.__file__),
    Path(data.__file__),
    Path(__file__).parents[1] / "control" / "leases.py",
]
LOADED = {
    str(path.relative_to(Path(__file__).parents[1])): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in PATHS
}


class Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class SourceRequest(Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,100}$")
    title: str = Field(min_length=1, max_length=200)
    family: str = Field(min_length=1, max_length=100)
    revision: str = Field(min_length=1, max_length=30)
    status: Literal["DRAFT", "SUPERSEDED", "CURRENT_APPROVED"] = "DRAFT"
    owner: str = Field(min_length=1, max_length=100)
    authority: str = Field(min_length=1, max_length=100)
    equipment: str = Field(min_length=1, max_length=100)
    compartment: Literal["Engineering", "Maintenance", "Finance", "HR", "Public"]
    classification: Literal["PUBLIC", "INTERNAL"]
    effective_date: str
    permitted_skills: list[str] = Field(min_length=1, max_length=10)
    fields: dict[str, str] = Field(min_length=1, max_length=100)
    field_rules: dict[
        str, Literal["expose", "mask", "pseudonymize", "remove", "tool-only", "recipient-only"]
    ]


class LeaseRequest(Strict):
    capsule_id: str = Field(min_length=1, max_length=100)
    source_ids: list[str] = Field(min_length=1, max_length=64)
    equipment: str = Field(min_length=1, max_length=100)
    skill: str
    purpose: str
    user: str
    minutes: int = Field(default=15, ge=1, le=15)
    allow_export: bool = False
    recipient: str
    combined_approval_id: str | None = None


class RunRequest(Strict):
    lease_id: str = Field(min_length=1, max_length=100)
    prompt: str = Field(min_length=1, max_length=8000)
    purpose: str
    retrieval_query: str | None = Field(default=None, min_length=1, max_length=300, pattern=r"\S")


def public(record):
    return {
        key: value
        for key, value in record.items()
        if key not in {"seal", "ciphertext", "wrapped_key"}
    }


def save(kind, record):
    body = {key: value for key, value in record.items() if key != "seal"}
    value = {**body, "seal": store.sign(body, "advisory:" + kind)}
    return store.put("advisory-" + kind, record["id"], value)


def read(kind, identity):
    value = store.require("advisory-" + kind, identity)
    body = {key: item for key, item in value.items() if key != "seal"}
    if not isinstance(value.get("seal"), str) or not store.verify_signature(
        body, "advisory:" + kind, value["seal"]
    ):
        raise store.Denied("ADVISORY_INTEGRITY_FAILURE", "Advisory record changed")
    return value


def components(spec):
    measured = {
        str(path.relative_to(Path(__file__).parents[1])): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in PATHS
    }
    if measured != LOADED:
        raise store.Denied(
            "RUNTIME_RESTART_REQUIRED",
            "Advisory implementation changed; restart before approval or execution",
        )
    return {
        "model": spec,
        "tokenizer": "NATIVE_SERVER_TOKENIZER",
        "quantization": "PINNED_PROVIDER_BUNDLE",
        "system_prompt_hash": store.digest(inference.SYSTEM),
        "adapter": spec["provider"],
        "runtime": {
            "implementation": measured,
            "answer_schema": inference.Answer.model_json_schema(),
        },
        "skill_policy": {"skills": policy.SKILLS, "tools": [], "ot_access": "NO_WRITE_CONNECTOR"},
        "retrieval": retrieval.configuration(),
        "security_policy_version": policy.POLICY_VERSION,
    }


def register_capsule(provider, identity):
    policy.actor(identity, ["Operator"])
    spec = providers.specification(provider)
    if provider == "reference" or spec.get("protocol") == "sd-webui":
        raise store.Denied(
            "PROVIDER_CAPABILITY_MISMATCH",
            "Advisory requires an explicitly configured local text provider",
        )
    value = capsules.register(components(spec), identity)
    return {
        "capsule": value,
        "approval": policy.request_approval("capsule", {"capsule_id": value["id"]}, identity),
    }


def attest(capsule_id):
    capsule = store.require("capsule", capsule_id)
    spec = capsule["components"]["model"]
    if spec != providers.specification(spec["provider"]):
        raise store.Denied("CAPSULE_MISMATCH", "Advisory provider configuration changed")
    measured = components(spec)
    capsules.attest(capsule_id, measured, POLICY_STATE)
    return spec, measured


def add_source(request, identity):
    request = SourceRequest.model_validate(request).model_dump()
    policy.actor(identity, ["Data Owner"])
    lockdown.check()
    policy.authorize_label(
        identity,
        {"compartments": [request["compartment"]], "classification": request["classification"]},
    )
    if sum(len(v.encode()) for v in request["fields"].values()) > 128000 or any(
        not 1 <= len(k) <= 100 for k in request["fields"]
    ):
        raise ValueError("Source exceeds bounded field limits")
    with store.LOCK:
        return data.add_source(request, identity)


def source_binding(source):
    return {
        "id": source["id"],
        "revision": source["revision"],
        "content_hash": source["content_hash"],
        "metadata_hash": store.digest(data.public_source(source)),
    }


def checked_sources(source_ids, identity, skill, equipment):
    if len(set(source_ids)) != len(source_ids):
        raise ValueError("Select distinct source revisions")
    sources = []
    for source_id in source_ids:
        source = store.require("source", source_id)
        policy.authorize_label(identity, policy.label([source]))
        data.source_current(source, skill, equipment)
        sources.append(source)
    return sources


def combined_binding(request, sources):
    return {
        "workflow": "advisory",
        "capsule_id": request["capsule_id"],
        "user": request["user"],
        "source_bindings": [source_binding(source) for source in sources],
        "purpose": request["purpose"],
        "equipment": request["equipment"],
    }


def lease_review(request, identity):
    request = LeaseRequest.model_validate(request).model_dump()
    person = policy.actor(identity, ["Operator", "Data Owner"])
    if person["role"] == "Operator" and request["user"] != identity:
        raise store.Denied("PURPOSE_LEASE_MISMATCH", "Review only your own proposed advisory lease")
    sources = checked_sources(
        request["source_ids"], identity, request["skill"], request["equipment"]
    )
    return {
        "requires_combined_approval": len(policy.label(sources)["compartments"]) > 1,
        "action": "combined-analysis",
        "binding": combined_binding(request, sources),
    }


def issue_lease(request, identity):
    request = LeaseRequest.model_validate(request).model_dump()
    policy.actor(identity, ["Data Owner"])
    policy.actor(request["user"], ["Operator"])
    skill = policy.SKILLS.get(request["skill"])
    if not skill or request["purpose"] not in skill["purposes"]:
        raise store.Denied("PURPOSE_LEASE_MISMATCH", "Choose a purpose from the selected skill")
    with store.LOCK:
        generation = lockdown.check()
        sources = checked_sources(
            request["source_ids"], request["user"], request["skill"], request["equipment"]
        )
        label = policy.label(sources, "advisory")
        policy.authorize_label(identity, label)
        policy.authorize_label(request["recipient"], label)
        binding = combined_binding(request, sources)
        if len(label["compartments"]) > 1 and not policy.approved(
            request["combined_approval_id"], "combined-analysis", binding
        ):
            raise store.Denied(
                "APPROVAL_REQUIRED",
                "Combined advisory analysis requires independent Data Owner and Security Officer approval",
            )
        if (
            label["classification"] not in {"PUBLIC", "INTERNAL"}
            or label["classification"] not in skill["data_classes"]
            or not set(label["compartments"]).issubset(skill["compartments"])
        ):
            raise store.Denied(
                "SKILL_POLICY_VIOLATION",
                "Sources exceed the advisory skill or supported classification",
            )
        spec, _ = attest(request["capsule_id"])
        release = providers.require_sensitive_boundary(spec, label["classification"])
        now = time.time()
        lease = {
            "id": store.uid("ADVICE-LEASE"),
            **request,
            "issuer": identity,
            "label": label,
            "source_bindings": [source_binding(source) for source in sources],
            "issued_at": now,
            "expires_at": min(
                now + request["minutes"] * 60, release["expires_at"] if release else now + 900
            ),
            "provider_release_id": release["id"] if release else None,
            "lockdown_generation": generation,
            "tools": [],
            "ot_write": False,
            "training": False,
            "persistent_memory": False,
        }
        store.receipt(
            "ADVISORY_LEASE_ISSUED",
            identity,
            lease_id=lease["id"],
            user=lease["user"],
            capsule_id=lease["capsule_id"],
            source_bindings=lease["source_bindings"],
            purpose=lease["purpose"],
        )
        return public(save("lease", lease))


def validate_lease(lease_id, identity, purpose):
    lease = read("lease", lease_id)
    lockdown.check(lease["lockdown_generation"])
    policy.actor(identity, ["Operator"])
    if lease["user"] != identity or lease["purpose"] != purpose:
        raise store.Denied(
            "PURPOSE_LEASE_MISMATCH", "Advisory identity or purpose differs from the lease"
        )
    if lease["expires_at"] <= time.time():
        raise store.Denied("EXPIRED_PURPOSE_LEASE", "Advisory lease expired")
    if revocation.revoked("advisory-lease", lease_id):
        raise store.Denied("REVOKED_PURPOSE_LEASE", "Advisory lease was revoked")
    sources = checked_sources(lease["source_ids"], identity, lease["skill"], lease["equipment"])
    if [source_binding(source) for source in sources] != lease["source_bindings"]:
        raise store.Denied(
            "SOURCE_REVISION_CHANGED", "Source identity, revision or permissions changed"
        )
    if len(lease["label"]["compartments"]) > 1 and not policy.approved(
        lease["combined_approval_id"], "combined-analysis", combined_binding(lease, sources)
    ):
        raise store.Denied("APPROVAL_REQUIRED", "Combined-analysis approval expired or changed")
    spec, measured = attest(lease["capsule_id"])
    release = providers.require_sensitive_boundary(spec, lease["label"]["classification"])
    if (release["id"] if release else None) != lease["provider_release_id"]:
        raise store.Denied(
            "PROVIDER_RELEASE_CHANGED", "Provider release changed; obtain a new advisory lease"
        )
    if release:
        spec = {**spec, "_sensitive_release_id": release["id"]}
    return lease, sources, spec, measured


def destroy(task, status):
    task.pop("ciphertext", None)
    task.pop("wrapped_key", None)
    task.update(status=status, retained_key="REVOKED")
    save("task", task)
    store.receipt(
        "ADVISORY_CONTENT_DESTROYED",
        task["user"],
        task_id=task["id"],
        status=status,
        physical_zeroization="NOT_CLAIMED",
    )


def revoke(lease_id, identity):
    policy.actor(identity, ["Data Owner", "Security Officer"])
    with store.LOCK:
        read("lease", lease_id)
        revocation.record("advisory-lease", lease_id, identity)
        for raw in store.all_objects("advisory-task"):
            if raw["lease_id"] == lease_id and raw.get("ciphertext"):
                destroy(read("task", raw["id"]), "REVOKED")
    return {"status": "REVOKED", "lease_id": lease_id}


def sweep():
    with store.LOCK:
        for raw in store.all_objects("advisory-task"):
            if raw.get("ciphertext") and raw["expires_at"] <= time.time():
                destroy(read("task", raw["id"]), "EXPIRED")


def run(request, identity):
    request = RunRequest.model_validate(request).model_dump()
    policy.actor(identity, ["Operator"])
    task = {
        "id": store.uid("ADVICE-TASK"),
        "lease_id": request["lease_id"],
        "user": identity,
        "purpose": request["purpose"],
        "status": "RUNNING",
        "created_at": time.time(),
        "local_model_calls": 0,
        "external_model_calls": 0,
        "ot_write": False,
        "policy_version": policy.POLICY_VERSION,
        "prompt_hash": store.digest(request["prompt"]),
        "retrieval_query_hash": store.digest(request["retrieval_query"] or request["prompt"]),
        "key_release_state": "NOT_RELEASED",
    }
    started = time.monotonic()
    key, disclosed, texts, protected, result = None, {}, {}, {}, None
    try:
        lease, sources, spec, measured = validate_lease(task["lease_id"], identity, task["purpose"])
        query = request["retrieval_query"] or request["prompt"]
        if len(query) > 300:
            raise store.Denied(
                "RETRIEVAL_QUERY_REQUIRED",
                "For long prompts, provide an explicit retrieval_query of at most 300 characters",
            )
        task.update(
            capsule_id=lease["capsule_id"],
            label=lease["label"],
            expires_at=lease["expires_at"],
            source_bindings=lease["source_bindings"],
            provider=spec["provider"],
            provider_configuration_hash=providers.configuration_hash(spec),
            model_digest=spec["digest"],
            provider_release_id=lease["provider_release_id"],
        )
        tools.inspect_text(request["prompt"], lease["label"]["compartments"])
        key = capsules.TaskKey(lease["capsule_id"], measured, POLICY_STATE)
        task["key_release_state"] = "RELEASED_AFTER_SOFTWARE_ATTESTATION_AND_AUTHORIZATION"
        for index, source in enumerate(sources):
            validate_lease(task["lease_id"], identity, task["purpose"])
            visible, private, _ = data.disclose(source, key)
            # Only fully exposed fields become evidence; mask/pseudonym tokens
            # cannot be reinterpreted by the model as operational measurements.
            visible = {
                name: value
                for name, value in visible.items()
                if source["field_rules"][name] == "expose"
            }
            text = "\n".join(visible.values())
            tools.inspect_text(text, lease["label"]["compartments"])
            disclosed[source["id"]] = visible
            protected.update(private)
            texts[f"source_{index}.txt"] = "\n".join(
                (source["id"], source["revision"], source["title"], source["equipment"], text)
            )
        try:
            matches = retrieval.search(texts, query)
        except ValueError:
            raise store.Denied(
                "CONTEXT_BUDGET_EXCEEDED",
                "Authorized evidence exceeds retrieval limits; narrow the source set",
            ) from None
        selected = [
            sources[int(item["path"].removeprefix("source_").removesuffix(".txt"))]
            for item in matches
        ]
        task["retrieval"] = [
            {"source_id": source["id"], "revision": source["revision"], "score": match["score"]}
            for source, match in zip(selected, matches)
        ]
        task["retrieval_backends"] = [match["retrieval"] for match in matches]
        if not selected:
            result = {
                "claims": [],
                "abstain": True,
                "reason": "NO_RELEVANT_AUTHORIZED_EVIDENCE",
                "advisory_only": True,
            }
        else:

            def guard():
                validate_lease(task["lease_id"], identity, task["purpose"])

            spec = {
                **spec,
                "_cache_scope": {
                    "task": task["id"],
                    "user": identity,
                    "lease": lease["id"],
                    "capsule": lease["capsule_id"],
                },
            }
            guard()
            task["local_model_calls"] += 1
            answer = inference.generate(spec, request["prompt"], selected, disclosed, guard)
            guard()
            tools.inspect_text(answer.model_dump_json(), lease["label"]["compartments"])
            output = answer.model_dump_json().casefold()
            if any(private and private.casefold() in output for private in protected):
                raise store.Denied(
                    "PROTECTED_FIELD_DISCLOSURE", "Model response contains a protected field"
                )
            evaluated = [inference.evaluate(claim, selected, disclosed) for claim in answer.claims]
            accepted = [
                claim
                for claim in evaluated
                if claim["state"]
                in {"SUPPORTED_QUOTE", "VERIFIED_CALCULATION", "INFERRED_REQUIRES_HUMAN_REVIEW"}
            ]
            # Abstention reasons are application-owned: unsupported free text
            # from the model cannot bypass the evidence gate via a reason field.
            result = {
                "claims": [] if answer.abstain else accepted,
                "abstain": answer.abstain or not accepted,
                "reason": "MODEL_ABSTAINED"
                if answer.abstain
                else "NO_SUPPORTED_CLAIMS"
                if not accepted
                else "EVIDENCE_AVAILABLE",
                "excluded_claims": len(evaluated) - len(accepted),
                "advisory_only": True,
                "human_review_required": any(c["human_review_required"] for c in accepted),
            }
        with store.LOCK:
            validate_lease(task["lease_id"], identity, task["purpose"])
            task.update(status="COMPLETED", result_hash=store.digest(result))
            retention_key = Fernet.generate_key()
            task["wrapped_key"] = store.encrypt("advisory-retention", retention_key)
            task["ciphertext"] = (
                Fernet(retention_key).encrypt(store.canonical(result).encode()).decode()
            )
    except store.Denied as error:
        task.update(status="BLOCKED", reason=error.code)
        result = None
    except Exception as error:
        task.update(status="FAILED", reason=type(error).__name__)
        result = None
        store.event("ADVISORY_EXECUTION_FAILURE", task["id"])
    finally:
        task["hygiene"] = {
            "task_key": key.destroy() if key else "NOT_RELEASED",
            "context": "TASK_LOCAL_REFERENCES_CLEARED",
            "physical_zeroization": "NOT_CLAIMED",
        }
        disclosed.clear()
        texts.clear()
        protected.clear()
    with store.LOCK:
        task.update(
            completed_at=time.time(), latency_ms=round((time.monotonic() - started) * 1000, 2)
        )
        if result is not None:
            try:
                validate_lease(task["lease_id"], identity, task["purpose"])
            except store.Denied as error:
                task.update(status="BLOCKED", reason=error.code)
                result = None
        if result is None:
            task.pop("ciphertext", None)
            task.pop("wrapped_key", None)
        save("task", task)
        store.receipt(
            "ADVISORY_TASK_FINISHED",
            identity,
            task_id=task["id"],
            **{key: value for key, value in public(task).items() if key != "id"},
        )
    return view(task["id"], identity) if result is not None else public(task)


def view(task_id, identity):
    with store.LOCK:
        task = read("task", task_id)
        if task["user"] != identity:
            raise store.Denied("UNAUTHORIZED_DATA_REQUEST", "Advisory task belongs to another user")
        if not task.get("ciphertext"):
            return public(task)
        validate_lease(task["lease_id"], identity, task["purpose"])
        raw = Fernet(store.decrypt("advisory-retention", task["wrapped_key"])).decrypt(
            task["ciphertext"].encode()
        )
        result = json.loads(raw)
        if store.digest(result) != task["result_hash"]:
            raise store.Denied("ADVISORY_INTEGRITY_FAILURE", "Advisory result changed")
        return {**public(task), "result": result}


def close(task_id, identity):
    with store.LOCK:
        task = read("task", task_id)
        if task["user"] != identity:
            raise store.Denied(
                "UNAUTHORIZED_DATA_REQUEST", "Only the requesting user may close this task"
            )
        destroy(task, "CLOSED")
    return {"status": "CLOSED", "task_id": task_id}


def export(task_id, identity, approval_id=None):
    with store.LOCK:
        value = view(task_id, identity)
        if value["status"] != "COMPLETED" or "result" not in value:
            raise store.Denied("CLOSED_ADVISORY_TASK", "Advisory result is no longer available")
        lease = read("lease", value["lease_id"])
        if not lease["allow_export"]:
            raise store.Denied("UNAUTHORIZED_EXPORT", "Advisory lease denies export")
        policy.authorize_label(lease["recipient"], lease["label"])
        binding = {
            "task_id": task_id,
            "result_hash": value["result_hash"],
            "lease_id": lease["id"],
            "recipient": lease["recipient"],
            "user": identity,
        }
        if approval_id is None:
            return {
                "binding": binding,
                "approval": policy.request_approval("export", binding, identity),
            }
        if not policy.approved(approval_id, "export", binding):
            raise store.Denied(
                "APPROVAL_REQUIRED",
                "Independent approval of this exact advisory export is required",
            )
        store.receipt("ADVISORY_EXPORTED", identity, **binding, approval_id=approval_id)
        return {
            "result": value["result"],
            "result_hash": value["result_hash"],
            "recipient": lease["recipient"],
        }
