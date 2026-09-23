"""Coding trust cycle using the existing local software trust root and personas.

Snapshots and retained proposals are encrypted; no tool touches the host checkout.
OS containment, real authentication and model-server isolation remain deployment work.
"""
import hashlib
import hmac
import json
import time
from pathlib import Path

from cryptography.fernet import Fernet
from aegis.control import capsules, data, policy, store
from aegis.control.runtime import POLICY_STATE
from aegis.coding import providers, tools

PURPOSES = {"ASK": "code-understanding", "PLAN": "code-planning", "EXECUTE": "secure-code-remediation"}
DEMO_FILES = {"validation.py": "def valid_port(port):\n    return 0 <= port <= 65535\n",
              "test_validation.py": "from validation import valid_port\n\ndef test_port_boundaries():\n    assert not valid_port(0)\n    assert valid_port(1)\n    assert valid_port(65535)\n    assert not valid_port(65536)\n"}
IMPLEMENTATION_PATHS = [Path(__file__), Path(providers.__file__), Path(tools.__file__), Path(capsules.__file__),
                        Path(data.__file__), Path(policy.__file__), Path(store.__file__)]
LOADED_IMPLEMENTATION = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in IMPLEMENTATION_PATHS}


def sealed(kind, value):
    body = {k: v for k, v in value.items() if k != "seal"}
    body["seal"] = store.sign(body, "coding:" + kind)
    return store.put("coding-" + kind, body["id"], body)


def verified(kind, identity):
    value = store.require("coding-" + kind, identity)
    body = {k: v for k, v in value.items() if k != "seal"}
    if not hmac.compare_digest(value.get("seal", ""), store.sign(body, "coding:" + kind)):
        raise store.Denied("CODING_INTEGRITY_FAILURE", "Coding record was modified")
    return value


def public(value):
    return {k: v for k, v in value.items() if k not in {"ciphertext", "seal", "wrapped_key"}}


def components(spec):
    # Measure this implementation and the shared gates. This is software measurement,
    # not independent verification of the Python interpreter or the Ollama process.
    implementation = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in IMPLEMENTATION_PATHS}
    if implementation != LOADED_IMPLEMENTATION:
        raise store.Denied("RUNTIME_RESTART_REQUIRED", "Coding implementation changed on disk; restart before measuring or running a Capsule")
    return {"model": spec, "tokenizer": "bundled-in-model-manifest", "quantization": "bundled-in-model-manifest",
            "system_prompt_hash": store.digest(providers.SYSTEM), "adapter": spec["provider"],
            "runtime": {"implementation": implementation, "proposal_schema": tools.Proposal.model_json_schema()},
            "skill_policy": {"id": "coding-v1", "tools": tools.TOOLS, "modes": tools.MODES, "purposes": PURPOSES},
            "retrieval": {"provider": "literal-plus-python-ast-v1", "semantic": False},
            "security_policy_version": policy.POLICY_VERSION}


def register_capsule(provider, identity):
    policy.actor(identity, ["Operator"])
    spec = providers.specification(provider)
    value = capsules.register(components(spec), identity)
    approval = policy.request_approval("capsule", {"capsule_id": value["id"]}, identity)
    return {"capsule": value, "approval": approval}


def add_repository(name, files, compartment, classification, identity):
    policy.actor(identity, ["Data Owner"])
    tools.validate_files(files)
    if compartment not in policy.COMPARTMENTS or classification not in {"PUBLIC", "INTERNAL"}:
        raise ValueError("This coding milestone accepts PUBLIC or INTERNAL snapshots only")
    label = {"compartments": [compartment], "classification": classification, "kind": "repository-snapshot"}
    policy.authorize_label(identity, label)
    tools.inspect_text(name, [compartment])
    value = {"id": store.uid("REPO"), "name": name, "label": label, "owner": identity,
             "content_hash": store.digest(files), "file_count": len(files), "created_at": time.time()}
    value["ciphertext"] = Fernet(store.encryption_key("coding-repository:" + compartment)).encrypt(store.canonical(files).encode()).decode()
    with store.LOCK:
        store.receipt("CODING_REPOSITORY_IMPORTED", identity, repository_id=value["id"], content_hash=value["content_hash"], label=label)
        return public(sealed("repository", value))


def attest(capsule_id):
    value = store.require("capsule", capsule_id)
    spec = value["components"]["model"]
    # Configuration drift also creates a different measured Capsule.
    if spec != providers.specification(spec.get("provider")):
        raise store.Denied("CAPSULE_MISMATCH", "Local model configuration changed")
    measured = components(spec)
    capsules.attest(capsule_id, measured, POLICY_STATE)
    return spec, measured


def issue_lease(repository_id, capsule_id, user, mode, minutes, allow_export, identity):
    policy.actor(identity, ["Data Owner"])
    repository = verified("repository", repository_id)
    policy.actor(user, ["Operator"])
    policy.authorize_label(user, repository["label"])
    attest(capsule_id)
    if mode not in tools.MODES or not 1 <= minutes <= 15:
        raise ValueError("Choose ASK, PLAN or EXECUTE and a lifetime of 1-15 minutes")
    value = {"id": store.uid("CODE-LEASE"), "user": user, "issuer": identity, "repository_id": repository_id,
             "repository_hash": repository["content_hash"], "capsule_id": capsule_id, "label": repository["label"],
             "mode": mode, "purpose": PURPOSES[mode], "tools": tools.MODES[mode], "allow_export": allow_export,
             "issued_at": time.time(), "expires_at": time.time() + minutes * 60}
    store.receipt("CODING_LEASE_ISSUED", identity, lease_id=value["id"], **{k: v for k, v in public(value).items() if k != "id"})
    return public(sealed("lease", value))


def validate_lease(lease_id, identity, purpose):
    lease = verified("lease", lease_id)
    if lease["user"] != identity:
        raise store.Denied("PURPOSE_LEASE_MISMATCH", "This lease belongs to a different persona")
    if lease["expires_at"] <= time.time():
        raise store.Denied("EXPIRED_PURPOSE_LEASE", "Coding lease expired")
    if store.get("coding-revocation", lease_id):
        raise store.Denied("REVOKED_PURPOSE_LEASE", "Coding lease was revoked")
    if purpose != lease["purpose"] or lease["purpose"] != PURPOSES[lease["mode"]] or lease["tools"] != tools.MODES[lease["mode"]]:
        raise store.Denied("PURPOSE_LEASE_MISMATCH", "Purpose or tools do not match the signed lease")
    policy.authorize_label(identity, lease["label"])
    repository = verified("repository", lease["repository_id"])
    if repository["content_hash"] != lease["repository_hash"] or repository["label"] != lease["label"]:
        raise store.Denied("CODING_INTEGRITY_FAILURE", "Repository revision or label changed")
    spec, measured = attest(lease["capsule_id"])
    return lease, repository, spec, measured


def revoke(lease_id, identity):
    policy.actor(identity, ["Data Owner"])
    with store.LOCK:
        verified("lease", lease_id)
        store.put("coding-revocation", lease_id, {"revoked_at": time.time(), "actor": identity})
        for task in store.all_objects("coding-task"):
            if task["lease_id"] == lease_id and task.get("ciphertext"):
                destroy(task, "REVOKED")
        store.receipt("CODING_LEASE_REVOKED", identity, lease_id=lease_id)
    return {"status": "REVOKED"}


def retain(task, payload):
    key = Fernet.generate_key()
    task["wrapped_key"] = Fernet(store.encryption_key("coding-retention")).encrypt(key).decode()
    task["ciphertext"] = Fernet(key).encrypt(store.canonical(payload).encode()).decode()
    task["content_hash"] = store.digest(payload)
    return sealed("task", task)


def destroy(task, status="CLOSED"):
    task.pop("wrapped_key", None)
    task.pop("ciphertext", None)
    task["status"] = status
    task["retained_key"] = "REVOKED"
    sealed("task", task)
    store.receipt("CODING_TASK_CLEANUP", task["user"], task_id=task["id"], status=status,
                  application_retention="REMOVED", physical_zeroization="NOT_CLAIMED")


def sweep():
    with store.LOCK:
        for record in store.all_objects("coding-task"):
            task = verified("task", record["id"])
            if task.get("ciphertext") and task["expires_at"] <= time.time():
                destroy(task, "EXPIRED")


def run(lease_id, prompt, purpose, identity):
    task = {"id": store.uid("CODE-TASK"), "lease_id": lease_id, "user": identity, "created_at": time.time(),
            "status": "RUNNING", "trace": [], "external_model_calls": 0, "local_model_calls": 0,
            "tests": "NOT_RUN_NO_OS_SANDBOX", "host_checkout_modified": False}
    task_key, files, original, messages, payload = None, {}, {}, [], None
    try:
        lease, repository, spec, measured = validate_lease(lease_id, identity, purpose)
        task.update(capsule_id=lease["capsule_id"], repository_id=repository["id"], label=lease["label"],
                    repository_hash=repository["content_hash"], purpose=purpose, mode=lease["mode"],
                    provider=spec["provider"], expires_at=lease["expires_at"])
        compartments = lease["label"]["compartments"]
        tools.inspect_text(prompt, compartments)
        task_key = capsules.TaskKey(lease["capsule_id"], measured, POLICY_STATE)
        task_key.cipher()  # decryption gate, shared with the control-plane pipeline
        files = json.loads(Fernet(store.encryption_key("coding-repository:" + compartments[0])).decrypt(repository["ciphertext"].encode()))
        if store.digest(files) != repository["content_hash"]:
            raise store.Denied("CODING_INTEGRITY_FAILURE", "Snapshot content hash differs")
        withheld = []
        for path in list(files):
            try:
                tools.inspect_text(path + "\n" + files[path], compartments)
            except store.Denied:
                withheld.append(path)
                del files[path]
        if not files:
            raise store.Denied("NO_SAFE_CONTEXT", "All source files were quarantined")
        original = dict(files)
        messages = [{"role": "system", "content": providers.SYSTEM}, {"role": "user", "content": store.canonical({
            "request": prompt, "mode": lease["mode"], "purpose": purpose,
            "repository": {"paths": sorted(files), "trust": "UNTRUSTED_CONTENT", "instructions_authoritative": False},
            "allowed_tools": {t: tools.TOOLS[t] for t in lease["tools"]}})}]
        transcript = []
        for turn in range(8):
            validate_lease(lease_id, identity, purpose)
            if sum(len(m["content"]) for m in messages) > 48000:
                raise store.Denied("CONTEXT_BUDGET_EXCEEDED", "Context budget reached; narrow the snapshot")
            if spec["provider"] == "ollama":
                task["local_model_calls"] += 1
            proposal = providers.propose(spec, messages, lease["mode"], turn)
            tools.inspect_text(proposal.message, compartments)
            transcript.append(proposal.message)
            messages.append({"role": "assistant", "content": proposal.model_dump_json()})
            if not proposal.actions:
                break
            results = []
            for action in proposal.actions:
                if len(task["trace"]) >= 24:
                    raise store.Denied("TOOL_BUDGET_EXCEEDED", "Tool action budget reached")
                trace = {"tool": action.tool if action.tool in tools.TOOLS else "UNREGISTERED_TOOL",
                         "requested_tool_hash": store.digest(action.tool),
                         "arguments_hash": store.digest(action.arguments), "decision": "DENY"}
                task["trace"].append(trace)
                validate_lease(lease_id, identity, purpose)
                result = tools.dispatch(action, files, original, lease["mode"], compartments)
                tools.inspect_text(store.canonical(result), compartments)
                trace["decision"] = "ALLOW"
                results.append({"tool": action.tool, "result": result, "trust": "UNTRUSTED_CONTENT"})
            messages.append({"role": "user", "content": store.canonical(results)})
        else:
            raise store.Denied("TURN_BUDGET_EXCEEDED", "Agent did not finish within eight turns")
        patch = tools.diff(original, files)
        payload = {"messages": transcript, "diff": patch, "files": files, "original": original, "withheld": withheld}
        tools.inspect_text(store.canonical({"messages": transcript, "diff": patch}), compartments)
        task["status"] = "AWAITING_REVIEW" if patch else "COMPLETED"
        task["diff_hash"] = store.digest(patch)
        task["quarantined_files"] = len(withheld)
        # Recheck after a possibly slow provider call, before retaining or showing output.
        with store.LOCK:
            validate_lease(lease_id, identity, purpose)
            store.receipt("CODING_TASK_PROPOSED", identity, task_id=task["id"], **{k: v for k, v in public(task).items() if k != "id"})
            retain(task, payload)
    except store.Denied as error:
        task.update(status="BLOCKED", reason=error.code, event_id=error.event_id)
        payload = None
    except Exception as error:
        task.update(status="FAILED", reason=type(error).__name__)
        payload = None
        store.event("CODING_EXECUTION_FAILURE", task["id"])
    finally:
        task["hygiene"] = {"task_key": task_key.destroy() if task_key else "NOT_RELEASED",
                           "workspace": "IN_MEMORY_ONLY_NO_HOST_FILES", "physical_zeroization": "NOT_CLAIMED",
                           "model_cache": "UNLOAD_REQUESTED_NOT_VERIFIED" if task.get("provider") == "ollama" else "NOT_USED"}
        files.clear()
        original.clear()
        messages.clear()
    with store.LOCK:
        if payload is None:
            task.pop("ciphertext", None)
            task.pop("wrapped_key", None)
        # Never resurrect a proposal that was concurrently revoked during cleanup.
        if payload is not None:
            try:
                validate_lease(lease_id, identity, purpose)
            except store.Denied as error:
                task.pop("ciphertext", None)
                task.pop("wrapped_key", None)
                task.update(status="BLOCKED", reason=error.code)
                payload = None
        sealed("task", task)
        store.receipt("CODING_TASK_FINISHED", identity, task_id=task["id"], **{k: v for k, v in public(task).items() if k != "id"})
    return view(task["id"], identity) if payload is not None else public(task)


def owned_task(task_id, identity):
    task = verified("task", task_id)
    if task["user"] != identity:
        raise store.Denied("UNAUTHORIZED_DATA_REQUEST", "This task belongs to a different persona")
    return task


def task_payload(task, identity):
    if task.get("expires_at", 0) <= time.time():
        if task.get("ciphertext"):
            destroy(task, "EXPIRED")
        raise store.Denied("EXPIRED_PURPOSE_LEASE", "Task retention expired")
    validate_lease(task["lease_id"], identity, task["purpose"])
    if not task.get("hygiene", {}).get("task_key", "").startswith("DESTROYED"):
        raise store.Denied("TASK_HYGIENE_FAILURE", "Task cleanup must finish before content is released")
    if not task.get("wrapped_key") or not task.get("ciphertext"):
        raise store.Denied("TASK_CLOSED", "Task content is no longer retained")
    key = Fernet(store.encryption_key("coding-retention")).decrypt(task["wrapped_key"].encode())
    payload = json.loads(Fernet(key).decrypt(task["ciphertext"].encode()))
    if store.digest(payload) != task["content_hash"]:
        raise store.Denied("CODING_INTEGRITY_FAILURE", "Retained task content changed")
    tools.inspect_text(store.canonical({"messages": payload["messages"], "diff": payload["diff"]}), task["label"]["compartments"])
    return payload


def view(task_id, identity):
    with store.LOCK:
        task = owned_task(task_id, identity)
        if not task.get("ciphertext"):
            return public(task)
        payload = task_payload(task, identity)
        return {**public(task), "messages": payload["messages"], "diff": payload["diff"], "withheld": payload["withheld"]}


def apply(task_id, diff_hash, identity):
    with store.LOCK:
        task = owned_task(task_id, identity)
        payload = task_payload(task, identity)
        if task["mode"] != "EXECUTE" or task["status"] != "AWAITING_REVIEW" or task["diff_hash"] != diff_hash:
            raise store.Denied("REVIEW_MISMATCH", "Review must match the current pending EXECUTE diff")
        # The applied branch is an encrypted task snapshot; no host checkout mutation.
        task["status"] = "APPLIED"
        task["applied_snapshot_hash"] = store.digest(payload["files"])
        store.receipt("CODING_PATCH_APPLIED", identity, task_id=task_id, diff_hash=diff_hash, host_checkout_modified=False)
        sealed("task", task)
        return view(task_id, identity)


def close(task_id, identity):
    with store.LOCK:
        task = owned_task(task_id, identity)
        destroy(task)
        return public(task)


def export(task_id, identity, approval_id=None, request=False):
    with store.LOCK:
        task = owned_task(task_id, identity)
        payload = task_payload(task, identity)
        lease = verified("lease", task["lease_id"])
        if not lease["allow_export"] or task["status"] != "APPLIED":
            raise store.Denied("UNAUTHORIZED_EXPORT", "Export requires an applied patch and explicit lease permission")
        binding = {"task_id": task_id, "diff_hash": task["diff_hash"], "lease_id": lease["id"], "recipient": identity}
        if request:
            approval = policy.request_approval("export", binding, identity)
            sealed("export-request", {"id": approval["id"], "task_id": task_id})
            return approval
        if not policy.approved(approval_id, "export", binding):
            raise store.Denied("APPROVAL_REQUIRED", "Patch download requires Data Owner and Security Officer approval")
        tools.inspect_text(payload["diff"], task["label"]["compartments"])
        store.receipt("CODING_PATCH_EXPORTED", identity, **binding, approval_id=approval_id)
        return {"filename": task_id + ".patch", "patch": payload["diff"], "classification": task["label"]["classification"]}


def review_export(approval_id, identity):
    policy.actor(identity, ["Data Owner", "Security Officer"])
    with store.LOCK:
        reference = verified("export-request", approval_id)
        task = verified("task", reference["task_id"])
        policy.authorize_label(identity, task["label"])
        approval = store.require("approval", approval_id)
        binding = {"task_id": task["id"], "diff_hash": task["diff_hash"], "lease_id": task["lease_id"], "recipient": task["user"]}
        if approval["binding"] != store.digest(binding) or approval["expires_at"] <= time.time():
            raise store.Denied("REVIEW_MISMATCH", "Export approval is stale")
        payload = task_payload(task, task["user"])
        store.receipt("CODING_EXPORT_REVIEWED", identity, approval_id=approval_id, task_id=task["id"])
        return {"task_id": task["id"], "diff": payload["diff"], "diff_hash": task["diff_hash"], "label": task["label"],
                "expires_at": min(task["expires_at"], approval["expires_at"])}


def state(identity):
    sweep()
    principal = policy.actor(identity)
    def visible(record):
        label = record["label"]
        return set(label["compartments"]).issubset(principal["compartments"]) and policy.LEVELS[label["classification"]] <= policy.LEVELS[principal["clearance"]]
    repositories = [public(v) for v in store.all_objects("coding-repository") if visible(v)]
    leases = [public(v) | {"revoked": bool(store.get("coding-revocation", v["id"]))} for v in store.all_objects("coding-lease")
              if v["user"] == identity or principal["role"] == "Data Owner"]
    tasks = [public(v) for v in store.all_objects("coding-task") if v["user"] == identity]
    stacks = [v for v in store.all_objects("capsule") if v["components"].get("skill_policy", {}).get("id") == "coding-v1"]
    bindings = {store.digest({"capsule_id": c["id"]}): c["id"] for c in stacks}
    exports = {r["id"]: r for r in store.all_objects("coding-export-request")}
    approvals = [{**a, "capsule_id": bindings.get(a["binding"]), "task_id": exports.get(a["id"], {}).get("task_id")}
                 for a in store.all_objects("approval") if a["binding"] in bindings or a["id"] in exports]
    return {"repositories": repositories, "leases": leases, "tasks": tasks, "capsules": stacks,
            "approvals": approvals, "actors": policy.ACTORS, "chain": store.verify_chain()}
