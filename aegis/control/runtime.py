"""The governed prototype pipeline. Mock inference only sees disclosed context."""
import time
from aegis.control import artifacts, capsules, leases, packages
from aegis.control.store import Denied, put, require, receipt, uid, digest, event
from aegis.control.policy import actor, authorize_label, classify, label, approved, SKILLS, tool_guard, LEVELS, POLICY_VERSION
from aegis.control.data import Workspace, disclose, context_check, tripwire
from aegis.control.retrieval import HybridRetrieval, verify_claim

POLICY_STATE = {"offline": True, "firewall": True, "hygiene": True, "training": False}


class GovernedRunner:
    def infer(self, sources, disclosed):
        # Deterministic extractive mock. No raw source, ciphertext, protected mapping or tools enter this adapter.
        return [{"text": value, "source_id": source["id"], "revision": source["revision"]}
                for source in sources for name, value in disclosed[source["id"]].items() if name == "finding"]

    def run(self, request, identity):
        actor(identity, ["Operator", "Data Owner"])
        task_id = uid("TASK")
        task = {"id": task_id, "user": identity, "role": actor(identity)["role"], "status": "RUNNING",
                "capsule_id": request["capsule_id"], "lease_id": request["lease_id"], "package_id": request["package_id"],
                "policy_version": POLICY_VERSION, "source_ids": request["source_ids"], "steps": [],
                "network": {"external_api_calls": 0, "internet_dependency": "NONE", "execution_mode": "OFFLINE",
                            "scope": "APPLICATION_MOCK_CALLS", "os_isolation_verified": False},
                "key_release_state": "NOT_RELEASED"}
        workspace = None
        task_key = None
        retained = None
        payload = None
        def step(name, **metadata):
            task["steps"].append({"step": name, **metadata})
        try:
            sources = [require("source", source_id) for source_id in request["source_ids"]]
            if not sources or len(set(request["source_ids"])) != len(sources):
                raise Denied("UNAUTHORIZED_DATA_REQUEST", "Select distinct authorized source IDs")
            classification = classify(request["prompt"], sources)
            task["classification"] = classification
            task.update(skill=classification["skill"], purpose=classification["purpose"], output_type=request["output_type"])
            flow_label = label(sources)
            task["label"] = flow_label
            authorize_label(identity, flow_label)
            skill = SKILLS[task["skill"]]
            if (request["output_type"] not in skill["output_types"] or not set(flow_label["compartments"]).issubset(skill["compartments"])
                    or flow_label["classification"] not in skill["data_classes"]):
                raise Denied("SKILL_POLICY_VIOLATION", "Data or output falls outside the active skill")
            step("CLASSIFICATION", **classification)
            lease_args = dict(user=identity, capsule_id=task["capsule_id"], skill=task["skill"],
                purpose=task["purpose"], source_ids=task["source_ids"], compartments=flow_label["compartments"], output_type=task["output_type"])
            lease = leases.validate(request["lease_id"], **lease_args)
            step("PURPOSE_LEASE", status="VERIFIED", lease_id=lease["id"])
            binding = {"lease_id": lease["id"], "capsule_id": task["capsule_id"], "user": identity, "source_ids": sorted(task["source_ids"])}
            if len(flow_label["compartments"]) > 1 and not approved(request.get("combined_approval_id"), "combined-analysis", binding):
                raise Denied("APPROVAL_REQUIRED", "Combined analysis requires two-person approval")
            if LEVELS[flow_label["classification"]] >= 2 and not approved(request.get("key_approval_id"), "key-release", binding):
                raise Denied("APPROVAL_REQUIRED", "Sensitive key release requires two-person approval")
            package = packages.executable(task["package_id"], task["skill"])
            from aegis.hardware.detector import detect_hardware
            hw = detect_hardware()
            compatibility = packages.compatibility(package["manifest"], hw["available_ram_mb"], hw["gpu"]["vram_mb"])
            if compatibility != "COMPATIBLE":
                raise Denied("HARDWARE_INCOMPATIBLE", compatibility)
            components = capsules.active_components(package, task["skill"])
            leases.validate(request["lease_id"], **lease_args)
            task_key = capsules.TaskKey(task["capsule_id"], components, POLICY_STATE)
            task["key_release_state"] = "RELEASED_AFTER_SOFTWARE_ATTESTATION"
            step("ATTESTATION", **task_key.attestation)
            step("KEY_RELEASE", key_ref=task_key.key_ref)
            workspace = Workspace(task_id, task_key, flow_label)
            scan = context_check(request["prompt"], flow_label["compartments"], task["source_ids"])
            if scan["action"] in {"BLOCK", "QUARANTINE"}:
                raise Denied("CONTEXT_FIREWALL_DETECTION", "Task prompt was blocked")
            if not classification["read_only"]:
                action_binding = {**binding, "equipment": request["equipment"], "action_hash": digest(request["prompt"])}
                tool_guard(task["skill"], "ot-write", request.get("action_approval_id"), action_binding)
                step("OT_BOUNDARY", status="APPROVED_SIMULATED_ACTION_ONLY")
            tool_guard(task["skill"], "search" if "search" in skill["tools"] else "telemetry")
            retrieval = HybridRetrieval().retrieve(request["prompt"], sources, flow_label["compartments"], task["skill"], request["equipment"], workspace)
            selected = retrieval["documents"]
            if not selected:
                raise Denied("NOT_AUTHORIZED", "No current authoritative source was retrieved")
            step("HYBRID_RETRIEVAL", route=retrieval["route"], **retrieval["audit"], rejected=retrieval["rejected"])
            task["source_revisions"] = [{"id": s["id"], "revision": s["revision"]} for s in selected]
            disclosed, protected, restoration = {}, {}, {}
            for source in selected:
                leases.validate(request["lease_id"], **lease_args)
                visible, secrets, tokens = disclose(source, task_key)
                text = "\n".join(visible.values())
                scan = context_check(text, flow_label["compartments"], task["source_ids"])
                if scan["action"] in {"BLOCK", "QUARANTINE"}:
                    raise Denied("CONTEXT_FIREWALL_DETECTION", "Retrieved context was quarantined", source["id"])
                tripwire(text, flow_label["compartments"])
                disclosed[source["id"]] = visible
                protected.update(secrets)
                restoration.update(tokens)
                workspace.write(digest(source["id"]) + ".enc", text, "retrieved-context")
            step("SELECTIVE_DISCLOSURE", status="APPLIED", protected_fields=len(protected))
            step("CONTEXT_FIREWALL", status="ALLOW")
            sensitive = LEVELS[flow_label["classification"]] >= 2
            workspace.prompt_cache.set(task_id, identity, flow_label["compartments"], request["prompt"], disclosed, sensitive)
            workspace.retrieval_cache.set(task_id, identity, flow_label["compartments"], request["prompt"], retrieval["audit"], sensitive)
            step("CACHE_ISOLATION", status="DISABLED_SENSITIVE" if sensitive else "TASK_PRINCIPAL_COMPARTMENT_SCOPED")
            leases.validate(request["lease_id"], **lease_args)
            # Recheck the measured stack immediately before crossing the adapter boundary.
            capsules.attest(task["capsule_id"], capsules.active_components(packages.executable(task["package_id"], task["skill"]), task["skill"]), POLICY_STATE)
            draft = self.infer([{"id": source["id"], "revision": source["revision"]} for source in selected], disclosed)
            tripwire("\n".join(c["text"] for c in draft), flow_label["compartments"])
            claims = [verify_claim(c, selected, disclosed) for c in draft]
            accepted = [c for c in claims if c["state"] in {"VERIFIED", "SUPPORTED"}]
            if not accepted:
                raise Denied("UNSUPPORTED_CLAIM", "No supported claims available for the deliverable")
            task["evidence"] = [{k: v for k, v in c.items() if k != "text"} for c in claims]
            text = "# Aegis prototype evidence review\n\nSoftware simulation; advisory output.\n\n" + "\n".join(
                f"- [{c['state']}] {c['text']} (source {c['source_id']}, revision {c['revision']})" for c in accepted)
            for source_id, fields in disclosed.items():
                text += "\n" + "\n".join(f"{name}: {value}" for name, value in fields.items() if name != "finding")
            tripwire(text, flow_label["compartments"])
            workspace.write("report.enc", text, "exportable-artifact")
            workspace.write("task-log.enc", "Policy steps completed", "temporary-log")
            task["information_flow"] = workspace.inventory + [{"label": {**flow_label, "kind": kind}}
                for kind in ("source-document", "task-memory", "tool-output", "generated-summary", "generated-report")]
            step("EVIDENCE_GATE", supported=len(accepted), excluded=len(claims) - len(accepted))
            step("PRIVACY_TRIPWIRE", status="CLEAR")
            payload = {"text": text, "protected": protected, "restoration": restoration}
            task["status"] = "COMPLETED"
        except Denied as error:
            task.update(status="BLOCKED", reason=error.code, event_id=error.event_id)
        except Exception as error:
            # Never persist exception strings which may contain confidential source content.
            task.update(status="FAILED", reason=type(error).__name__)
            event("TASK_EXECUTION_FAILURE", task_id)
        finally:
            if workspace:
                task["hygiene"] = workspace.cleanup()
                if task["hygiene"]["workspace"] != "DESTROYED":
                    task.update(status="FAILED", reason="TASK_HYGIENE_FAILURE")
            else:
                task["hygiene"] = {"workspace": "NOT_CREATED", "task_key": task_key.destroy() if task_key else "NOT_RELEASED",
                                   "physical_zeroization": "NOT_CLAIMED"}
            step("MEMORY_HYGIENE", **task["hygiene"])
        if task["status"] == "COMPLETED" and payload:
            try:
                retained = artifacts.retain(task, payload, min(lease["expires_at"], time.time() + 900))
                task["artifact_id"] = retained["id"]
            except Exception as error:
                task.update(status="FAILED", reason=type(error).__name__)
                event("ARTIFACT_RETENTION_FAILURE", task_id)
        task["completed_at"] = time.time()
        put("task", task_id, task)
        task["receipt"] = receipt("TASK_COMPLETED" if task["status"] == "COMPLETED" else "TASK_DENIED", identity,
            task_id=task_id, user=identity, role=task["role"], skill=task.get("skill"), purpose=task.get("purpose"),
            capsule_id=task["capsule_id"], policy_version=POLICY_VERSION, source_ids=task["source_ids"],
            source_revisions=task.get("source_revisions", []), label=task.get("label"), evidence=task.get("evidence", []),
            key_release_state=task["key_release_state"], hygiene=task["hygiene"], network=task["network"],
            export_decision="NOT_REQUESTED", status=task["status"], reason=task.get("reason"))
        if retained and request.get("export", True):
            task["export"] = artifacts.export_artifact(retained["id"], identity, request["recipient"])
        return task
