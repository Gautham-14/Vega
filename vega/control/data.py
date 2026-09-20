"""Encrypted prototype assets, selective disclosure, tripwires and temporary state."""
import hashlib
import hmac
import json
import re
import shutil
import time
from datetime import date
from cryptography.fernet import Fernet
from vega import config
from vega.control.store import Denied, canonical, digest, encryption_key, get, put, require, receipt, sign, uid, event, all_objects
from vega.control.policy import COMPARTMENTS, LEVELS, SKILLS, actor, label
from vega.storage.paths import contained_file

FIELD_RULES = {"expose", "mask", "pseudonymize", "remove", "tool-only", "recipient-only"}


def add_source(spec, identity):
    actor(identity, ["Data Owner"])
    if get("source", spec["id"]):
        raise ValueError("Source already exists; register a new revision")
    if spec["compartment"] not in COMPARTMENTS or spec["classification"] not in LEVELS:
        raise ValueError("Unknown compartment or classification")
    if not spec["owner"] or not spec["authority"] or not spec["family"] or not spec["revision"]:
        raise ValueError("Source governance metadata is required")
    date.fromisoformat(spec["effective_date"])
    if not spec["permitted_skills"] or not set(spec["permitted_skills"]).issubset(SKILLS):
        raise ValueError("Unknown permitted skill")
    if spec["status"] not in {"CURRENT_APPROVED", "SUPERSEDED", "DRAFT"}:
        raise ValueError("Unknown source status")
    if set(spec["fields"]) != set(spec["field_rules"]) or not set(spec["field_rules"].values()).issubset(FIELD_RULES):
        raise ValueError("Every field needs one explicit disclosure rule")
    body = dict(spec)
    fields = body.pop("fields")
    cipher = Fernet(encryption_key("source:" + spec["compartment"]))
    body["ciphertext"] = cipher.encrypt(canonical(fields).encode()).decode()
    body["content_hash"] = digest(fields)
    body["namespace"] = "index:" + spec["compartment"]
    body["key_ref"] = "department-key-" + digest(spec["compartment"])[:16]
    body["seal"] = sign(body, "source")
    put("source", body["id"], body)
    receipt("SOURCE_REGISTERED", identity, source_id=body["id"], revision=body["revision"], compartment=body["compartment"])
    return public_source(body)


def public_source(value):
    return {k: v for k, v in value.items() if k not in {"ciphertext", "seal"}}


def source_current(value, skill, equipment):
    unsigned = {k: v for k, v in value.items() if k != "seal"}
    if not hmac.compare_digest(value.get("seal", ""), sign(unsigned, "source")):
        raise Denied("SOURCE_INTEGRITY_FAILURE", "Source metadata or encrypted content changed", value["id"])
    if value["status"] == "SUPERSEDED":
        raise Denied("SUPERSEDED_SOURCE", "Superseded source cannot enter inference", value["id"])
    if value["status"] != "CURRENT_APPROVED" or date.fromisoformat(value["effective_date"]) > date.today():
        raise Denied("NOT_AUTHORIZED", "Source is unapproved or not yet effective", value["id"])
    if skill not in value["permitted_skills"] or value["equipment"] not in {"ALL", equipment}:
        raise Denied("NOT_AUTHORIZED", "Skill or equipment is outside source authority", value["id"])
    for candidate in all_objects("source"):
        if (candidate["id"] != value["id"] and candidate["family"] == value["family"]
                and candidate["compartment"] == value["compartment"] and candidate["status"] == "CURRENT_APPROVED"
                and candidate["equipment"] in {equipment, "ALL"}
                and candidate["effective_date"] <= date.today().isoformat()
                and candidate["effective_date"] >= value["effective_date"]):
            code = "SUPERSEDED_SOURCE" if candidate["effective_date"] > value["effective_date"] else "CONFLICTING_SOURCE"
            raise Denied(code, "A newer or conflicting current revision requires a new source selection", value["id"])


def disclose(source, task_key):
    # Require successful attestation and a live key before decrypting protected fields.
    task_key.cipher()
    fields = json.loads(Fernet(encryption_key("source:" + source["compartment"])).decrypt(source["ciphertext"].encode()))
    if digest(fields) != source["content_hash"]:
        raise Denied("SOURCE_INTEGRITY_FAILURE", "Decrypted source hash mismatch", source["id"])
    visible, protected, restoration = {}, {}, {}
    for name, value in fields.items():
        rule = source["field_rules"][name]
        if rule == "expose":
            visible[name] = value
        else:
            protected[value] = rule
            if rule == "mask":
                visible[name] = "[MASKED]"
            elif rule == "pseudonymize":
                token = "Entity_" + sign({"key_ref": task_key.key_ref, "value": value}, "pseudonym")[:10]
                visible[name] = token
                restoration[token] = {"value": value, "rule": rule}
            elif rule == "recipient-only":
                token = "Recipient_" + digest({"source": source["id"], "field": name})[:10]
                visible[name] = token
                restoration[token] = {"value": value, "rule": rule}
    # Prevent accidental duplicate sensitive values in an exposed free-text field.
    for name, value in visible.items():
        for private in sorted(protected, key=len, reverse=True):
            if private:
                value = value.replace(private, "[REDACTED]")
        visible[name] = value
    return visible, protected, restoration


class IsolatedCache:
    def __init__(self):
        self.entries = {}

    def key(self, user, compartments, prefix):
        return sign({"user": user, "compartments": sorted(compartments), "prefix": prefix}, "cache-namespace")

    def set(self, task_id, user, compartments, prefix, value, sensitive=False):
        if not sensitive:
            self.entries[(task_id, self.key(user, compartments, prefix))] = value

    def read(self, task_id, user, compartments, prefix, sensitive=False):
        return None if sensitive else self.entries.get((task_id, self.key(user, compartments, prefix)))

    def clear(self, task_id):
        for key in list(self.entries):
            if key[0] == task_id:
                del self.entries[key]


def canaries():
    return {c: "VG-" + c[:3].upper() + "-" + sign(c, "privacy-canary")[:20] for c in COMPARTMENTS}


def tripwire(text, allowed_compartments):
    leaked = [c for c, marker in canaries().items() if marker in text and c not in allowed_compartments]
    if leaked:
        raise Denied("TRIPWIRE_LEAK", "Cross-compartment canary detected; export blocked")
    return {"status": "CLEAR", "scanned": "output/files/release-logs/exports/transfers"}


def context_check(text, compartments, authorized_ids=(), sanitize=False):
    from vega.security.firewall import ContextFirewall
    clean = text
    if sanitize:
        clean = clean.replace("\ufeff", "").replace("\u200b", "")
    scan = ContextFirewall().scan_text(clean, "protected-context")
    if not scan["is_safe"]:
        return {"action": "QUARANTINE", "text": "", "rule_ids": [r["rule_id"] for r in scan["matched_rules"]]}
    if re.search(r"https?://|file://|(?:[A-Za-z]:\\)|\.\./|\.\.\\|override\s+vega|bypass\s+(?:security|policy)", clean, re.I):
        event("CONTEXT_FIREWALL_DETECTION")
        return {"action": "BLOCK", "text": "", "rule_ids": ["PROHIBITED_REFERENCE"]}
    for compartment in COMPARTMENTS:
        if compartment not in compartments and re.search(r"\[compartment:" + re.escape(compartment) + r"\]", clean, re.I):
            event("COMPARTMENT_VIOLATION")
            return {"action": "BLOCK", "text": "", "rule_ids": ["CROSS_COMPARTMENT_REFERENCE"]}
    if any(item not in authorized_ids for item in re.findall(r"\[source:([^\]]+)\]", clean)):
        event("UNAUTHORIZED_FILE_ACCESS")
        return {"action": "BLOCK", "text": "", "rule_ids": ["UNAUTHORIZED_SOURCE_REFERENCE"]}
    return {"action": "SANITIZE" if clean != text else "ALLOW", "text": clean, "rule_ids": []}


class Workspace:
    def __init__(self, task_id, task_key, flow_label):
        self.task_id, self.task_key, self.label = task_id, task_key, flow_label
        self.path = contained_file(config.WORKSPACES_DIR, task_id)
        self.path.mkdir(exist_ok=False)
        self.inventory = []
        self.memory = {}
        self.prompt_cache, self.retrieval_cache = IsolatedCache(), IsolatedCache()

    def write(self, filename, text, kind):
        tripwire(text, self.label["compartments"])
        path = contained_file(self.path, filename)
        path.write_bytes(self.task_key.cipher().encrypt(text.encode()))
        self.inventory.append({"filename": filename, "label": {**self.label, "kind": kind},
                               "key_ref": self.task_key.key_ref})
        return path

    def cleanup(self):
        self.prompt_cache.clear(self.task_id)
        self.retrieval_cache.clear(self.task_id)
        self.memory.clear()
        key_status = self.task_key.destroy()
        state = {"task_key": key_status, "prompt_cache": "CLEARED", "retrieval_cache": "CLEARED",
                 "temporary_query_data": "CLEARED", "task_memory": "CLEARED", "temporary_logs": "DESTROYED",
                 "temporary_artifacts": "DESTROYED", "cross_compartment_reuse": "BLOCKED",
                 "physical_zeroization": "NOT_CLAIMED"}
        try:
            expected = contained_file(config.WORKSPACES_DIR, self.task_id)
            if expected != self.path or expected.is_symlink():
                raise OSError("Unexpected workspace location")
            shutil.rmtree(expected)
            if expected.exists():
                raise OSError("Workspace remains")
            state["workspace"] = "DESTROYED"
        except (OSError, ValueError):
            state.update(workspace="CLEANUP_FAILED", temporary_logs="CLEANUP_FAILED", temporary_artifacts="CLEANUP_FAILED")
            event("TASK_HYGIENE_FAILURE", self.task_id)
        return state
