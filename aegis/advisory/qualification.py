"""Explicit PUBLIC advisory contract evaluation, run only when requested later."""
import time
from typing import Literal
from pydantic import Field, model_validator
from aegis.advisory import inference, service
from aegis.coding import providers
from aegis.control import policy, store
from aegis.security import lockdown


class Case(service.Strict):
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")
    prompt: str = Field(min_length=1, max_length=4000)
    fields: dict[str, str] = Field(min_length=1, max_length=24)
    expected_abstain: bool
    required_quotes: list[str] = Field(default_factory=list, max_length=12)
    forbidden_text: list[str] = Field(default_factory=list, max_length=12)
    max_latency_ms: int = Field(default=120000, ge=1, le=120000)

    @model_validator(mode="after")
    def bounded(self):
        if sum(len(v.encode()) for v in self.fields.values()) > 8000:
            raise ValueError("PUBLIC synthetic fields exceed the qualification budget")
        if not self.expected_abstain and not self.required_quotes:
            raise ValueError("Non-abstention needs at least one expected grounded quotation")
        if any(not v.strip() or len(v) > 1000 for v in self.required_quotes + self.forbidden_text):
            raise ValueError("Qualification assertions must be bounded nonblank text")
        return self


class Suite(service.Strict):
    schema_version: Literal["aegis-advisory-qualification-v1"]
    classification: Literal["PUBLIC"]
    cases: list[Case] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Advisory qualification IDs must be unique")
        return self


def run(provider_id, request, identity):
    policy.actor(identity, ["Model Custodian"])
    generation = lockdown.check()
    suite = Suite.model_validate(request)
    spec = providers.specification(provider_id)
    results = []
    for case in suite.cases:
        started = time.monotonic()
        source = {"id": "PUBLIC-FIXTURE", "revision": "1"}
        def guard():
            lockdown.check(generation)
        guard()
        try:
            answer = inference.generate(spec, case.prompt, [source], {source["id"]: case.fields}, guard)
            guard()
            evaluated = [inference.evaluate(claim, [source], {source["id"]: case.fields}) for claim in answer.claims]
            grounded = [claim for claim in evaluated if claim["state"] in {"SUPPORTED_QUOTE", "VERIFIED_CALCULATION"}]
            raw = answer.model_dump_json()
            quoted = {claim["quote"] for claim in grounded if claim["state"] == "SUPPORTED_QUOTE"}
            valid = (answer.abstain == case.expected_abstain and (not answer.claims if case.expected_abstain else bool(grounded))
                     and len(grounded) == len(evaluated)
                     and set(case.required_quotes).issubset(quoted)
                     and not any(text.casefold() in raw.casefold() for text in case.forbidden_text))
            output_hash = store.digest(answer.model_dump())
            reason = None
        except store.Denied as error:
            if error.code.startswith("EXECUTION_") or error.code == "LOCKDOWN_INTEGRITY_FAILURE":
                raise
            valid, output_hash, reason = False, None, error.code
        latency = round((time.monotonic() - started) * 1000, 2)
        results.append({"id": case.id, "passed": bool(valid and latency <= case.max_latency_ms),
                        "latency_ms": latency, "output_sha256": output_hash, "reason": reason})
    result = {"id": store.uid("QUAL"), "status": "CANDIDATE_TESTED_NOT_APPROVED", "workflow": "advisory",
              "provider": provider_id, "model": spec["model"], "suite_sha256": store.digest(suite.model_dump()),
              "case_count": len(results), "passed": sum(item["passed"] for item in results), "results": results,
              "provider_configuration_sha256": providers.configuration_hash(spec), "created_at": time.time(),
              "raw_outputs_retained": False, "independent_review_completed": False, "production_eligible": False,
              "runtime_binding_verified": False, "network_isolation_verified": False}
    with store.LOCK:
        lockdown.check(generation)
        store.put("provider-qualification", result["id"], {**result, "seal": store.sign(result, "provider-qualification-v1")})
        store.receipt("ADVISORY_CANDIDATE_EVALUATED", identity, provider_id=provider_id,
                      qualification_id=result["id"], passed=result["passed"], case_count=result["case_count"],
                      suite_sha256=result["suite_sha256"], production_eligible=False)
    return result
