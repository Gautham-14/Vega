"""Bounded, local text-model candidate evaluation; never grants approval."""

import hashlib
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.coding import providers
from aegis.control import policy, store
from aegis.security import lockdown


class QualificationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")
    prompt: str = Field(min_length=1, max_length=4000)
    required_text: list[str] = Field(default_factory=list, max_length=12)
    forbidden_text: list[str] = Field(default_factory=list, max_length=12)
    max_latency_ms: int = Field(default=120_000, ge=1, le=120_000)

    @model_validator(mode="after")
    def meaningful(self):
        if not self.required_text and not self.forbidden_text:
            raise ValueError("Qualification case needs an observable pass/fail condition")
        if any(not item or len(item) > 500 for item in self.required_text + self.forbidden_text):
            raise ValueError("Qualification check text is empty or too long")
        return self


class QualificationSuite(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["aegis-text-qualification-v1"]
    classification: Literal["PUBLIC"]
    cases: list[QualificationCase] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Qualification case IDs must be unique")
        return self


def _text_response(spec, prompt):
    providers.check_model(spec, providers.model_listing(spec))
    if spec.get("protocol", "ollama") == "openai-compatible":
        result = providers.request_json("/v1/chat/completions", {
            "model": spec["model"], "messages": [{"role": "user", "content": prompt}],
            "temperature": 0, "stream": False, "max_tokens": min(spec["max_tokens"], 1024),
        }, spec=spec)
        choices = result.get("choices")
        if (result.get("model") != spec["model"] or not isinstance(choices, list) or len(choices) != 1
                or not isinstance(choices[0], dict) or choices[0].get("finish_reason") != "stop"):
            raise ValueError("Incomplete or mismatched local model response")
        message = choices[0].get("message")
        content = message.get("content") if isinstance(message, dict) else None
    else:
        result = providers.request_json("/api/chat", {
            "model": spec["model"], "messages": [{"role": "user", "content": prompt}],
            "stream": False, "keep_alive": 0,
            "options": {"temperature": 0, "num_predict": min(spec.get("max_tokens", 1024), 1024),
                        "num_ctx": spec.get("context_tokens", 16384)},
        }, spec=spec)
        if result.get("model") != spec["model"] or result.get("done") is not True or result.get("done_reason") == "length":
            raise ValueError("Incomplete or mismatched local model response")
        message = result.get("message")
        content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not 1 <= len(content) <= 20_000:
        raise ValueError("Qualification output is empty or too large")
    return content


def run_candidate_suite(provider_id: str, suite: dict, identity: str) -> dict:
    """Run synthetic PUBLIC tests through a registered loopback provider."""
    policy.actor(identity, ["Model Custodian"])
    generation = lockdown.check()
    suite = QualificationSuite.model_validate(suite)
    spec = providers.specification(provider_id)
    if provider_id == "reference" or spec.get("protocol") == "sd-webui":
        raise store.Denied("QUALIFICATION_CAPABILITY_MISMATCH", "This preliminary suite supports live text providers only")
    suite_hash = store.digest(suite.model_dump())
    results = []
    for case in suite.cases:
        lockdown.check(generation)
        started = time.monotonic()
        output = _text_response(spec, case.prompt)
        lockdown.check(generation)
        latency = round((time.monotonic() - started) * 1000, 2)
        observed = output.casefold()
        missing = [value for value in case.required_text if value.casefold() not in observed]
        forbidden = [value for value in case.forbidden_text if value.casefold() in observed]
        results.append({"id": case.id, "passed": not missing and not forbidden and latency <= case.max_latency_ms,
                        "missing_required": len(missing), "forbidden_found": len(forbidden),
                        "latency_ms": latency, "output_sha256": hashlib.sha256(output.encode()).hexdigest()})
    result = {"status": "CANDIDATE_TESTED_NOT_APPROVED", "provider": provider_id,
              "model": spec["model"], "suite_sha256": suite_hash, "case_count": len(results),
              "passed": sum(item["passed"] for item in results), "results": results,
              "raw_outputs_retained": False, "independent_review_completed": False,
              "runtime_binding_verified": False, "network_isolation_verified": False,
              "production_eligible": False}
    with store.LOCK:
        lockdown.check(generation)
        store.receipt("MODEL_CANDIDATE_EVALUATED", identity, provider_id=provider_id,
                      suite_sha256=suite_hash, passed=result["passed"], case_count=len(results),
                      production_eligible=False)
    return result
