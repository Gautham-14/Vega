"""PUBLIC media regression cases; observations never grant production approval."""

import hashlib
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.coding import providers
from aegis.control import policy, store
from aegis.media import images, inference
from aegis.security import lockdown


class MediaCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")
    operation: Literal["understand", "generate", "edit"]
    prompt: str = Field(min_length=1, max_length=4000)
    images: list[str] = Field(default_factory=list, max_length=4)
    required_text: list[str] = Field(default_factory=list, max_length=12)
    forbidden_text: list[str] = Field(default_factory=list, max_length=12)
    negative_prompt: str = Field(default="", max_length=2000)
    width: int = Field(default=512, ge=64, le=1024, multiple_of=64)
    height: int = Field(default=512, ge=64, le=1024, multiple_of=64)
    steps: int = Field(default=20, ge=1, le=50)
    seed: int = Field(default=0, ge=0, le=2**32 - 1)
    strength: float = Field(default=0.6, ge=0, le=1, allow_inf_nan=False)
    max_latency_ms: int = Field(default=120_000, ge=1, le=120_000)

    @model_validator(mode="after")
    def meaningful(self):
        if (
            (self.operation == "understand" and not self.images)
            or (self.operation == "generate" and self.images)
            or (self.operation == "edit" and len(self.images) != 1)
        ):
            raise ValueError("Images do not match the selected operation")
        if self.operation == "understand" and not (self.required_text or self.forbidden_text):
            raise ValueError("Understanding cases require observable text checks")
        if self.operation != "understand" and (self.required_text or self.forbidden_text):
            raise ValueError("Generated images are checked for dimensions, not text semantics")
        if any(not value or len(value) > 500 for value in self.required_text + self.forbidden_text):
            raise ValueError("Check text is empty or too long")
        if sum(len(value) for value in self.images) > 8_000_000:
            raise ValueError("Case images exceed the byte budget")
        return self


class MediaSuite(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["aegis-media-qualification-v1"]
    classification: Literal["PUBLIC"]
    cases: list[MediaCase] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Qualification case IDs must be unique")
        if sum(len(image) for case in self.cases for image in case.images) > 8_000_000:
            raise ValueError("Suite images exceed the byte budget")
        return self


def run(provider_id, suite, identity):
    policy.actor(identity, ["Model Custodian"])
    generation = lockdown.check()
    suite = MediaSuite.model_validate(suite)
    spec = providers.specification(provider_id)
    requests = []
    # Validate every image and capability before any inference call.
    for case in suite.cases:
        inference.require_capability(spec, case.operation)
        request = case.model_dump()
        request["images"] = [images.sanitize(image) for image in case.images]
        requests.append(request)
    results = []
    for case, request in zip(suite.cases, requests):
        started = time.monotonic()

        def send_check():
            lockdown.check(generation)

        send_check()
        result = (inference.understand if case.operation == "understand" else inference.diffuse)(
            spec, request, before_send=send_check
        )
        send_check()
        latency = round((time.monotonic() - started) * 1000, 2)
        if case.operation == "understand":
            observed = result["answer"].casefold()
            passed = all(value.casefold() in observed for value in case.required_text) and not any(
                value.casefold() in observed for value in case.forbidden_text
            )
        else:
            passed = bool(result["images"]) and all(
                image["width"] == case.width and image["height"] == case.height
                for image in result["images"]
            )
        results.append(
            {
                "id": case.id,
                "operation": case.operation,
                "passed": passed and latency <= case.max_latency_ms,
                "latency_ms": latency,
                "output_sha256": hashlib.sha256(store.canonical(result).encode()).hexdigest(),
            }
        )
    value = {
        "id": store.uid("QUAL"),
        "status": "CANDIDATE_TESTED_NOT_APPROVED",
        "provider": provider_id,
        "model": spec["model"],
        "suite_sha256": store.digest(suite.model_dump()),
        "results": results,
        "passed": sum(row["passed"] for row in results),
        "case_count": len(results),
        "provider_configuration_sha256": providers.configuration_hash(spec),
        "created_at": time.time(),
        "raw_outputs_retained": False,
        "production_eligible": False,
        "scope": "Text checks or decoded image dimensions; visual quality is not evaluated",
    }
    with store.LOCK:
        lockdown.check(generation)
        store.receipt(
            "MEDIA_CANDIDATE_EVALUATED",
            identity,
            qualification_id=value["id"],
            passed=value["passed"],
            case_count=value["case_count"],
            production_eligible=False,
        )
        store.put(
            "provider-qualification",
            value["id"],
            {**value, "seal": store.sign(value, "provider-qualification-v1")},
        )
    return value
