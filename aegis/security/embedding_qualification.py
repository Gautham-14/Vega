"""Host-admin PUBLIC ranking checks using pinned, local embedding data."""

import re
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.coding.embedding import LocalEmbeddingSystem
from aegis.control import store
from aegis.security import lockdown


class RankingCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")
    query: str = Field(min_length=1, max_length=2000)
    documents: list[str] = Field(min_length=2, max_length=64)
    expected_index: int = Field(ge=0)

    @model_validator(mode="after")
    def valid(self):
        if self.expected_index >= len(self.documents) or any(
            not text or len(text.encode()) > 8192 for text in self.documents
        ):
            raise ValueError("Expected index or document size is invalid")
        return self


class RankingSuite(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["aegis-embedding-qualification-v1"]
    classification: Literal["PUBLIC"]
    cases: list[RankingCase] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Case IDs must be unique")
        return self


def run(directory, digest, suite):
    suite = RankingSuite.model_validate(suite)
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Expected a SHA-256 model digest")
    generation = lockdown.check()
    model = LocalEmbeddingSystem(directory, digest)
    results = []
    try:
        for case in suite.cases:
            lockdown.check(generation)
            vectors = model.encode([case.query, *case.documents])
            scores = [sum(a * b for a, b in zip(vectors[0], vector)) for vector in vectors[1:]]
            winner = max(range(len(scores)), key=scores.__getitem__)
            # Ties are inconclusive rather than a lucky ordering-dependent pass.
            passed = (
                winner == case.expected_index
                and sum(score == scores[winner] for score in scores) == 1
            )
            results.append({"id": case.id, "passed": passed, "selected_index": winner})
        with store.LOCK:
            lockdown.check(generation)
            value = {
                "id": store.uid("EMBED-QUAL"),
                "model_digest": digest,
                "results": results,
                "passed": sum(row["passed"] for row in results),
                "case_count": len(results),
                "suite_sha256": store.digest(suite.model_dump()),
                "created_at": time.time(),
                "production_eligible": False,
                "raw_vectors_retained": False,
            }
            store.receipt(
                "EMBEDDING_CANDIDATE_EVALUATED",
                "host-administrator",
                qualification_id=value["id"],
                model_digest=digest,
                passed=value["passed"],
                case_count=value["case_count"],
            )
            store.put(
                "embedding-qualification",
                value["id"],
                {**value, "seal": store.sign(value, "embedding-qualification-v1")},
            )
            return value
    finally:
        model.model = None
