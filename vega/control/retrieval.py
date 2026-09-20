"""Replaceable department-local retrieval interfaces with deterministic mock engines."""
import re
from decimal import Decimal, InvalidOperation
from typing import Protocol
from vega.control.store import Denied, digest
from vega.control.data import source_current


class EmbeddingProvider(Protocol):
    def embed(self, text: str) -> list[float]: ...


class VectorBackend(Protocol):
    def search(self, namespace: str, vector: list[float], documents: list[dict]) -> list[str]: ...


class LexicalBackend(Protocol):
    def search(self, query: str, documents: list[dict]) -> list[str]: ...


class Reranker(Protocol):
    def rank(self, query: str, candidates: list[str]) -> list[str]: ...


class MockEmbedding:
    def embed(self, text):
        return [int(digest(text)[i:i + 2], 16) / 255 for i in range(0, 32, 2)]


class MockVector:
    def search(self, namespace, vector, documents):
        if any(d["namespace"] != namespace for d in documents):
            raise Denied("COMPARTMENT_VIOLATION", "Search backend received another department's documents")
        return [d["id"] for d in documents]  # Explicit mock candidates, not semantic relevance claims.


class ExactLexical:
    def search(self, query, documents):
        identifiers = set(re.findall(r"\b[A-Za-z]+-\d+\b", query.lower()))
        words = set(re.findall(r"\w+", query.lower()))
        scored = []
        for d in documents:
            text = (d["id"] + " " + d["equipment"] + " " + d["title"]).lower()
            score = sum(10 for i in identifiers if i in text) + len(words & set(re.findall(r"\w+", text)))
            if score:
                scored.append((score, d["id"]))
        return [identity for _, identity in sorted(scored, reverse=True)]


class StableReranker:
    def rank(self, query, candidates):
        return list(dict.fromkeys(candidates))


class HybridRetrieval:
    def __init__(self, embedding=None, vector=None, lexical=None, reranker=None):
        self.embedding = embedding or MockEmbedding()
        self.vector = vector or MockVector()
        self.lexical = lexical or ExactLexical()
        self.reranker = reranker or StableReranker()

    def route(self, query):
        if re.search(r'"[^"]+"|\btitle\s*:', query, re.I):
            return "TITLE"
        if re.search(r"\b[A-Za-z]+-\d+\b|\b\d{5,}\b", query):
            return "MIXED" if len(query.split()) > 3 else "EXACT"
        return "SEMANTIC"

    def retrieve(self, query, documents, compartments, skill, equipment, workspace):
        current, rejected = [], []
        for d in documents:
            if d["compartment"] not in compartments:
                raise Denied("COMPARTMENT_VIOLATION", "Cross-compartment retrieval denied", d["id"])
            try:
                source_current(d, skill, equipment)
                current.append(d)
            except Denied as error:
                rejected.append({"source_id": d["id"], "state": error.code})
        selected = []
        families = {(d["compartment"], d["family"]) for d in current}
        for compartment, family in families:
            candidates = [d for d in current if d["family"] == family and d["compartment"] == compartment]
            latest = max(d["effective_date"] for d in candidates)
            newest = [d for d in candidates if d["effective_date"] == latest]
            if len(newest) != 1:
                rejected.extend({"source_id": d["id"], "state": "CONFLICTING SOURCE"} for d in candidates)
            else:
                selected.extend(newest)
                rejected.extend({"source_id": d["id"], "state": "SUPERSEDED SOURCE"} for d in candidates if d != newest[0])
        route = self.route(query)
        vector = self.embedding.embed(query) if route in {"SEMANTIC", "MIXED"} else []
        workspace.memory["query_vector"] = vector
        workspace.memory["query"] = query
        ids = []
        for compartment in compartments:
            department_docs = [d for d in selected if d["compartment"] == compartment]
            if route in {"EXACT", "TITLE", "MIXED"}:
                ids.extend(self.lexical.search(query, department_docs))
            if route in {"SEMANTIC", "MIXED"}:
                ids.extend(self.vector.search("index:" + compartment, vector, department_docs))
        ids = self.reranker.rank(query, ids)
        result = [next(d for d in selected if d["id"] == identity) for identity in ids]
        return {"route": route, "documents": result, "rejected": rejected,
                "audit": {"source_ids": ids, "namespaces": ["index:" + c for c in compartments]}}


EVIDENCE_STATES = ["VERIFIED", "SUPPORTED", "PARTIALLY SUPPORTED", "UNSUPPORTED", "CONFLICTING SOURCE", "SUPERSEDED SOURCE", "NOT AUTHORIZED"]


def verify_claim(claim, sources, disclosed):
    source = next((s for s in sources if s["id"] == claim["source_id"]), None)
    if source is None:
        state = "NOT AUTHORIZED"
    elif source["status"] == "SUPERSEDED":
        state = "SUPERSEDED SOURCE"
    elif source["status"] != "CURRENT_APPROVED":
        state = "NOT AUTHORIZED"
    elif source["revision"] != claim.get("revision"):
        state = "CONFLICTING SOURCE"
    elif claim["text"] in disclosed.get(source["id"], {}).values():
        state = "SUPPORTED"
    elif claim.get("calculation"):
        calc = claim["calculation"]
        fields = disclosed.get(source["id"], {})
        try:
            left, right = Decimal(fields[calc["numerator"]]), Decimal(fields[calc["denominator"]])
            result = Decimal(calc["result"])
            exact_statement = f"{left} / {right} = {result}"
            state = "VERIFIED" if (left.is_finite() and right.is_finite() and result.is_finite()
                                   and right != 0 and left / right == result and claim["text"] == exact_statement) else "UNSUPPORTED"
        except (InvalidOperation, KeyError, TypeError, ZeroDivisionError):
            state = "UNSUPPORTED"
    elif claim.get("quote") in disclosed.get(source["id"], {}).values() and claim["quote"] in claim["text"]:
        state = "PARTIALLY SUPPORTED"
    else:
        state = "UNSUPPORTED"
    return {**claim, "state": state, "source_authorized": source is not None}
