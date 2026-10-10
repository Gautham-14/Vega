"""Explainable capability-first routing. Decisions never grant tool authority."""

import re

from aegis.control import store

CODE = re.compile(
    r"\b(code|coding|python|javascript|typescript|sql|debug|refactor|function|program|compiler|unit tests?|regex|traceback|algorithm|c\+\+)\b|```|\bdef\s+\w+\s*\(",
    re.I,
)


def select(prompt, models, available_mib, *, has_images=False, semantic_role=None):
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 8000:
        raise ValueError("Use a nonempty prompt of at most 8000 characters")
    if semantic_role not in {None, "code", "text"}:
        raise ValueError("Invalid semantic routing role")
    role = "vision" if has_images else semantic_role or ("code" if CODE.search(prompt) else "text")
    # Conservative UTF-8 byte upper bound, not a fabricated tokenizer count.
    budget = len(prompt.encode("utf-8")) + 1024 + (1024 if has_images else 0)
    candidates = []
    rejected = []
    for model in models:
        if model["role"] != role:
            rejected.append({"model": model["id"], "reason": "capability mismatch"})
        elif model["memory_mib"] + 512 > available_mib:
            rejected.append({"model": model["id"], "reason": "insufficient live RAM headroom"})
        elif model["context_tokens"] < budget:
            rejected.append(
                {"model": model["id"], "reason": "conservative context budget exceeded"}
            )
        else:
            candidates.append(model)
    if not candidates:
        raise store.Denied(
            "NO_ELIGIBLE_LOCAL_MODEL",
            "No matching local model fits this request; no mock/cloud/weaker-modality fallback",
        )
    selected = min(candidates, key=lambda model: (model["memory_mib"], model["id"]))
    return {
        "model": selected["id"],
        "role": role,
        "reason": "Image attachment requires vision"
        if has_images
        else "Code intent/syntax detected"
        if role == "code"
        else "General-language request",
        "policy": "capability-first-v1",
        "rejected": rejected,
        "context_estimate": "CONSERVATIVE_UTF8_BYTES_NOT_NATIVE_TOKENS",
        "available_mib": available_mib,
    }
