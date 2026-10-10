"""Advisory integrates independent signed releases without loading weights."""

from unittest.mock import Mock

import pytest
from test_advisory import approve_capsule, claim, source_spec
from test_review_fixes import activate
from test_review_fixes import database as database  # pytest autouse fixture registration
from test_review_fixes import evidence as evidence  # pytest fixture registration

from aegis.advisory import inference, service
from aegis.control import store


@pytest.fixture
def internal(evidence):
    spec, signed, *_ = evidence
    _, release = activate(spec, signed)
    capsule = approve_capsule(spec["provider"])
    service.add_source(source_spec(classification="INTERNAL"), "data-owner")
    lease = service.issue_lease(
        {
            "capsule_id": capsule,
            "source_ids": ["SOP-P204"],
            "equipment": "Pump P-204",
            "skill": "inspection-review-v3",
            "purpose": "maintenance-risk-assessment",
            "user": "operator",
            "recipient": "operator",
        },
        "data-owner",
    )
    return spec, signed, release, lease


def request(lease):
    return {
        "lease_id": lease["id"],
        "prompt": "Review pump vibration",
        "purpose": "maintenance-risk-assessment",
    }


def test_signed_internal_release_is_bound_through_disclosure_and_retention(internal, monkeypatch):
    spec, _, release, lease = internal
    dispatched = []

    def synthetic(specification, prompt, sources, disclosed, before_send):
        before_send()
        dispatched.append(specification)
        assert disclosed["SOP-P204"]["finding"] == claim()["quote"]
        return inference.Answer(
            claims=[inference.Claim.model_validate(claim())], abstain=False, reason=""
        )

    monkeypatch.setattr(inference, "generate", synthetic)
    result = service.run(request(lease), "operator")
    assert result["status"] == "COMPLETED"
    assert result["provider_release_id"] == lease["provider_release_id"] == release["id"]
    assert dispatched[0]["_sensitive_release_id"] == release["id"]
    assert (
        result["provider"] == spec["provider"]
        and result["result"]["claims"][0]["state"] == "SUPPORTED_QUOTE"
    )


def test_valid_replacement_release_blocks_old_internal_lease_before_disclosure(
    internal, monkeypatch
):
    spec, signed, release, lease = internal
    _, replacement = activate(spec, signed)
    assert replacement["id"] != release["id"]
    generate = Mock(side_effect=AssertionError("Old release must not disclose evidence"))
    monkeypatch.setattr(inference, "generate", generate)
    result = service.run(request(lease), "operator")
    assert result["status"] == "BLOCKED" and result["reason"] == "PROVIDER_RELEASE_CHANGED"
    assert result["key_release_state"] == "NOT_RELEASED" and not generate.called
    assert "ciphertext" not in store.require("advisory-task", result["id"])


def test_release_replaced_during_generation_prevents_retaining_output(internal, monkeypatch):
    spec, signed, _, lease = internal

    def synthetic(*args):
        activate(spec, signed)
        return inference.Answer(
            claims=[inference.Claim.model_validate(claim())], abstain=False, reason=""
        )

    monkeypatch.setattr(inference, "generate", synthetic)
    result = service.run(request(lease), "operator")
    assert result["status"] == "BLOCKED" and result["reason"] == "PROVIDER_RELEASE_CHANGED"
    assert "ciphertext" not in store.require("advisory-task", result["id"])
