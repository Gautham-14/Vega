"""Meaningful negative coverage for immutable accounts and deterministic authority."""

import pytest

from aegis.control import policy, store
from aegis.security import auth
from aegis.storage.database import init_db


@pytest.fixture(autouse=True)
def initialized():
    init_db()
    store.init_control()


@pytest.mark.parametrize(
    "actor,password,template",
    [
        ("Invalid Name", "synthetic-password-12", "operator"),
        ("alice", "synthetic-password-12", "unknown-role"),
        ("operator", "synthetic-password-12", "data-owner"),
        ("operator", "short", None),
        ("alice", "synthetic-password-12", None),
    ],
)
def test_invalid_account_provisioning_does_not_create_accounts(actor, password, template):
    with pytest.raises(ValueError):
        auth.provision(actor, password, template)
    assert auth.account_inventory() == []


def test_named_account_role_is_immutable_across_password_resets():
    auth.provision("alice", "synthetic-password-one", "operator")
    assert policy.actor("alice")["role"] == "Operator"
    auth.provision("alice", "synthetic-password-two")
    assert policy.actor("alice")["role"] == "Operator"
    with pytest.raises(ValueError, match="immutable"):
        auth.provision("alice", "synthetic-password-three", "data-owner")
    assert policy.actor("alice")["role"] == "Operator"
    with pytest.raises(store.Denied):
        policy.actor("alice", ["Data Owner"])


@pytest.mark.parametrize("tamper", ["identity", "seal", "template"])
def test_named_account_role_binding_cannot_be_tampered(tamper):
    auth.provision("alice", "synthetic-password-one", "operator")
    profile = store.get("account-profile", "alice")
    if tamper == "identity":
        profile["id"] = "bob"
    elif tamper == "seal":
        profile["seal"] = "invalid"
    else:
        profile["template"] = "data-owner"
    store.put("account-profile", "alice", profile)
    with pytest.raises(store.Denied) as failure:
        policy.actor("alice")
    assert failure.value.code == "ACCOUNT_PROFILE_INTEGRITY_FAILURE"


@pytest.mark.parametrize(
    "prompt,kind,read_only",
    [
        ("shut down pump", "action", False),
        ("sensor readings", "telemetry", True),
        ("review pump vibration", "inspection", True),
        ("review this document", "review", True),
    ],
)
def test_deterministic_classification_preserves_physical_action_boundary(prompt, kind, read_only):
    decision = policy.classify(prompt, [])
    assert decision["task_type"] == kind
    assert decision["read_only"] is read_only
    assert decision["authority"] == "DETERMINISTIC_POLICY"
    if not read_only:
        assert decision["human_approval_required"] is True


def test_label_authorization_requires_clearance_and_compartment():
    with pytest.raises(store.Denied):
        policy.authorize_label(
            "operator", {"compartments": ["Finance"], "classification": "INTERNAL"}
        )
    with pytest.raises(store.Denied):
        policy.authorize_label(
            "operator", {"compartments": ["Engineering"], "classification": "CONFIDENTIAL"}
        )
    policy.authorize_label(
        "operator", {"compartments": ["Engineering"], "classification": "INTERNAL"}
    )


def test_unknown_approval_action_is_refused():
    with pytest.raises(store.Denied):
        policy.request_approval("unknown-action", {}, "data-owner")
