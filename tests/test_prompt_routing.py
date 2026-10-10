"""Deterministic routing/security contracts; no real model runs in pytest."""

import copy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from aegis import cli
from aegis.api.routes import chat
from aegis.control import store
from aegis.models import local_runtime, prompt_routing

MODELS = [
    {"id": name, "role": role, "memory_mib": 1536, "context_tokens": 8192, "sha256": "a" * 64}
    for name, role in (("general", "text"), ("coder", "code"), ("vision", "vision"))
]


@pytest.fixture(autouse=True)
def routing_storage(isolated_storage):
    from aegis.storage.database import init_db

    init_db()


@pytest.mark.parametrize(
    "prompt,images,expected",
    [
        ("Explain heat transfer", False, "text"),
        ("Write a Python function", False, "code"),
        ("Debug this traceback", False, "code"),
        ("Read this code in an image", True, "vision"),
    ],
)
def test_capability_routing(prompt, images, expected):
    assert prompt_routing.select(prompt, MODELS, 4096, has_images=images)["role"] == expected


def test_semantic_role_and_resource_fail_closed():
    assert (
        prompt_routing.select("Implement a loop", MODELS, 4096, semantic_role="code")["model"]
        == "coder"
    )
    for kwargs in ({"has_images": True}, {"semantic_role": "code"}, {}):
        with pytest.raises(store.Denied):
            prompt_routing.select("Explain something", MODELS, 100, **kwargs)
    with pytest.raises(store.Denied):
        prompt_routing.select("Read this image", MODELS[:2], 4096, has_images=True)
    with pytest.raises(ValueError):
        prompt_routing.select("hello", MODELS, 4096, semantic_role="admin")


def test_public_and_no_tools_schema():
    for body in (
        {"prompt": "hello"},
        {"prompt": "hello", "classification": "INTERNAL"},
        {"prompt": "hello", "classification": "PUBLIC", "tools": ["shell"]},
    ):
        with pytest.raises(ValidationError):
            chat.ChatRequest.model_validate(body)
    assert cli.build_parser().parse_args(["chat", "--public", "hello"]).text == ["hello"]
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["chat", "hello"])


@pytest.fixture
def configured_chat(monkeypatch):
    settings = {"port": 8089, "models": copy.deepcopy(MODELS)}
    monkeypatch.setattr(local_runtime, "configuration", lambda: settings)
    monkeypatch.setattr(
        chat.psutil, "virtual_memory", lambda: SimpleNamespace(available=4096 * 1024**2)
    )
    monkeypatch.setattr(chat.policy, "actor", Mock())
    monkeypatch.setattr(chat.tools, "inspect_text", Mock())
    monkeypatch.setattr(chat.lockdown, "check", lambda *args: 0)
    monkeypatch.setattr(chat.auth, "authenticate", lambda request: "operator")
    monkeypatch.setattr(chat.store, "receipt", Mock())
    monkeypatch.setenv(local_runtime.KEY_ENV, "ephemeral-test-key")
    monkeypatch.setenv(local_runtime.CONFIG_HASH_ENV, local_runtime.configuration_hash(settings))
    return settings


def test_preview_never_calls_model(configured_chat, monkeypatch):
    model_call = Mock(side_effect=AssertionError("Preview must not infer"))
    monkeypatch.setattr(chat.providers, "generate_structured", model_call)
    result = chat.route(
        chat.ChatRequest(prompt="Write Python", classification="PUBLIC"), "operator"
    )
    assert result["model_calls"] == 0 and result["routing"]["role"] == "code"
    model_call.assert_not_called()


def test_chat_semantic_routing_and_auth_revocation(configured_chat, monkeypatch):
    generator = Mock(side_effect=[chat.Intent(role="code"), chat.Answer(text="A safe explanation")])
    monkeypatch.setattr(chat.providers, "generate_structured", generator)
    result = chat.chat(
        chat.ChatRequest(prompt="Implement a loop", classification="PUBLIC"), object(), "operator"
    )
    assert result["routing"]["model"] == "coder"
    assert result["routing_model_calls"] == 1 and result["is_simulation"] is False
    assert result["tools"] == [] and result["retained"] is False
    assert generator.call_args.args[0]["model"] == "coder"
    monkeypatch.setattr(chat.auth, "authenticate", Mock(side_effect=HTTPException(401, "revoked")))
    with pytest.raises(HTTPException):
        chat.chat(
            chat.ChatRequest(prompt="Write Python", classification="PUBLIC"), object(), "operator"
        )


def test_changed_inventory_and_busy_never_dispatch(configured_chat, monkeypatch):
    generator = Mock()
    monkeypatch.setattr(chat.providers, "generate_structured", generator)
    monkeypatch.setenv(local_runtime.CONFIG_HASH_ENV, "changed")
    with pytest.raises(store.Denied, match="inventory changed"):
        chat.chat(
            chat.ChatRequest(prompt="Write Python", classification="PUBLIC"), object(), "operator"
        )
    with chat.DISPATCH:
        with pytest.raises(store.Denied, match="Another routed"):
            chat.chat(
                chat.ChatRequest(prompt="Write Python", classification="PUBLIC"),
                object(),
                "operator",
            )
    generator.assert_not_called()
