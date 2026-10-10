"""Retrieval math, structured transports and no-load adapter invariants."""

import json
from unittest.mock import Mock

import pytest

from aegis.coding import providers, retrieval
from aegis.coding.tools import Proposal
from aegis.control import store
from aegis.knowledge import ranking
from aegis.models.base import LlamaCppAdapter, ModelRequest, OllamaAdapter
from aegis.storage.database import init_db


def test_bm25_limits_repeated_term_inflation_and_handles_empty_documents():
    scores = ranking.bm25([["pump"], ["pump"] * 100, ["valve"]], ["pump"])
    assert scores[0] > 0 and scores[1] < 3 * scores[0] and scores[2] == 0
    assert ranking.bm25([], ["pump"]) == []


def test_mrl_shortlist_is_reranked_using_native_dimensions():
    query = [1.0, 0.0, 1.0]
    documents = [[1.0, 0.0, -1.0], [0.8, 0.1, 1.0], [-1.0, 0.0, 0.0]]
    result = ranking.dense_rank(
        query, documents, coarse_dimension=2, reviewed_dimensions=(2,), candidates=2
    )
    assert [index for index, _ in result] == [1, 0]
    with pytest.raises(ValueError, match="reviewed"):
        ranking.dense_rank(query, documents, coarse_dimension=2)


def test_late_interaction_uses_per_query_token_maxima():
    assert ranking.late_interaction([[1.0, 0.0], [0.0, 1.0]], [[0.0, 1.0], [1.0, 0.0]]) == 2
    assert ranking.late_interaction([[1.0, 0.0], [0.0, 1.0]], [[1.0, 0.0]]) == 1
    with pytest.raises(ValueError):
        ranking.late_interaction([[1.0]], [[1.0, 2.0]])


def test_packages_do_not_turn_lexical_counts_into_colbert_or_faiss(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "colbert", Mock())
    monkeypatch.setitem(sys.modules, "faiss", Mock())
    result = retrieval.search(
        {"pump.txt": "vibration measurements", "other.txt": "unrelated"}, "vibration"
    )[0]
    assert result["retrieval"]["semantic_score"] == 0
    assert result["retrieval"]["late_interaction"] == "NOT_CONFIGURED"
    assert result["retrieval"]["lexical"] == "BM25_WITH_EXACT_MATCH"


@pytest.mark.parametrize("mode", ["json_schema", "json_object", "prompt_json"])
def test_structured_output_modes_are_explicit_and_always_locally_validated(monkeypatch, mode):
    init_db()
    store.init_control()
    spec = {
        "provider": "fixture",
        "protocol": "openai-compatible",
        "model": "fixture-Q4",
        "structured_output": mode,
    }
    monkeypatch.setattr(providers, "model_listing", lambda spec: [{"model": "fixture-Q4"}])
    request = Mock(
        return_value={
            "model": "fixture-Q4",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": '{"message":"ok","actions":[]}'},
                }
            ],
        }
    )
    monkeypatch.setattr(providers, "request_json", request)
    guard = Mock()
    result = providers.generate_structured(
        spec, [{"role": "user", "content": "Return JSON"}], Proposal, before_send=guard
    )
    assert result.message == "ok" and guard.call_count == 1
    body = request.call_args.args[1]
    if mode == "prompt_json":
        assert "response_format" not in body
    else:
        assert body["response_format"]["type"] == mode
    request.return_value["choices"][0]["message"]["content"] = (
        '{"message":"x","unexpected_authority":"root"}'
    )
    with pytest.raises(store.Denied):
        providers.generate_structured(spec, [{"role": "user", "content": "Return JSON"}], Proposal)


def test_adapters_construct_and_report_configuration_without_model_calls(monkeypatch):
    monkeypatch.setattr(
        providers,
        "specification",
        lambda provider: {
            "provider": provider,
            "protocol": "openai-compatible",
            "engine": "llama.cpp",
            "model": "fixture-Q4",
        },
    )
    request = Mock(side_effect=AssertionError("No inference during setup"))
    monkeypatch.setattr(providers, "request_json", request)
    adapter = LlamaCppAdapter("fixture")
    assert adapter.health()["status"] == "CONFIGURED_NOT_PROBED"
    init_db()
    store.init_control()
    with pytest.raises(store.Denied) as error:
        adapter.generate(ModelRequest(prompt="No authorization"))
    assert error.value.code == "AUTHORIZATION_REQUIRED" and not request.called


def test_guarded_adapter_uses_local_structured_contract(monkeypatch):
    init_db()
    store.init_control()
    spec = {
        "provider": "fixture",
        "protocol": "ollama",
        "engine": "ollama",
        "model": "fixture:Q4",
        "digest": "a" * 64,
    }
    monkeypatch.setattr(providers, "specification", lambda provider: spec)
    monkeypatch.setattr(
        providers,
        "model_listing",
        lambda spec: [{"model": spec["model"], "digest": spec["digest"]}],
    )
    monkeypatch.setattr(
        providers,
        "request_json",
        lambda *a, **kw: {
            "model": spec["model"],
            "done": True,
            "message": {"role": "assistant", "content": '{"text":"synthetic answer"}'},
        },
    )
    guard = Mock()
    response = OllamaAdapter("fixture", authorization=guard, classification="PUBLIC").generate(
        ModelRequest(prompt="Answer")
    )
    assert response.content == "synthetic answer" and not response.is_simulation
    assert guard.call_count == 3 and response.metadata["weights_loaded_by_aegis"] is False


def test_vllm_cache_scope_is_gateway_issued_and_isolates_tasks(monkeypatch):
    init_db()
    store.init_control()
    connection = Mock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.read.return_value = b"{}"
    monkeypatch.setattr(providers.http.client, "HTTPConnection", lambda *a, **kw: connection)
    spec = {
        "provider": "fixture",
        "protocol": "openai-compatible",
        "engine": "vllm",
        "endpoint": "http://127.0.0.1:8080",
        "_cache_scope": {"task": "one", "user": "operator"},
    }
    salts = []
    for task in ("one", "one", "two"):
        spec["_cache_scope"]["task"] = task
        providers.request_json(
            "/v1/chat/completions", {"model": "fixture", "cache_salt": "untrusted"}, spec=spec
        )
        salts.append(json.loads(connection.request.call_args.kwargs["body"])["cache_salt"])
    assert salts[0] == salts[1] and salts[0] != salts[2] and "untrusted" not in salts


def test_dispatch_rechecks_authorization_before_disclosing_request(monkeypatch):
    init_db()
    store.init_control()
    connection = Mock()
    monkeypatch.setattr(providers.http.client, "HTTPConnection", lambda *a, **kw: connection)

    def revoked():
        raise store.Denied("REVOKED_PURPOSE_LEASE", "Lease revoked during model listing")

    spec = {"protocol": "openai-compatible", "endpoint": "http://127.0.0.1:8080"}
    with pytest.raises(store.Denied):
        providers.request_json(
            "/v1/chat/completions", {"model": "fixture"}, spec=spec, before_send=revoked
        )
    connection.request.assert_not_called()


@pytest.mark.parametrize(
    "raw",
    [
        '{"model":"a","model":"b"}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":1e9999}',
        '{"value":-1e9999}',
        '{"nested":{"actions":[],"actions":["shell"]}}',
    ],
)
def test_provider_json_rejects_ambiguous_and_nonfinite_data(raw):
    with pytest.raises(ValueError):
        providers.decode_json(raw)
