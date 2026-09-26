"""Model-native tokenization, bounded embeddings and honest memory estimates."""
import hashlib
import json
import math
from unittest.mock import Mock

import pytest
from aegis.coding import embedding, providers, retrieval, tokenizer
from aegis.control import store
from aegis.hardware.capacity import estimate
from aegis.storage.database import init_db


def test_retrieval_terms_preserve_snake_camel_acronyms_and_unicode():
    terms = tokenizer.get_tokens("valid_port parseHTTPResponse 你好 नमस्ते")
    assert {"valid_port", "valid", "port", "parse", "http", "response", "你好"} <= set(terms)
    assert ";" not in tokenizer.get_tokens("x;y")


def test_native_tokenizer_roundtrip_and_stable_ids(tmp_path):
    tokenizers = pytest.importorskip("tokenizers")
    native = tokenizers.Tokenizer(tokenizers.models.BPE())
    native.pre_tokenizer = tokenizers.pre_tokenizers.ByteLevel(add_prefix_space=False)
    native.decoder = tokenizers.decoders.ByteLevel()
    text = "Hello नमस्ते 世界 café 👩🏽‍💻\n<|custom|>"
    native.train_from_iterator([text], tokenizers.trainers.BpeTrainer(vocab_size=300,
        initial_alphabet=tokenizers.pre_tokenizers.ByteLevel.alphabet(), special_tokens=["<|custom|>"]))
    native.enable_truncation(max_length=1)
    path = tmp_path / "tokenizer.json"
    native.save(str(path))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    first = tokenizer.LocalModelTokenizer(str(path), digest)
    second = tokenizer.LocalModelTokenizer(str(path), digest)
    ids = first.encode(text)
    assert ids == second.encode(text) and len(ids) > 1
    assert first.decode(ids) == text
    assert first.encode("<|custom|>") == [native.token_to_id("<|custom|>")]
    with pytest.raises(ValueError, match="Unknown token"):
        first.decode([-1])
    with pytest.raises(ValueError, match="digest"):
        tokenizer.LocalModelTokenizer(str(path), "f" * 64)


@pytest.mark.parametrize("path", ["Qwen/model", "https://models.invalid/tokenizer.json", "//host/models/tokenizer.json"])
def test_tokenizer_never_fetches_remote_or_relative_paths(path):
    with pytest.raises(ValueError):
        tokenizer.LocalModelTokenizer(path, "a" * 64)


def local_embedding(tmp_path, monkeypatch, rows, **kwargs):
    (tmp_path / "model.safetensors").write_bytes(b"test-fixture-weights")
    (tmp_path / "modules.json").write_text(json.dumps([{"type": "sentence_transformers.models.Transformer", "path": ""}]))
    digest = retrieval.model_digest(str(tmp_path))
    model = Mock(max_seq_length=512)
    model.encode.return_value.tolist.return_value = rows
    loader = Mock(return_value=model)
    module = Mock(SentenceTransformer=loader)
    monkeypatch.setattr(embedding.importlib, "import_module", lambda name: module)
    return embedding.LocalEmbeddingSystem(str(tmp_path), digest, **kwargs), loader


def test_embedding_requires_reviewed_model_for_truncation(tmp_path, monkeypatch):
    system, loader = local_embedding(tmp_path, monkeypatch, [[3.0, 4.0]])
    for dimensions in [0, -1, True, 1, 9, 1.5]:
        with pytest.raises(ValueError, match="Truncation"):
            system.encode(["text"], dimensions=dimensions)
    assert not loader.called
    assert system.encode(["text"])[0] == [0.6, 0.8]
    assert loader.call_args.kwargs["local_files_only"] is True
    assert loader.call_args.kwargs["trust_remote_code"] is False
    assert loader.call_args.kwargs["model_kwargs"]["use_safetensors"] is True


def test_reviewed_matryoshka_dimension_normalizes(tmp_path, monkeypatch):
    system, _ = local_embedding(tmp_path, monkeypatch, [[3.0, 4.0, 8.0]], matryoshka_dimensions=(2,))
    assert system.encode(["text"], dimensions=2) == [[0.6, 0.8]]


@pytest.mark.parametrize("rows", [[], [[0.0, 0.0]], [[float("nan")]], [[float("inf")]], [[True]],
                                  [[1.0], [1.0, 2.0]], [["secret"]], [[1e308, 1e308, 1e308, 1e308]]])
def test_embedding_rejects_invalid_vectors(tmp_path, monkeypatch, rows):
    system, _ = local_embedding(tmp_path, monkeypatch, rows)
    with pytest.raises(ValueError):
        system.encode(["text"])


def test_embedding_rechecks_pin_after_construction(tmp_path, monkeypatch):
    system, loader = local_embedding(tmp_path, monkeypatch, [[1.0, 0.0]])
    (tmp_path / "model.safetensors").write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        system.encode(["text"])
    assert not loader.called


def test_embedding_direct_loader_rejects_custom_modules(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"fixture")
    (tmp_path / "modules.json").write_text('[{"type":"evil.Loader","path":""}]')
    with pytest.raises(ValueError, match="Custom"):
        embedding.LocalEmbeddingSystem(str(tmp_path), retrieval.model_digest(str(tmp_path)))


def test_external_provider_switch_cannot_bypass_loopback(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_EXTERNAL_LLM", "1")
    for endpoint in ["https://api.openai.com/v1", "http://openrouter.ai/api", "https://user:pass@generativelanguage.googleapis.com"]:
        with pytest.raises(ValueError):
            providers.loopback_endpoint(endpoint, "openai-compatible")


def test_context_guard_reserves_output_and_counts_utf8_bytes():
    init_db()
    store.init_control()
    spec = {"context_tokens": 4096, "max_tokens": 1024}
    providers.check_context(spec, [{"content": "a" * 2048}])
    with pytest.raises(store.Denied) as error:
        providers.check_context(spec, [{"content": "界" * 700}])
    assert error.value.code == "CONTEXT_BUDGET_EXCEEDED"


def test_trillion_parameter_capacity_uses_total_weight_storage():
    result = estimate(1000, 4)
    assert result["raw_weights_gb"] == 500
    assert math.isclose(result["raw_weights_gib"], 465.661, abs_tol=0.001)
    assert "KV cache" in result["excluded_memory"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 0, True])
def test_capacity_rejects_invalid_parameter_counts(value):
    with pytest.raises(ValueError):
        estimate(value)
