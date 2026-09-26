import json
from unittest.mock import patch

import pytest
from aegis.coding import retrieval
from aegis.control import store
from aegis.storage.database import init_db


def test_exact_and_python_symbols_rank_with_line_evidence():
    files = {"validate.py": "# validation\ndef valid_port(value):\n    return value > 0\n",
             "README.md": "The port is documented here.", "other.py": "count = 42\n"}
    results = retrieval.search(files, "valid_port")
    assert results[0]["path"] == "validate.py"
    assert results[0]["line"] == 2
    assert results[0]["symbols"][0]["name"] == "valid_port"
    assert results[0]["trust"] == "UNTRUSTED_CONTENT"
    assert results[0]["retrieval"]["semantic"] is False
    assert "other.py" not in [item["path"] for item in results]


def test_chunk_line_evidence_stays_correct_at_chunk_boundary():
    content = "x" * (retrieval.CHUNK_CHARS - 1) + "\nnext line"
    chunks = retrieval._chunks({"notes.txt": content})
    assert [chunk["line"] for chunk in chunks] == [1, 2]


def test_lexical_splits_identifiers_and_missing_grammar_is_honest():
    files = {"main.js": "function parsePort(input) { return Number(input); }"}
    with patch.object(retrieval, "installed", return_value=False):
        result = retrieval.search(files, "parse port")[0]
    assert result["path"] == "main.js" and not result["symbols"]
    assert result["retrieval"]["structure"] == "UNAVAILABLE"


@pytest.mark.parametrize("files", [{"../bad": "x"}, {".env": "x"}, {"x": "\x00"}, {"x": "x" * 128001}])
def test_retrieval_rejects_invalid_snapshots(files):
    with pytest.raises(ValueError):
        retrieval.search(files, "x")


def test_explicit_unavailable_embedding_fails_without_network(monkeypatch, tmp_path):
    init_db()
    store.init_control()
    monkeypatch.setenv("AEGIS_EMBEDDING_MODEL_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_EMBEDDING_DIGEST", "a" * 64)
    with patch.object(retrieval, "installed", return_value=False):
        assert retrieval.configuration()["semantic_status"] == "DEPENDENCY_UNAVAILABLE"
        with pytest.raises(store.Denied) as denied:
            retrieval.search({"x.py": "x=1"}, "x")
    assert denied.value.code == "EMBEDDING_UNAVAILABLE"


def test_embedding_digest_changes_with_weight_bytes_and_rejects_code(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"fixture-not-a-live-model")
    first = retrieval.model_digest(str(tmp_path))
    (tmp_path / "model.safetensors").write_bytes(b"changed")
    assert retrieval.model_digest(str(tmp_path)) != first
    (tmp_path / "evil.py").write_text("raise RuntimeError('never execute')")
    with pytest.raises(ValueError, match="data and safetensors"):
        retrieval.model_digest(str(tmp_path))


def test_semantic_adapter_is_local_only_and_scores_bounded(monkeypatch, tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"fixture-not-live-weights")
    (tmp_path / "modules.json").write_text(json.dumps([{"type": "sentence_transformers.models.Transformer", "path": ""}]))
    profile = {"enabled": True, "requested": True, "status": "PINNED_LOCAL_MODEL", "model_digest": retrieval.model_digest(str(tmp_path))}
    monkeypatch.setenv("AEGIS_EMBEDDING_MODEL_DIR", str(tmp_path))
    monkeypatch.setattr(retrieval, "_embedding_configuration", lambda: profile)
    calls = []
    class Vectors:
        def tolist(self):
            return [[1.0, 0.0], [1.0, 0.0], [0.0, 1.0]]
    class Model:
        max_seq_length = 1024
        def __init__(self, path, **kwargs):
            calls.append(kwargs)
        def encode(self, texts, **kwargs):
            assert len(texts) == 3
            return Vectors()
    class Module:
        SentenceTransformer = Model
    with patch.object(retrieval.importlib, "import_module", return_value=Module):
        scores = retrieval._semantic_scores({"a.py": "foo", "b.py": "bar"}, "idea", profile)
    assert scores["a.py"][0] == 1
    assert calls[0]["local_files_only"] and calls[0]["trust_remote_code"] is False
    assert calls[0]["device"] == "cpu" and calls[0]["token"] is False
