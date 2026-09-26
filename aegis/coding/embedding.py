"""Pinned local text embeddings for retrieval, separate from LLM weight storage."""
import importlib
import math


class LocalEmbeddingSystem:
    def __init__(self, model_dir, expected_digest, *, matryoshka_dimensions=()):
        from aegis.coding.retrieval import _model_root, model_digest, _validate_model_layout
        self.model_dir = str(_model_root(model_dir))
        self.expected_digest = expected_digest
        if model_digest(self.model_dir) != expected_digest:
            raise ValueError("Embedding model digest mismatch")
        _validate_model_layout(_model_root(self.model_dir))
        if any(type(d) is not int or not 1 <= d <= 4096 for d in matryoshka_dimensions):
            raise ValueError("Invalid reviewed Matryoshka dimensions")
        self.matryoshka_dimensions = tuple(matryoshka_dimensions)
        self.model = None

    def load_model(self):
        from aegis.coding.retrieval import model_digest, _validate_model_layout, _model_root
        if model_digest(self.model_dir) != self.expected_digest:
            raise ValueError("Embedding model changed before loading")
        _validate_model_layout(_model_root(self.model_dir))
        loader = importlib.import_module("sentence_transformers").SentenceTransformer
        self.model = loader(
            self.model_dir, local_files_only=True, trust_remote_code=False,
            device="cpu", token=False,
            model_kwargs={"use_safetensors": True, "local_files_only": True, "trust_remote_code": False},
            config_kwargs={"local_files_only": True, "trust_remote_code": False})
        self.model.max_seq_length = min(int(self.model.max_seq_length), 512)

    def encode(self, texts, dimensions=None):
        if (not isinstance(texts, list) or not 1 <= len(texts) <= 385
                or any(not isinstance(t, str) or len(t.encode("utf-8")) > 8192 for t in texts)):
            raise ValueError("Embedding inputs must be a bounded batch of text")
        if dimensions is not None and (type(dimensions) is not int or dimensions not in self.matryoshka_dimensions):
            raise ValueError("Truncation requires a reviewed Matryoshka-trained model and supported dimension")
        from aegis.coding.retrieval import model_digest
        if model_digest(self.model_dir) != self.expected_digest:
            raise ValueError("Embedding model changed")
        if self.model is None:
            self.load_model()
        rows = self.model.encode(texts, batch_size=8, show_progress_bar=False,
                                 normalize_embeddings=True, convert_to_numpy=True).tolist()
        if (not isinstance(rows, list) or len(rows) != len(texts) or not rows
                or not isinstance(rows[0], list) or not 1 <= len(rows[0]) <= 4096):
            raise ValueError("Invalid embedding shape")
        width = len(rows[0])
        normalized = []
        for row in rows:
            if (not isinstance(row, list) or len(row) != width
                    or any(type(v) not in (int, float) or not math.isfinite(v) for v in row)):
                raise ValueError("Invalid embedding vector")
            if dimensions is not None:
                if dimensions > width:
                    raise ValueError("Requested dimension exceeds the model output")
                row = row[:dimensions]
            norm = math.hypot(*row)
            if not math.isfinite(norm) or norm == 0:
                raise ValueError("Embedding must have a finite nonzero norm")
            normalized.append([v / norm for v in row])
        if model_digest(self.model_dir) != self.expected_digest:
            raise ValueError("Embedding model changed during encoding")
        return normalized


# Compatibility name; arbitrary models do not acquire Matryoshka training here.
MatryoshkaEmbeddingSystem = LocalEmbeddingSystem
