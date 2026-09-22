"""Every test gets private storage; collection must not open the user's data."""
import os
import tempfile

import pytest

_collection_storage = tempfile.TemporaryDirectory(prefix="aegis-test-collection-")
os.environ["AEGIS_DATA_DIR"] = _collection_storage.name
os.environ["AEGIS_ALLOWED_HOSTS"] = "localhost,127.0.0.1,[::1],testserver"
os.environ["AEGIS_ENABLE_DEMO_ENDPOINTS"] = "1"


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    from aegis import config
    from aegis.storage import database
    from aegis.knowledge import demo_data
    from aegis.runtime import enclave
    from aegis.receipts import generator
    from aegis.security import self_test

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    for name in ("DB_DIR", "KNOWLEDGE_DIR", "WORKSPACES_DIR", "RECEIPTS_DIR", "MODELS_DIR", "ARTIFACTS_DIR"):
        path = tmp_path / name.removesuffix("_DIR").lower()
        path.mkdir()
        monkeypatch.setattr(config, name, path)
    monkeypatch.setattr(config, "DB_PATH", config.DB_DIR / "aegis.db")
    monkeypatch.setattr(database, "DB_PATH", config.DB_PATH)
    monkeypatch.setattr(demo_data, "KNOWLEDGE_DIR", config.KNOWLEDGE_DIR)
    monkeypatch.setattr(enclave, "WORKSPACES_DIR", config.WORKSPACES_DIR)
    monkeypatch.setattr(generator, "RECEIPTS_DIR", config.RECEIPTS_DIR)
    monkeypatch.setattr(self_test, "_last_result", None)
