"""Every test gets private storage; collection must not open the user's data."""

import os
import tempfile
from pathlib import Path

import pytest

# macOS commonly aliases /var to /private/var; use the canonical OS temp root
# while retaining the application's rejection of arbitrary symlinked inputs.
_collection_storage = tempfile.TemporaryDirectory(
    prefix="aegis-test-collection-", dir=Path(tempfile.gettempdir()).resolve()
)
os.environ["AEGIS_DATA_DIR"] = _collection_storage.name
os.environ["AEGIS_ALLOWED_HOSTS"] = "localhost,127.0.0.1,[::1],testserver"
os.environ["AEGIS_ENABLE_DEMO_ENDPOINTS"] = "1"
# Unit/regression tests must never start or infer with the operator's weights.
os.environ["AEGIS_LOCAL_MODELS_CONFIG"] = ""


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    from aegis import config
    from aegis.knowledge import demo_data
    from aegis.receipts import generator
    from aegis.runtime import enclave
    from aegis.security import self_test
    from aegis.storage import database

    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    for name in (
        "DB_DIR",
        "KNOWLEDGE_DIR",
        "WORKSPACES_DIR",
        "RECEIPTS_DIR",
        "MODELS_DIR",
        "ARTIFACTS_DIR",
    ):
        path = tmp_path / name.removesuffix("_DIR").lower()
        path.mkdir()
        monkeypatch.setattr(config, name, path)
    monkeypatch.setattr(config, "DB_PATH", config.DB_DIR / "aegis.db")
    monkeypatch.setattr(database, "DB_PATH", config.DB_PATH)
    monkeypatch.setattr(demo_data, "KNOWLEDGE_DIR", config.KNOWLEDGE_DIR)
    monkeypatch.setattr(enclave, "WORKSPACES_DIR", config.WORKSPACES_DIR)
    monkeypatch.setattr(generator, "RECEIPTS_DIR", config.RECEIPTS_DIR)
    monkeypatch.setattr(self_test, "_last_result", None)


@pytest.fixture
def simulated_demo_hardware(isolated_storage, monkeypatch):
    """Demo workflows use fixed resources regardless of host memory pressure."""
    from aegis.hardware import scheduler
    from aegis.hardware.simulation import set_active_hardware_profile_name
    from aegis.storage.database import init_db

    init_db()
    set_active_hardware_profile_name("PROFILE_WORKSTATION")

    def no_host_detection():
        raise AssertionError("Demo tests must not depend on live hardware")

    monkeypatch.setattr(scheduler, "detect_hardware", no_host_detection)
