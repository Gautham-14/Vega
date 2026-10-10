"""
Aegis Sovereign AI Runtime - Core Configuration
"""

import os
from pathlib import Path

from aegis import __version__
from aegis.security.private_files import no_links, restrict_permissions

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = (
    BASE_DIR / "data"
    if (BASE_DIR / "pyproject.toml").is_file()
    else Path.home() / ".aegis" / "runtime"
)
DATA_DIR = no_links(os.environ.get("AEGIS_DATA_DIR", DEFAULT_DATA_DIR))
DB_DIR = DATA_DIR / "db"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
WORKSPACES_DIR = DATA_DIR / "workspaces"
RECEIPTS_DIR = DATA_DIR / "receipts"
MODELS_DIR = DATA_DIR / "models"
ARTIFACTS_DIR = DATA_DIR / "artifacts"


def initialize_storage() -> None:
    """Create private storage explicitly at startup, never during import."""
    for path in (
        DATA_DIR,
        DB_DIR,
        KNOWLEDGE_DIR,
        WORKSPACES_DIR,
        RECEIPTS_DIR,
        MODELS_DIR,
        ARTIFACTS_DIR,
    ):
        no_links(path)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        restrict_permissions(path, directory=True)


# Database
DB_PATH = DB_DIR / "aegis.db"

# System Constants
SYSTEM_NAME = "AEGIS"
SYSTEM_TAGLINE = "Self-Defending Sovereign Industrial AI Runtime"
VERSION = __version__
RUNTIME_MODE = "SIMULATION"

# Sovereignty & Zero-Egress Network Policy
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
