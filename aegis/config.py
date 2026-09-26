"""
Aegis Sovereign AI Runtime - Core Configuration
"""
from pathlib import Path
import os
from aegis.security.private_files import no_links, restrict_permissions

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "data"
DATA_DIR = no_links(os.environ.get("AEGIS_DATA_DIR", DEFAULT_DATA_DIR))
DB_DIR = DATA_DIR / "db"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
WORKSPACES_DIR = DATA_DIR / "workspaces"
RECEIPTS_DIR = DATA_DIR / "receipts"
MODELS_DIR = DATA_DIR / "models"
ARTIFACTS_DIR = DATA_DIR / "artifacts"
FRONTEND_DIR = BASE_DIR / "frontend"

# Ensure all essential directories exist
for path in [DATA_DIR, DB_DIR, KNOWLEDGE_DIR, WORKSPACES_DIR, RECEIPTS_DIR, MODELS_DIR, ARTIFACTS_DIR]:
    no_links(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        restrict_permissions(path, directory=True)

# Database
DB_PATH = DB_DIR / "aegis.db"

# System Constants
SYSTEM_NAME = "AEGIS"
SYSTEM_TAGLINE = "Self-Defending Sovereign Industrial AI Runtime"
VERSION = "1.0.0-prototype"
RUNTIME_MODE = "SIMULATION"

# Sovereignty & Zero-Egress Network Policy
ZERO_EGRESS_ENFORCED = False
ALLOW_EXTERNAL_CALLS = False
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
