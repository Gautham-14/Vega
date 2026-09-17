"""
Vega Sovereign AI Runtime - Core Configuration
"""
from pathlib import Path
import os

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("VEGA_DATA_DIR", BASE_DIR / "data")).resolve()
DB_DIR = DATA_DIR / "db"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
WORKSPACES_DIR = DATA_DIR / "workspaces"
RECEIPTS_DIR = DATA_DIR / "receipts"
MODELS_DIR = DATA_DIR / "models"
ARTIFACTS_DIR = DATA_DIR / "artifacts"
FRONTEND_DIR = BASE_DIR / "frontend"

# Ensure all essential directories exist
for path in [DATA_DIR, DB_DIR, KNOWLEDGE_DIR, WORKSPACES_DIR, RECEIPTS_DIR, MODELS_DIR, ARTIFACTS_DIR]:
    path.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = DB_DIR / "vega.db"

# System Constants
SYSTEM_NAME = "VEGA"
SYSTEM_TAGLINE = "Self-Defending Sovereign Industrial AI Runtime"
VERSION = "1.0.0-prototype"
RUNTIME_MODE = "SIMULATION"

# Sovereignty & Zero-Egress Network Policy
ZERO_EGRESS_ENFORCED = False
ALLOW_EXTERNAL_CALLS = False
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
