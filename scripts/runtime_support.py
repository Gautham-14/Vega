"""Shared, dependency-free platform and offline-runtime settings."""
import importlib
import os
from pathlib import Path
import sys

CORE_MODULES = ("fastapi", "uvicorn", "pydantic", "psutil", "cryptography", "rich")
PROFILES = {"core": CORE_MODULES, "media": (*CORE_MODULES, "PIL"),
            "full": (*CORE_MODULES, "PIL", "tokenizers", "sentence_transformers")}


def environment_python(root, platform_name=None):
    return Path(root) / ".venv" / ("Scripts/python.exe" if (platform_name or os.name) == "nt" else "bin/python")


def offline_environment():
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("PYTHON", "PIP_"))}
    env.update({"PIP_NO_INDEX": "1", "PIP_CONFIG_FILE": os.devnull,
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
                "NO_PROXY": "*", "no_proxy": "*"})
    return env


def require_environment(root):
    expected = Path(root) / ".venv"
    # POSIX venv executables may resolve to the system Python symlink. Comparing
    # executables alone would accidentally accept the shared system environment.
    if (sys.version_info < (3, 11) or Path(sys.prefix).resolve() != expected.resolve()
            or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve()):
        raise RuntimeError("Use Aegis.bat or Aegis.command to run the dedicated environment. See QUICKSTART.md.")
    missing = []
    for module in CORE_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    if missing:
        raise RuntimeError("Incomplete core environment: " + ", ".join(missing) + ". See QUICKSTART.md.")
