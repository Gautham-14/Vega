"""Create an Aegis venv using only a reviewed, hash-listed local wheelhouse."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aegis.security.private_files import no_links
from scripts.runtime_support import PROFILES, environment_python, offline_environment


ROOT = Path(__file__).resolve().parent.parent
WHEEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl\Z")
HASH_LINE = re.compile(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.+!-]*\.whl)\Z")


def verify_wheelhouse(wheelhouse: Path, manifest: Path) -> list[Path]:
    wheelhouse = no_links(wheelhouse)
    manifest = no_links(manifest)
    if not wheelhouse.is_dir() or not manifest.is_file():
        raise ValueError("Use a regular local wheelhouse and manifest")
    expected = {}
    with manifest.open("rb") as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Wheel manifest exceeds limit")
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = HASH_LINE.fullmatch(line)
        if not match or match[2] in expected:
            raise ValueError("Malformed or duplicate wheel hash entry")
        expected[match[2]] = match[1]
    files = list(wheelhouse.iterdir())
    actual = {item.name for item in files}
    if not expected or actual != set(expected):
        raise ValueError("Manifest must name every wheel and no extra wheelhouse files")
    for item in files:
        no_links(item)
        if not WHEEL_NAME.fullmatch(item.name) or not item.is_file() or item.is_symlink():
            raise ValueError("Wheelhouse must contain regular wheel files only")
        checksum = hashlib.sha256()
        with item.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(block)
        digest = checksum.hexdigest()
        if digest != expected[item.name]:
            raise ValueError(f"Wheel SHA-256 mismatch: {item.name}")
    return files


def install_verified_wheels(python: Path, wheelhouse: Path, manifest: Path, *, cwd: Path) -> int:
    # Pin each local wheel at pip's consumption boundary. Dependency URL
    # resolution and all ambient pip configuration are deliberately disabled.
    no_links(manifest)
    with manifest.open("rb") as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Wheel manifest exceeds limit")
    files = verify_wheelhouse(wheelhouse, manifest)
    with manifest.open("rb") as stream:
        if stream.read(1_000_001) != raw:
            raise ValueError("Wheel manifest changed during verification")
    expected = {match[2]: match[1] for line in raw.decode("utf-8").splitlines()
                if (match := HASH_LINE.fullmatch(line))}
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("PIP_", "PYTHON"))}
    env.update({"PIP_CONFIG_FILE": os.devnull, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                "HF_DATASETS_OFFLINE": "1"})
    fd, filename = tempfile.mkstemp(prefix=".aegis-wheel-lock-", suffix=".txt", dir=cwd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for item in sorted(files):
                stream.write(f"{item.as_uri()} --hash=sha256:{expected[item.name]}\n")
        subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
                        "install", "--no-index", "--no-deps", "--no-cache-dir", "--require-hashes",
                        "--only-binary=:all:", "-r", filename], check=True, cwd=cwd, env=env)
        subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
                        "check"], check=True, cwd=cwd, env=env)
    finally:
        Path(filename).unlink(missing_ok=True)
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheelhouse", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="core")
    args = parser.parse_args()
    try:
        files = verify_wheelhouse(args.wheelhouse, args.manifest)
        if sys.version_info < (3, 11):
            raise ValueError("Python 3.11 or newer is required")
        target = ROOT / ".venv"
        if target.exists() or target.is_symlink():
            raise ValueError(".venv already exists; use a fresh checkout or inspect it before replacement")
        env = offline_environment()
        subprocess.run([sys.executable, "-I", "-m", "venv", "--copies", str(target)], check=True, cwd=ROOT, env=env)
        python = environment_python(ROOT)
        install_verified_wheels(python, args.wheelhouse, args.manifest, cwd=ROOT)
        subprocess.run([str(python), "-I", "-c",
                        "import importlib; " + "; ".join(f"importlib.import_module({module!r})" for module in PROFILES[args.profile])],
                       check=True, cwd=ROOT, env=env)
        print(f"Verified {len(files)} local wheels; {args.profile} environment ready at {target}")
        print("Next: open Aegis.bat (Windows) or run sh Aegis.command (Linux/macOS). See QUICKSTART.md for accounts.")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Offline setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
