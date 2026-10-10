"""UTF-8, provenance, critical coverage and reproducible source release gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRITICAL_FLOORS = {
    "aegis/security/auth.py": 80,
    "aegis/control/policy.py": 80,
    "aegis/security/recovery.py": 80,
    "aegis/coding/providers.py": 80,
    "aegis/advisory/inference.py": 80,
    "aegis/media/inference.py": 80,
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_files():
    # Include new, uncommitted implementation files, but never ignored secrets.
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT
    )
    return sorted({p.decode("utf-8") for p in raw.split(b"\0") if p} - {"verification/latest.json"})


def source_hash():
    digest = hashlib.sha256()
    for name in source_files():
        path = ROOT / name
        if path.suffix == ".md" or not path.is_file():
            continue
        digest.update(name.encode("utf-8") + b"\0" + bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def encoding_check():
    suffixes = {
        ".py",
        ".md",
        ".toml",
        ".txt",
        ".json",
        ".yml",
        ".yaml",
        ".sh",
        ".ps1",
        ".bat",
        ".command",
        ".lock",
        ".service",
        ".rules",
        ".conf",
    }
    # Escapes keep the checker itself free of the malformed sequences it detects.
    malformed = (
        "\ufffd",
        "\u00c2\u00b0",
        "\u00e2\u20ac\u201c",
        "\u00e2\u20ac\u201d",
        "\u00e2\u20ac\u2122",
    )
    for name in source_files():
        path = ROOT / name
        if path.suffix not in suffixes or not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="strict")
        if any(value in text for value in malformed):
            raise ValueError("Malformed text encoding: " + name)


def versions_check():
    from aegis import __version__, config

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert (
        metadata["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "aegis.version.__version__"
    )
    assert metadata["project"]["dynamic"] == ["version"]
    assert config.VERSION == __version__
    assert "version=__version__" in (ROOT / "aegis/api/server.py").read_text(encoding="utf-8")
    assert "{__version__}" in (ROOT / "aegis/operator/shell.py").read_text(encoding="utf-8")
    return __version__


def coverage_check(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    files = {name.replace("\\", "/"): data for name, data in report["files"].items()}
    actual = {}
    for name, floor in CRITICAL_FLOORS.items():
        data = files.get(name)
        if data is None:
            raise ValueError("Coverage missing for " + name)
        percent = data["summary"]["percent_covered"]
        if percent < floor:
            raise ValueError(f"{name}: {percent:.2f}% coverage below {floor}%")
        actual[name] = round(percent, 2)
    return actual


def snapshot():
    return {
        "source_sha256": source_hash(),
        "base_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_at": time.time(),
        "locks": {p.name: sha256(p) for p in sorted(ROOT.glob("requirements*.lock"))},
    }


def release_gate(args):
    baseline = json.loads(args.snapshot.read_text(encoding="utf-8"))
    current = snapshot()
    if (
        current["source_sha256"] != baseline["source_sha256"]
        or current["locks"] != baseline["locks"]
    ):
        raise ValueError("Source or dependency locks changed after verification started")
    for report in (args.junit, args.coverage, args.package):
        if report.stat().st_mtime < baseline["created_at"]:
            raise ValueError("Stale verification artifact: " + str(report))
    root = ET.parse(args.junit).getroot()
    cases = list(root.iter("testcase"))
    if not cases or list(root.iter("failure")) or list(root.iter("error")):
        raise ValueError("Regression report is empty or contains failures")
    package = json.loads(args.package.read_text(encoding="utf-8"))
    version = versions_check()
    if package.get("status") != "PASS" or package.get("version") != version:
        raise ValueError("Packaged installation did not pass for this version")
    actual = coverage_check(args.coverage)
    encoding_check()
    for command in (
        [
            "ruff",
            "check",
            "aegis",
            "scripts",
            "tests",
            "aegis.py",
            "run_aegis.py",
            "demo_pipeline.py",
        ],
        [
            "ruff",
            "format",
            "--check",
            "aegis",
            "scripts",
            "tests",
            "aegis.py",
            "run_aegis.py",
            "demo_pipeline.py",
        ],
        ["mypy"],
    ):
        subprocess.run([str(args.quality_python), "-m", *command], cwd=ROOT, check=True)
    return {
        **current,
        "application_version": version,
        "status": "PASS",
        "scope": "Source release checks only; not production deployment acceptance",
        "tests": {
            "passed": len(cases) - len(list(root.iter("skipped"))),
            "skipped": len(list(root.iter("skipped"))),
            "failed": 0,
        },
        "critical_coverage": actual,
        "artifacts": {p.name: sha256(p) for p in (args.junit, args.coverage, args.package)},
        "package": package,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "check", choices=("encoding", "versions", "coverage", "snapshot", "release")
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--junit", type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--quality-python", type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    if args.check == "release" and not all(
        (args.snapshot, args.junit, args.coverage, args.package)
    ):
        parser.error("release requires --snapshot, --junit, --coverage and --package")
    if args.check == "coverage" and not args.coverage:
        parser.error("coverage requires --coverage")
    result = {
        "encoding": encoding_check,
        "versions": versions_check,
        "coverage": lambda: coverage_check(args.coverage),
        "snapshot": snapshot,
        "release": lambda: release_gate(args),
    }[args.check]()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
