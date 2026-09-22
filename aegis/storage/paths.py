"""Portable single-file names and containment checks for generated storage."""
import re
from pathlib import Path


def safe_filename(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 180
            or value in {".", ".."} or value[-1] in {".", " "}
            or re.search(r'[<>:"/\\|?*\x00-\x1f]', value)
            or re.match(r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", value, re.I)):
        raise ValueError("Expected a safe single filename without path components")
    return value


def contained_file(directory: Path, filename: str) -> Path:
    path = directory / safe_filename(filename)
    if path.is_symlink() or path.resolve().parent != directory.resolve():
        raise ValueError("File path escapes its storage directory")
    return path
