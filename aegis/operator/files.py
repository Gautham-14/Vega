from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from .common import (
    EXCLUDED_DIRS,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_IMPORT_BYTES,
    MAX_JSON_BYTES,
    PRIVATE_NAMES,
    PRIVATE_SUFFIXES,
    SECRET,
    CLIError,
    no_links,
    restrict_permissions,
    segment,
)


def json_file(path):
    path = no_links(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise CLIError("JSON request file exceeds 2 MB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise CLIError("Request file must contain valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise CLIError("Request JSON must be an object")
    return value


def private_path(path):
    return (
        any(
            part.lower() in EXCLUDED_DIRS
            or part.lower() in PRIVATE_NAMES
            or part.lower().startswith(".env.")
            for part in path.parts
        )
        or path.suffix.lower() in PRIVATE_SUFFIXES
    )


def import_files(paths):
    """Read explicitly named files/directory, with bounded UTF-8 input."""
    if not paths:
        raise CLIError("Name a directory or one or more UTF-8 files")
    originals = [no_links(p) for p in paths]
    directories = [p for p in originals if p.is_dir()]
    if directories and len(originals) != 1:
        raise CLIError("Import one directory or a list of explicit files")
    files, skipped, seen = {}, [], set()
    total = 0
    if directories:
        root = directories[0]
        candidates = []
        visited = 0

        def unreadable(error):
            raise CLIError(
                "Import inventory could not be completely read; nothing was imported"
            ) from error

        for current, dirs, names in os.walk(root, followlinks=False, onerror=unreadable):
            visited += 1 + len(dirs) + len(names)
            if visited > 4096:
                raise CLIError(
                    "Import exceeds the directory entry budget; name a smaller directory"
                )
            for name in list(dirs):
                child = Path(current) / name
                try:
                    no_links(child)
                    allowed = not private_path(child.relative_to(root))
                except CLIError:
                    allowed = False
                if not allowed:
                    dirs.remove(name)
                    skipped.append(str(child.relative_to(root)) + "/")
            for name in sorted(names):
                child = Path(current) / name
                relative = child.relative_to(root)
                try:
                    no_links(child)
                    allowed = not private_path(relative)
                except CLIError:
                    allowed = False
                if not allowed:
                    skipped.append(relative.as_posix())
                    continue
                candidates.append((child, relative.as_posix()))
                if len(candidates) > MAX_FILES:
                    raise CLIError(
                        f"Import exceeds {MAX_FILES} files. Name fewer files; nothing was imported."
                    )
    else:
        if any(not path.is_file() for path in originals):
            raise CLIError("Every import path must be an existing regular file")
        root = Path(os.path.commonpath([str(p.parent) for p in originals]))
        candidates = [(p, p.relative_to(root).as_posix()) for p in originals]
    if len(candidates) > MAX_FILES:
        raise CLIError(f"Import exceeds {MAX_FILES} files. Name fewer files; nothing was imported.")
    for path, name in sorted(candidates, key=lambda pair: pair[1]):
        if private_path(Path(name)) or private_path(path):
            raise CLIError(f"Private configuration cannot be imported: {name}")
        no_links(path)
        if not path.is_file():
            raise CLIError(f"Not a regular file: {name}")
        if name.casefold() in seen:
            raise CLIError("Import paths conflict on a case-insensitive filesystem")
        seen.add(name.casefold())
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise CLIError(f"File exceeds 128 KB: {name}; nothing was imported")
        total += len(raw)
        if total > MAX_IMPORT_BYTES:
            raise CLIError("Import exceeds 512 KB; nothing was imported")
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            raise CLIError(f"Not UTF-8 text: {name}; name only text files") from None
        if "\x00" in text:
            raise CLIError(f"Binary file cannot be imported: {name}")
        if SECRET.search(text):
            raise CLIError(f"Secret-like content detected in {name}; remove it before import")
        files[name] = text
    if not files:
        raise CLIError("No eligible text files found")
    return files, skipped


def export_patch(client, task_id, approval_id, destination):
    destination = no_links(destination)
    if destination.exists():
        raise CLIError("Export destination already exists; choose a new file")
    if not destination.parent.is_dir():
        raise CLIError("Export destination directory does not exist")
    result = client.call(
        f"/coding/tasks/{segment(task_id)}/export", "POST", {"approval_id": approval_id}
    )
    if not isinstance(result.get("patch"), str):
        raise CLIError("Server did not return a patch")
    no_links(destination)
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        restrict_permissions(destination)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = None
            stream.write(result["patch"])
    finally:
        if fd is not None:
            os.close(fd)
    return {
        "exported": str(destination),
        "bytes": len(result["patch"].encode("utf-8")),
        "classification": result.get("classification"),
    }


def export_media(client, task_id, approval_id, filename):
    destination = no_links(filename)
    if destination.exists() or not destination.parent.is_dir():
        raise CLIError("Choose a new export file in an existing local directory")
    response = client.call(
        f"/media/tasks/{segment(task_id)}/export", "POST", {"approval_id": approval_id}
    )
    result = response["result"]
    digest = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    if digest != response.get("result_hash"):
        raise CLIError("Media result hash does not match the reviewed output")
    if result.get("images"):
        if len(result["images"]) != 1 or destination.suffix.lower() != ".png":
            raise CLIError("Image export requires one image and a .png destination")
        item = result["images"][0]
        raw = base64.b64decode(item["data"], validate=True)
        if (
            not raw.startswith(b"\x89PNG\r\n\x1a\n")
            or len(raw) > 2_000_000
            or hashlib.sha256(raw).hexdigest() != item["sha256"]
        ):
            raise CLIError("Export image failed integrity checks")
    else:
        if destination.suffix.lower() != ".txt" or not isinstance(result.get("answer"), str):
            raise CLIError("Vision answer export requires a .txt destination")
        raw = result["answer"].encode("utf-8")
    no_links(destination)
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        restrict_permissions(destination)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(raw)
    finally:
        if fd is not None:
            os.close(fd)
    return {"exported": str(destination), "bytes": len(raw), "result_hash": response["result_hash"]}
