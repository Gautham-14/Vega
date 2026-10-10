"""Pinned, offline llama.cpp lifecycle. Startup advertises models but does not load them."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from aegis.security.private_files import no_links, restrict_permissions

CONFIG_DEFAULT = Path(__file__).resolve().parents[2] / ".runtime" / "local-models.json"
KEY_ENV = "AEGIS_PROVIDER_LOCAL_MODELS_API_KEY"
CONFIG_HASH_ENV = "AEGIS_LOCAL_MODELS_CONFIG_HASH"
_active_runtime = None


def reclaimable_memory_mib():
    """Only this launcher's model children; never count unrelated processes.

    The serial chat dispatcher permits the one-model router to unload its idle
    model before loading another. Working-set reclaim is an estimate, not VRAM.
    """
    if _active_runtime is None or _active_runtime.process is None:
        return 0
    import psutil

    try:
        if _active_runtime.process.poll() is not None:
            return 0
        children = psutil.Process(_active_runtime.process.pid).children(recursive=True)
        return int(sum(child.memory_info().rss for child in children) / 1024**2)
    except psutil.Error:
        return 0


def configuration_hash(settings):
    return hashlib.sha256(
        json.dumps(settings, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def configuration():
    raw = os.environ.get("AEGIS_LOCAL_MODELS_CONFIG")
    path = Path(raw) if raw else CONFIG_DEFAULT
    if raw == "" or not path.exists():
        return None
    path = no_links(path)
    if path.stat().st_size > 65536:
        raise ValueError("Local model configuration exceeds its limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        set(value)
        != {"schema", "runtime", "runtime_files", "port", "threads", "models", "acquisition"}
        or value["schema"] != 1
    ):
        raise ValueError("Unsupported local model configuration")
    if (
        type(value["port"]) is not int
        or not 1024 <= value["port"] <= 65535
        or type(value["threads"]) is not int
        or not 1 <= value["threads"] <= 32
    ):
        raise ValueError("Invalid local runtime resources")
    value["runtime"] = no_links(value["runtime"])
    if not value["runtime"].is_file():
        raise ValueError("Configured llama-server executable is missing: " + str(value["runtime"]))
    if not isinstance(value["runtime_files"], dict) or not 1 <= len(value["runtime_files"]) <= 128:
        raise ValueError(
            "Local runtime configuration needs 1-128 pinned executable/dependency entries"
        )
    if value["runtime"].name not in value["runtime_files"]:
        raise ValueError("The server executable needs a pinned inventory entry")
    for name, pin in value["runtime_files"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", name) or not re.fullmatch(
            r"[a-f0-9]{64}", str(pin)
        ):
            raise ValueError("Invalid local runtime inventory")
        if not no_links(value["runtime"].parent / name).is_file():
            raise ValueError("Local runtime dependency is missing")
    if not isinstance(value["models"], list) or not 1 <= len(value["models"]) <= 16:
        raise ValueError("Configure 1-16 local models")
    identities = set()
    for model in value["models"]:
        if set(model) != {
            "id",
            "role",
            "path",
            "sha256",
            "projector",
            "projector_sha256",
            "context_tokens",
            "memory_mib",
        }:
            raise ValueError("Invalid local model fields")
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", str(model["id"]))
            or model["id"] in identities
            or model["role"] not in {"text", "code", "vision"}
        ):
            raise ValueError("Invalid or duplicate local model identity")
        identities.add(model["id"])
        if (
            type(model["context_tokens"]) is not int
            or not 4096 <= model["context_tokens"] <= 131072
            or type(model["memory_mib"]) is not int
            or not 512 <= model["memory_mib"] <= 131072
        ):
            raise ValueError("Invalid local model resource estimate")
        for field, pin in (("path", "sha256"), ("projector", "projector_sha256")):
            if field == "projector" and model[field] is None and model[pin] is None:
                continue
            if (
                not isinstance(model[field], str)
                or not Path(model[field]).is_absolute()
                or not re.fullmatch(r"[a-f0-9]{64}", str(model[pin]))
            ):
                raise ValueError("Local model artifacts need absolute paths and SHA-256 pins")
            model[field] = no_links(model[field])
            if not model[field].is_file() or model[field].suffix != ".gguf":
                raise ValueError("Local model artifact is not a regular GGUF file")
        if (model["role"] == "vision") != (model["projector"] is not None):
            raise ValueError("Vision models require their separately pinned projector")
    return value


def verify_inventory(settings):
    for name, pin in settings["runtime_files"].items():
        if file_hash(no_links(settings["runtime"].parent / name)) != pin:
            raise ValueError("Local runtime digest mismatch: " + name)
    for model in settings["models"]:
        for field, pin in (("path", "sha256"), ("projector", "projector_sha256")):
            if model[field] is not None and file_hash(no_links(model[field])) != model[pin]:
                raise ValueError("Local model digest mismatch: " + model["id"])


def spec(settings, model):
    return {
        "provider": "local-" + model["id"],
        "protocol": "openai-compatible",
        "engine": "llama.cpp",
        "endpoint": f"http://127.0.0.1:{settings['port']}",
        "model": model["id"],
        "digest": model["sha256"],
        "digest_verification": "CUSTODIAN_ASSERTED",
        "local_only": True,
        "api_key_env": KEY_ENV,
        "max_tokens": 512,
        "timeout_seconds": 120,
        "max_response_bytes": 1_000_000,
        "context_tokens": model["context_tokens"],
        "vision": model["role"] == "vision",
        "structured_output": "json_schema",
    }


class LocalRuntime:
    def __init__(self, settings=None):
        self.settings = configuration() if settings is None else settings
        self.process = None
        self.temporary = None
        self.previous_key = None
        self.previous_hash = None

    def __enter__(self):
        if self.settings is None:
            return self
        try:
            self.start()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def start(self):
        global _active_runtime
        settings = self.settings
        verify_inventory(settings)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", settings["port"]))
        self.temporary = tempfile.TemporaryDirectory(
            prefix="aegis-model-server-", dir=Path(tempfile.gettempdir()).resolve()
        )
        work = no_links(self.temporary.name)
        restrict_permissions(work, directory=True)
        key = secrets.token_urlsafe(32)
        credential = work / "api-key.txt"
        credential.write_text(key, encoding="ascii")
        restrict_permissions(credential)
        presets = configparser.ConfigParser(interpolation=None)
        presets["*"] = {
            "n-gpu-layers": "0",
            "parallel": "1",
            "cache-ram": "0",
            "load-on-startup": "false",
            "no-cache-prompt": "true",
            "no-slots": "true",
            "offline": "true",
            "threads": str(settings["threads"]),
            "repeat-penalty": "1.1",
        }
        for model in settings["models"]:
            presets[model["id"]] = {
                "model": str(model["path"]),
                "ctx-size": str(model["context_tokens"]),
            }
            if model["projector"] is not None:
                presets[model["id"]]["mmproj"] = str(model["projector"])
        preset_file = work / "models.ini"
        with preset_file.open("w", encoding="utf-8") as output:
            output.write("version = 1\n")
            presets.write(output)
        restrict_permissions(preset_file)
        environment = {
            "PATH": str(settings["runtime"].parent),
            "HF_HUB_OFFLINE": "1",
            "LLAMA_ARG_OFFLINE": "1",
            "LLAMA_CACHE": str(work / "cache"),
        }
        for name in ("SystemRoot", "WINDIR", "TEMP", "TMP"):
            if name in os.environ:
                environment[name] = os.environ[name]
        self.process = subprocess.Popen(
            [
                str(settings["runtime"]),
                "--models-preset",
                str(preset_file),
                "--models-max",
                "1",
                "--host",
                "127.0.0.1",
                "--port",
                str(settings["port"]),
                "--api-key-file",
                str(credential),
                "--offline",
                "--no-webui",
                "--no-slots",
                "--log-disable",
            ],
            cwd=settings["runtime"].parent,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.previous_key = os.environ.get(KEY_ENV)
        self.previous_hash = os.environ.get(CONFIG_HASH_ENV)
        os.environ[KEY_ENV] = key
        os.environ[CONFIG_HASH_ENV] = configuration_hash(settings)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Pinned local model router exited during startup")
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{settings['port']}/v1/models",
                    headers={"Authorization": "Bearer " + key},
                )
                with opener.open(request, timeout=1) as response:
                    listing = json.loads(response.read(65536))
                if {item["id"] for item in listing["data"]} != {
                    model["id"] for model in settings["models"]
                }:
                    raise RuntimeError("Local runtime model aliases differ from inventory")
                print(
                    "Local models ready for on-demand routing: "
                    + ", ".join(model["id"] for model in settings["models"]),
                    flush=True,
                )
                _active_runtime = self
                return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("Local model router startup timed out")

    def __exit__(self, *args):
        global _active_runtime
        if _active_runtime is self:
            _active_runtime = None
        if self.process is not None:
            from aegis.vm.host import stop

            stop(self.process)
            self.process = None
            if self.previous_key is None:
                os.environ.pop(KEY_ENV, None)
            else:
                os.environ[KEY_ENV] = self.previous_key
            if self.previous_hash is None:
                os.environ.pop(CONFIG_HASH_ENV, None)
            else:
                os.environ[CONFIG_HASH_ENV] = self.previous_hash
        if self.temporary is not None:
            self.temporary.cleanup()
            self.temporary = None
