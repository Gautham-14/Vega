"""Explicitly pin the owner's three local GGUF models; no downloads or inference."""

import argparse
import json
from pathlib import Path

from aegis.models.local_runtime import CONFIG_DEFAULT, file_hash
from aegis.security.private_files import no_links, restrict_permissions

MODELS = [
    ("llama-general", "text", "Llama-3.2-1B-Instruct-Q4_K_M.gguf", None, 4096, 2048),
    ("qwen-coder", "code", "qwen2.5-coder-0.5b-instruct-q4_k_m.gguf", None, 8192, 1536),
    (
        "smol-vision",
        "vision",
        "SmolVLM-500M-Instruct-Q8_0.gguf",
        "mmproj-SmolVLM-500M-Instruct-Q8_0.gguf",
        4096,
        2048,
    ),
]


def configure(directory, executable, output, *, port=8089, threads=6):
    directory = no_links(directory)
    executable = no_links(executable)
    output = no_links(output)
    models = []
    for identity, role, filename, projector, context, memory in MODELS:
        path = no_links(directory / filename)
        projection = no_links(directory / projector) if projector else None
        for artifact in (path, projection):
            if artifact is not None:
                with artifact.open("rb") as stream:
                    if stream.read(4) != b"GGUF":
                        raise ValueError("Invalid GGUF header: " + artifact.name)
        models.append(
            {
                "id": identity,
                "role": role,
                "path": str(path),
                "sha256": file_hash(path),
                "projector": str(projection) if projection else None,
                "projector_sha256": file_hash(projection) if projection else None,
                "context_tokens": context,
                "memory_mib": memory,
            }
        )
    files = {
        path.name: file_hash(no_links(path))
        for path in executable.parent.iterdir()
        if path.is_file() and path.suffix.lower() in {".dll", ".exe"}
    }
    value = {
        "schema": 1,
        "runtime": str(executable),
        "runtime_files": files,
        "port": port,
        "threads": threads,
        "models": models,
        "acquisition": {
            "source": "operator-supplied local artifacts",
            "model_publisher_verified": False,
            "production_accepted": False,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    restrict_permissions(output.parent, directory=True)
    with output.open("x", encoding="utf-8") as stream:
        restrict_permissions(output)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "configuration": str(output),
                "models": [item["id"] for item in models],
                "inference_calls": 0,
            }
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--output", type=Path, default=CONFIG_DEFAULT)
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--threads", type=int, default=6)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 1 <= args.threads <= 32:
        parser.error("Invalid local runtime resources")
    configure(args.directory, args.executable, args.output, port=args.port, threads=args.threads)


if __name__ == "__main__":
    main()
