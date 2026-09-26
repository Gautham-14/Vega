"""Bounded retrieval over an already authorized, sanitized in-memory snapshot.

Lexical TF-IDF is not semantic retrieval. Optional grammars are installed Python
packages, never downloaded. Embeddings require a pinned local safetensors model;
model and vector objects live only for this search, with no cross-task index.
"""
import ast
from collections import Counter
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat

from aegis.control import store
from aegis.storage.paths import safe_filename
from aegis.coding.tokenizer import get_tokens
from aegis.coding.embedding import MatryoshkaEmbeddingSystem

MAX_FILES = 64
MAX_BYTES = 512_000
MAX_CHUNKS = 384
CHUNK_CHARS = 2048
MAX_MODEL_BYTES = 1_073_741_824
GRAMMARS = {
    ".js": ("javascript", "tree_sitter_javascript", "language"),
    ".jsx": ("javascript", "tree_sitter_javascript", "language"),
    ".ts": ("typescript", "tree_sitter_typescript", "language_typescript"),
    ".tsx": ("tsx", "tree_sitter_typescript", "language_tsx"),
    ".c": ("c", "tree_sitter_c", "language"),
    ".h": ("c", "tree_sitter_c", "language"),
    ".cpp": ("cpp", "tree_sitter_cpp", "language"),
    ".hpp": ("cpp", "tree_sitter_cpp", "language"),
    ".rs": ("rust", "tree_sitter_rust", "language"),
    ".go": ("go", "tree_sitter_go", "language"),
}
SYMBOL_NODES = {"function_declaration", "function_definition", "class_declaration", "class_definition",
                "method_definition", "method_declaration", "function_item", "struct_item", "enum_item",
                "trait_item", "interface_declaration", "type_alias_declaration", "type_spec"}
SAFE_MODULES = {"sentence_transformers.models.Transformer", "sentence_transformers.models.Pooling",
                "sentence_transformers.models.Normalize"}


def installed(module):
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def version(distribution):
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "UNAVAILABLE"


def _model_root(directory):
    # Reject network shares and relative model names before filesystem access.
    if not isinstance(directory, str) or not directory or directory.startswith(("\\\\", "//")):
        raise ValueError("An absolute local model directory is required")
    path = Path(directory)
    if not path.is_absolute() or path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise ValueError("The model directory must be a real local directory")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Model directory ancestors cannot contain links or reparse points")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("The model directory is unavailable")
    return resolved


def model_digest(directory):
    """SHA-256 of canonical sorted {path,bytes,sha256} entries for every file.

    This reads existing files only. It returns no filenames or model content.
    Symlinks, junctions, special files, code, pickle weights and oversized trees
    are rejected. A deployment must separately protect model files from writes.
    """
    root = _model_root(directory)
    entries, total, visited = [], 0, 0
    for parent, directories, files in os.walk(root, followlinks=False):
        visited += 1
        if visited > 128:
            raise ValueError("Model tree exceeds directory limit")
        for name in sorted(directories + files):
            path = Path(parent) / name
            details = path.lstat()
            if (path.is_symlink() or getattr(path, "is_junction", lambda: False)()
                    or getattr(details, "st_file_attributes", 0) & 0x400
                    or not path.resolve().is_relative_to(root)):
                raise ValueError("Model links are not permitted")
            if stat.S_ISDIR(details.st_mode):
                continue
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("Model special files are not permitted")
            if path.suffix.lower() in {".py", ".pyc", ".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt"}:
                raise ValueError("Only data and safetensors weights are permitted")
            total += details.st_size
            if total > MAX_MODEL_BYTES or len(entries) >= 256:
                raise ValueError("Model tree exceeds size limit")
            hashed, size = hashlib.sha256(), 0
            with path.open("rb") as stream:
                while block := stream.read(1_048_576):
                    size += len(block)
                    if size > details.st_size:
                        raise ValueError("Model changed while hashing")
                    hashed.update(block)
            after = path.stat()
            if size != details.st_size or after.st_mtime_ns != details.st_mtime_ns or after.st_size != details.st_size:
                raise ValueError("Model changed while hashing")
            entries.append({"path": path.relative_to(root).as_posix(), "bytes": size, "sha256": hashed.hexdigest()})
    if not entries or not any(item["path"].endswith(".safetensors") for item in entries):
        raise ValueError("Local safetensors weights are required")
    return store.digest(sorted(entries, key=lambda item: item["path"]))


def _validate_model_layout(root):
    # The optional loader may import module types from modules.json. Permit only
    # the standard safe, local Transformer/Pooling/Normalize pipeline.
    manifest = root / "modules.json"
    if not manifest.is_file() or manifest.stat().st_size > 32000:
        raise ValueError("A bounded standard sentence-transformers modules.json is required")
    modules = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(modules, list) or not 1 <= len(modules) <= 8:
        raise ValueError("Invalid embedding module manifest")
    for module in modules:
        if not isinstance(module, dict) or module.get("type") not in SAFE_MODULES:
            raise ValueError("Custom embedding modules are disabled")
        relative = module.get("path")
        if not isinstance(relative, str) or "\\" in relative or Path(relative).is_absolute():
            raise ValueError("Embedding module paths must be local")
        if any(part in {"..", "."} for part in relative.split("/") if part):
            raise ValueError("Embedding module path escapes model directory")
        if not (root / relative).resolve().is_relative_to(root):
            raise ValueError("Embedding module path escapes model directory")
    # Avoid shard-index references to files outside the pinned directory.
    for index in root.rglob("*.safetensors.index.json"):
        if index.stat().st_size > 1_000_000:
            raise ValueError("Embedding weight index exceeds limit")
        mapping = json.loads(index.read_text(encoding="utf-8")).get("weight_map", {})
        if not isinstance(mapping, dict):
            raise ValueError("Invalid weight index")
        for target in mapping.values():
            if not isinstance(target, str) or Path(target).name != target or "\\" in target:
                raise ValueError("Weight shards must be adjacent to their index")
            if not (index.parent / target).is_file() or not target.endswith(".safetensors"):
                raise ValueError("Weight shard is unavailable")


def _embedding_configuration():
    directory = os.environ.get("AEGIS_EMBEDDING_MODEL_DIR", "")
    expected = os.environ.get("AEGIS_EMBEDDING_DIGEST", "")
    value = {"requested": bool(directory or expected), "enabled": False, "status": "NOT_CONFIGURED",
             "model_digest": expected if re.fullmatch(r"[a-f0-9]{64}", expected) else None,
             "model_location_hash": hashlib.sha256(directory.encode()).hexdigest() if directory else None,
             "package_version": version("sentence-transformers"), "device": "cpu",
             "local_files_only": True, "trust_remote_code": False, "persistent_vectors": False}
    if not value["requested"]:
        return value
    if not directory or value["model_digest"] is None:
        value["status"] = "INCOMPLETE_CONFIGURATION"
        return value
    try:
        root = _model_root(directory)
        if not installed("sentence_transformers"):
            value["status"] = "DEPENDENCY_UNAVAILABLE"
            return value
        if model_digest(str(root)) != expected:
            value["status"] = "MODEL_DIGEST_MISMATCH"
            return value
        _validate_model_layout(root)
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        value["status"] = "LOCAL_MODEL_INVALID"
        return value
    value.update(enabled=True, status="PINNED_LOCAL_MODEL")
    return value


def configuration():
    grammar_runtime = installed("tree_sitter")
    structural = {"python": {"backend": "PYTHON_AST"}}
    for language, module, _ in GRAMMARS.values():
        available = grammar_runtime and installed(module)
        structural[language] = {"backend": "TREE_SITTER" if available else "UNAVAILABLE",
                                "package_version": version(module.replace("_", "-")) if available else None}
    embedding = _embedding_configuration()
    return {"provider": "local-hybrid-v1", "lexical": "TF_IDF_WITH_EXACT_MATCH", "structural": structural,
            "tree_sitter_version": version("tree-sitter") if grammar_runtime else None,
            "semantic_enabled": embedding["enabled"], "semantic_status": embedding["status"], "embedding": embedding,
            "automatic_downloads": False, "cache_scope": "SEARCH_CALL_MEMORY_ONLY",
            "limits": {"files": MAX_FILES, "bytes": MAX_BYTES, "chunks": MAX_CHUNKS, "chunk_characters": CHUNK_CHARS},
            "scope": "Caller supplies authorized sanitized files. Local model files are hashed; host memory isolation is not attested."}


def _validate_snapshot(files, query):
    if not isinstance(query, str) or not 1 <= len(query) <= 300 or not query.strip():
        raise ValueError("Search requires 1-300 nonblank characters")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Search requires a bounded authorized snapshot")
    total, seen = 0, set()
    for path, content in files.items():
        if not isinstance(path, str) or len(path) > 240 or "\\" in path or not isinstance(content, str):
            raise ValueError("Search requires relative UTF-8 text paths")
        for part in path.split("/"):
            safe_filename(part)
            if part.lower() in {".git", ".ssh", ".aws", ".env"} or part.lower().startswith(".env."):
                raise ValueError("Private configuration paths are excluded from retrieval")
        key = path.casefold()
        if key in seen or any(key.startswith(other + "/") or other.startswith(key + "/") for other in seen):
            raise ValueError("Search paths conflict")
        seen.add(key)
        size = len(content.encode())
        total += size
        if size > 128_000 or total > MAX_BYTES or "\x00" in content:
            raise ValueError("Search snapshot exceeds text limits")


def _tokens(text):
    # Lexical identifier splitting, separate from model-native token IDs.
    return get_tokens(text)


def symbols(path, content):
    if path.lower().endswith(".py"):
        try:
            parsed = ast.parse(content)
            found = [{"name": node.name, "line": node.lineno, "kind": type(node).__name__}
                     for node in ast.walk(parsed) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
            return found[:1024], "PYTHON_AST"
        except (SyntaxError, ValueError, RecursionError):
            return [], "SYNTAX_ERROR"
    grammar = GRAMMARS.get(Path(path).suffix.lower())
    if not grammar or not installed("tree_sitter") or not installed(grammar[1]):
        return [], "UNAVAILABLE"
    try:
        runtime = importlib.import_module("tree_sitter")
        module = importlib.import_module(grammar[1])
        parser = runtime.Parser(runtime.Language(getattr(module, grammar[2])()))
        source = content.encode()
        root = parser.parse(source).root_node
        if root.has_error:
            return [], "SYNTAX_ERROR"
        stack, found, visited = [root], [], 0
        while stack and visited < 30000 and len(found) < 1024:
            node = stack.pop()
            visited += 1
            eligible = node.type in SYMBOL_NODES
            if node.type == "variable_declarator":
                value = node.child_by_field_name("value")
                eligible = value is not None and value.type in {"arrow_function", "function_expression"}
            if eligible:
                name = node.child_by_field_name("name")
                if name is not None:
                    found.append({"name": source[name.start_byte:name.end_byte].decode("utf-8")[:160],
                                  "line": node.start_point[0] + 1, "kind": node.type})
            stack.extend(reversed(node.named_children))
        return found, "TREE_SITTER" if not stack else "TREE_SITTER_LIMIT_REACHED"
    except (ImportError, OSError, ValueError, TypeError, AttributeError, RecursionError):
        return [], "PARSER_UNAVAILABLE"


def _chunks(files):
    result = []
    for path, content in sorted(files.items()):
        line = 1
        for start in range(0, len(content), CHUNK_CHARS):
            chunk = content[start:start + CHUNK_CHARS]
            result.append({"path": path, "line": line, "text": chunk})
            line += chunk.count("\n")
    if len(result) > MAX_CHUNKS:
        raise ValueError("Snapshot exceeds retrieval chunk limit")
    return result


def _semantic_scores(files, query, expected):
    chunks, texts, rows, system = _chunks(files), [], None, None
    try:
        if not chunks:
            return {}
        if _embedding_configuration() != expected:
            raise store.Denied("EMBEDDING_CONFIGURATION_CHANGED", "Pinned embedding configuration changed")
        root = _model_root(os.environ.get("AEGIS_EMBEDDING_MODEL_DIR", ""))
        system = MatryoshkaEmbeddingSystem(str(root), expected["model_digest"])
        texts = [query] + [item["text"] for item in chunks]
        # Preserve the trained output dimension by default.
        rows = system.encode(texts, dimensions=None)
        if len(rows) != len(texts) or not rows or not 1 <= len(rows[0]) <= 4096:
            raise ValueError("Invalid embedding output dimensions")
        dimensions = len(rows[0])
        if any(len(row) != dimensions or any(not isinstance(v, (int, float)) or not math.isfinite(v) for v in row) for row in rows):
            raise ValueError("Invalid embedding output")
        query_norm = math.sqrt(sum(v * v for v in rows[0]))
        scores = {}
        for chunk, vector in zip(chunks, rows[1:]):
            norm = math.sqrt(sum(v * v for v in vector))
            score = sum(a * b for a, b in zip(rows[0], vector)) / (query_norm * norm) if query_norm and norm else 0
            score = min(1.0, max(0.0, score))
            if score > scores.get(chunk["path"], (0, 1))[0]:
                scores[chunk["path"]] = (score, chunk["line"])
        if _embedding_configuration() != expected:
            raise store.Denied("EMBEDDING_CONFIGURATION_CHANGED", "Pinned embedding configuration changed during search")
        return scores
    except store.Denied:
        raise
    except Exception:
        # Do not echo source text, query, host paths or dependency exception text.
        raise store.Denied("EMBEDDING_UNAVAILABLE", "Pinned local embeddings could not run; no remote fallback was attempted") from None
    finally:
        texts.clear()
        chunks.clear()
        del rows, system


def search(files, query):
    """Return max-eight ranked matches; callers must authorize/quarantine first."""
    _validate_snapshot(files, query)
    profile = _embedding_configuration()
    if profile["requested"] and not profile["enabled"]:
        raise store.Denied("EMBEDDING_UNAVAILABLE", "Configured local embedding model is unavailable: " + profile["status"])
    counts = {path: Counter(_tokens(path + "\n" + content)) for path, content in files.items()}
    terms = set(_tokens(query))
    frequencies = {term: sum(term in count for count in counts.values()) for term in terms}
    weights = {term: math.log((1 + len(files)) / (1 + count)) + 1 for term, count in frequencies.items()}
    semantic = _semantic_scores(files, query, profile) if profile["enabled"] else {}
    result = []
    for path, content in files.items():
        discovered, structure = symbols(path, content)
        structural = [symbol for symbol in discovered if symbol["name"].casefold() in terms]
        lines = content.splitlines()
        exact = [index for index, line in enumerate(lines, 1) if query.casefold() in line.casefold()]
        lexical = sum((1 + math.log(counts[path][term])) * weights[term] for term in terms if counts[path][term])
        lexical /= math.sqrt(max(1, sum(counts[path].values())))
        semantic_score, semantic_line = semantic.get(path, (0, 1))
        score = 10 * len(structural) + 5 * bool(exact) + lexical + semantic_score
        if score <= 0:
            continue
        if exact:
            line = exact[0]
        elif structural:
            line = structural[0]["line"]
        elif semantic_score > lexical:
            line = semantic_line
        else:
            line = max(enumerate(lines, 1), key=lambda entry: len(terms.intersection(_tokens(entry[1]))),
                       default=(1, ""))[0]
        result.append({"path": path, "line": line, "score": round(score, 6), "symbols": structural[:20],
                       "excerpt": "\n".join(lines[max(0, line - 2):line + 5])[:2500],
                       "trust": "UNTRUSTED_CONTENT", "instructions_authoritative": False,
                       "retrieval": {"lexical": "TF_IDF_WITH_EXACT_MATCH", "structure": structure,
                                     "semantic": profile["enabled"], "semantic_score": round(semantic_score, 6)}})
    return sorted(result, key=lambda item: (-item["score"], item["path"]))[:8]
