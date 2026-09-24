"""Finite tool authority. No shell, host paths, imports, or generated-code execution."""
import ast
import difflib
import re
import json

from pydantic import BaseModel, ConfigDict, Field
from aegis.control import data, store
from aegis.storage.paths import safe_filename

MAX_BYTES = 512_000
TOOLS = {
    "repository.read": {"path": "relative path"},
    "repository.search": {"query": "literal text or Python symbol"},
    "repository.edit": {"path": "existing relative path", "before": "unique exact text", "after": "replacement"},
    "repository.create": {"path": "new relative path", "content": "UTF-8 text"},
    "repository.delete": {"path": "existing relative path"},
    "repository.diff": {},
    "python.syntax": {},
    "sandbox.test": {},
    "sandbox.lint": {},
    "sandbox.typecheck": {},
}
MODES = {"ASK": ["repository.read", "repository.search"],
         "PLAN": ["repository.read", "repository.search"], "EXECUTE": list(TOOLS)}
SECRET = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|"
                    r"\bgh[pousr]_[A-Za-z0-9]{20,}|(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]", re.I)
HOST_SECRET = re.compile(r"~[/\\]\.ssh|/etc/(?:passwd|shadow)|(?:read|upload|send).{0,60}(?:credentials|private keys)", re.I)


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict = Field(default_factory=dict)


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    message: str = Field(max_length=16000)
    actions: list[Action] = Field(default_factory=list, max_length=12)


def path_name(value):
    if not isinstance(value, str) or len(value) > 240 or "\\" in value:
        raise store.Denied("UNAUTHORIZED_FILE_ACCESS", "Use a repository-relative path")
    parts = value.split("/")
    try:
        for part in parts:
            safe_filename(part)
    except ValueError:
        raise store.Denied("UNAUTHORIZED_FILE_ACCESS", "Unsafe repository path") from None
    if any(p.lower() in {".git", ".ssh", ".aws", ".env"} or p.lower().startswith(".env.") for p in parts):
        raise store.Denied("UNAUTHORIZED_FILE_ACCESS", "Private configuration paths cannot enter coding context")
    return value


def inspect_text(text, compartments):
    data.tripwire(text, compartments)
    if SECRET.search(text) or HOST_SECRET.search(text):
        raise store.Denied("CONTEXT_SECRET_OR_HOST_PATH", "Secret-like content or a host-secret instruction was withheld")
    scan = data.context_check(text, compartments)
    if scan["action"] in {"BLOCK", "QUARANTINE"}:
        raise store.Denied("CONTEXT_FIREWALL_DETECTION", "Untrusted content failed the context firewall")


def validate_files(files):
    if not 1 <= len(files) <= 64 or sum(len(v.encode()) for v in files.values()) > MAX_BYTES:
        raise ValueError("Import 1-64 UTF-8 text files totaling at most 512 KB")
    seen = set()
    for path, content in files.items():
        path_name(path)
        folded = path.casefold()
        if folded in seen or any(folded.startswith(s + "/") or s.startswith(folded + "/") for s in seen):
            raise ValueError("Repository paths conflict on a case-insensitive filesystem")
        seen.add(folded)
        if "\x00" in content or len(content.encode()) > 128_000:
            raise ValueError("Each file must be text and at most 128 KB")


def search(files, query):
    """Only the authorized, sanitized task snapshot reaches retrieval."""
    from aegis.coding.retrieval import search as retrieve
    return retrieve(files, query)


def diff(before, after):
    # Explicit newline markers keep patches valid even for files without final LF.
    chunks = []
    for path in sorted(set(before) | set(after)):
        if path in before and path in after and before[path] == after[path]:
            continue
        chunks.append(f"diff --git {json.dumps('a/' + path, ensure_ascii=False)} {json.dumps('b/' + path, ensure_ascii=False)}\n")
        # Unified diff has no hunk for an empty file. Preserve structural changes
        # in a Git-compatible patch so they still require review and export.
        if path not in before:
            chunks.append("new file mode 100644\n")
            if after[path] == "":
                chunks.append("index 0000000..e69de29\n")
        elif path not in after:
            chunks.append("deleted file mode 100644\n")
            if before[path] == "":
                chunks.append("index e69de29..0000000\n")
        for line in difflib.unified_diff(before.get(path, "").splitlines(keepends=True), after.get(path, "").splitlines(keepends=True),
                                         fromfile="a/" + path if path in before else "/dev/null",
                                         tofile="b/" + path if path in after else "/dev/null"):
            chunks.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(chunks)


def dispatch(action, files, original, mode, compartments):
    tool, args = action.tool, action.arguments
    if tool not in MODES[mode]:
        code = "SANDBOX_UNAVAILABLE" if tool in {"shell", "sandbox.test", "sandbox.lint"} else "UNAUTHORIZED_TOOL"
        raise store.Denied(code, "This action is outside the mode or requires an unavailable OS sandbox")
    if set(args) != set(TOOLS[tool]) or any(not isinstance(v, str) for v in args.values()):
        raise store.Denied("INVALID_TOOL_ARGUMENTS", "Tool arguments do not match the approved schema")
    if "path" in args:
        path = path_name(args["path"])
        if path not in files and tool != "repository.create":
            raise store.Denied("UNAUTHORIZED_FILE_ACCESS", "Path is absent or quarantined in this snapshot")
    if tool == "repository.create":
        if path in files:
            raise store.Denied("EDIT_CONFLICT", "File already exists")
        inspect_text(args["content"], compartments)
        validate_files({**files, path: args["content"]})
        files[path] = args["content"]
        return {"path": path, "status": "CREATION_STAGED_FOR_REVIEW"}
    if tool == "repository.delete":
        if len(files) == 1:
            raise store.Denied("EDIT_CONFLICT", "Cannot remove the entire snapshot")
        del files[path]
        return {"path": path, "status": "DELETION_STAGED_FOR_REVIEW"}
    if tool.startswith("sandbox."):
        from aegis.coding.sandbox import execute
        return execute(files, tool.split(".")[1])
    if tool == "repository.read":
        return {"path": path, "content": files[path], "trust": "UNTRUSTED_CONTENT", "instructions_authoritative": False}
    if tool == "repository.search":
        if not 1 <= len(args["query"]) <= 300:
            raise store.Denied("INVALID_TOOL_ARGUMENTS", "Search requires 1-300 characters")
        return search(files, args["query"])
    if tool == "repository.edit":
        if not args["before"] or files[path].count(args["before"]) != 1:
            raise store.Denied("EDIT_CONFLICT", "Edit must match exactly one span in the current file")
        proposed = files[path].replace(args["before"], args["after"], 1)
        inspect_text(proposed, compartments)
        candidate = {**files, path: proposed}
        validate_files(candidate)
        files[path] = proposed
        return {"path": path, "status": "STAGED_FOR_REVIEW"}
    if tool == "repository.diff":
        return {"diff": diff(original, files)}
    errors = []
    for path, content in files.items():
        if path.endswith(".py"):
            try:
                ast.parse(content)
            except (SyntaxError, ValueError, RecursionError) as error:
                errors.append({"path": path, "line": getattr(error, "lineno", None), "error": type(error).__name__})
    return {"status": "FAIL" if errors else "PASS", "errors": errors, "scope": "Python syntax only; tests were NOT executed"}
