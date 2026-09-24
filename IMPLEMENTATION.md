# Aegis CLI and telemetry prototype

The current operating interface is `aegis_cli.py`, also launched by `gemini-cli/scripts/aegis.mjs`. The website is a read-only telemetry/audit client with cookie sign-in. This document supersedes the former browser-operated demonstration walkthrough.

## Identity and local setup

Run `python aegis_cli.py users roles` to list supported account IDs. The local administrator uses `users set <actor>` to provision/reset an account interactively. Passwords are scrypt-hashed with individual random salts; no password is accepted on command-line arguments. Eight failed sign-in attempts per client within five minutes trigger throttling. Successful low-role sign-in does not reset that counter.

A successful `/login <actor>` obtains an eight-hour opaque bearer session. Only its hash is stored on the server. CLI sessions are stored per canonical API origin in an owner-restricted file under `~/.aegis` (override with `AEGIS_CLIENT_DIR`). The browser uses an HttpOnly, SameSite=Strict cookie and stores no bearer token in web storage. `/logout`, expiry and administrator password reset revoke access. Role/compartment assignment comes from the server's fixed account roster; caller-supplied role headers cannot change authenticated identity.

The server and CLI default to `http://127.0.0.1:8000`. Use `--url http://127.0.0.1:8765/api` or `AEGIS_API_URL` to select another local runtime. Credentials never follow redirects or travel through an inherited HTTP proxy. The server validates Host and mutation Origin headers. Existing unscoped registries are limited to appropriate administrative roles once accounts exist.

This is local account authentication, not enterprise SSO. One fixed account exists per prototype identity. The trusted host administrator can reset accounts and read the local software keys; HSM/TPM identity, multiple users per role, TLS/LAN deployment and external identity integration remain deployment work.

## Coding workflow

Run `python aegis_cli.py` for an interactive shell. Commands below use shell syntax; omit the leading slash when calling the Python program directly. IDs in angle brackets are values returned by earlier commands.

1. As Data Owner: `/login data-owner`, then `/import ./sample --name "Sample repository"`. Import one directory or explicit UTF-8 files. The client reports excluded private/generated/link paths. Imports accept at most 64 files, 128,000 bytes each and 512,000 bytes total, PUBLIC or INTERNAL. Oversize/binary/secret-like inputs fail without silently truncating the import. The backend enforces relative paths, collision checks and encrypted storage.
2. As Operator: `/login operator`, then `/register reference` or `/register <provider-profile-id>`. This returns a Capsule and approval ID. The reference provider handles only the documented `validation.py` port fixture.
3. As Model Custodian: `/login model-custodian`, `/approve <approval-id> approve`. As Security Officer, independently approve the same ID. As Model Custodian, `/activate <capsule-id> <approval-id>`.
4. As Data Owner: `/lease --repo <repository-id> --capsule <capsule-id> --recipient operator --mode EXECUTE --minutes 15 --export`. Omit `--export` unless patch export is intended. ASK and PLAN cannot mutate source or execute tests.
5. As Operator: `/use <lease-id>`, then enter a prompt or `/run Fix valid_port`. The signed lease supplies the exact purpose, identity, mode, snapshot and tools. There is no auto-created lease or auto-approval.
6. `/diff <task-id>` returns the patch and review hash. `/apply <task-id> <diff-hash>` applies only that reviewed patch to encrypted task storage. Source checkout files remain unchanged.
7. `/export-request <task-id>` returns an approval ID. Data Owner and Security Officer inspect `/review <approval-id>` and independently approve it. The Operator runs `/export <task-id> <approval-id> ./approved.patch`. Existing destinations are never overwritten. Export permission and approval bind the task, lease, recipient and exact diff.
8. `/run --parent-task <applied-task-id> Review the updated code` continues from the applied snapshot under the same live lease. `/revert <task-id> <diff-hash>` restores its encrypted original checkpoint and invalidates export eligibility. `/close <task-id>` removes retained content; `/revoke <lease-id>` is a Data Owner action. Expiry is checked at every release and by a background sweep.

For a no-model demonstration, start the backend with `--demo` and use `/coding-fixture` as Data Owner instead of importing files. Accounts still require real login after provisioning. A new source measurement, runtime option, retrieval model or provider profile requires a newly approved Capsule. Restart the server after code updates before registering it.

Other commands: `/state`, `/control-state`, `/repositories`, `/leases`, `/tasks`, `/task <id>`, `/providers`, `/provider <id>`, `/sandbox`, `/telemetry`, `/receipts`, `/verify`, `/validate` and `/endpoints`. `/api GET /api/coding/capabilities` shows available tools and optional adapter status. The generic form `/api POST /api/<operation> request.json` submits a bounded JSON file to additional control-plane endpoints.

`/manifest-hash manifest.json` validates registry metadata and returns it with its canonical SHA-256. This is an offline CLI operation; save the returned JSON before submitting it to a registry endpoint.

## Local provider profiles

As Model Custodian, save a profile JSON file and run `/provider-add profile.json`. Example (replace model and digest with your reviewed local values):

```json
{
  "name": "Local coding server",
  "protocol": "openai-compatible",
  "engine": "llama.cpp",
  "endpoint": "http://127.0.0.1:8080/v1",
  "model": "reviewed-local-model",
  "digest": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
  "local_only": true
}
```

Use engine `ollama` with protocol `ollama`, or `llama.cpp`, `lm-studio`, `vllm`, `openai-compatible` with protocol `openai-compatible`. Ollama requires an explicit tag and rejects cloud/latest aliases. Numeric IPv4/IPv6 loopback endpoints only; no DNS, redirects, custom paths or automatic pulls. `/provider-probe <id>` performs an explicit local model inventory check. Profiles are immutable and signed; changes require a new profile and approved Capsule.

Optional fields: `max_tokens` (64–8192, default 4096), `timeout_seconds` (1–120, default 60), `max_response_bytes` (4096–1000000), and `api_key_env`. The last field names an existing server environment variable matching `AEGIS_PROVIDER_*_API_KEY`; it contains no key value. Unrelated host environment secrets cannot be referenced. Credentials are never returned or written to receipts.

Ollama compares its reported manifest digest before inference. Compatible servers expose model names rather than a verifiable weight digest: their digest is explicitly a custodian assertion. Neither proves independent runtime or weight integrity. Model-server network isolation is a deployment responsibility. Legacy `AEGIS_OLLAMA_MODEL`, `AEGIS_OLLAMA_DIGEST`, `AEGIS_OLLAMA_LOCAL_ONLY=1` remain supported by `/register ollama`.

The protocol implementations follow [Ollama chat](https://docs.ollama.com/api/chat), [Ollama tags](https://docs.ollama.com/api/tags), [llama.cpp server](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md), [LM Studio structured output](https://lmstudio.ai/docs/developer/openai-compat/structured-output), and [vLLM structured outputs](https://docs.vllm.ai/en/latest/features/structured_outputs/).

## Retrieval, Git and test execution

The default retrieval path ranks exact matches, lexical TF-IDF and Python AST symbols with line references. It receives only the authorized snapshot after quarantine. Lexical ranking is not semantic search. Installed `tree-sitter` and language grammar packages optionally add syntax-aware JS/TS/C/C++/Rust/Go extraction. Missing grammars are reported as unavailable, never downloaded.

Semantic retrieval requires an installed `sentence-transformers` package, `AEGIS_EMBEDDING_MODEL_DIR` pointing to an absolute local directory, and `AEGIS_EMBEDDING_DIGEST` from `aegis.coding.retrieval.model_digest(directory)`. The digest covers the canonical sorted file manifest and file hashes. The loader rejects code/pickle weights, links, custom modules and external shard paths, and uses CPU, safetensors, `local_files_only=True`, `trust_remote_code=False`. A configured-but-unavailable model fails closed. Vectors exist only during a search; physical memory erasure is not claimed. See [SentenceTransformer's local loading parameters](https://sbert.net/docs/package_reference/sentence_transformer/model.html) and [Tree-sitter bindings](https://github.com/tree-sitter/py-tree-sitter).

Set `AEGIS_GIT_WORKTREES=1` before starting the server to enable ephemeral Git checkpoints during reviewed apply. Aegis creates its own repository and detached worktree, disables user/system Git configuration, hooks, signing, network protocols and content filters, commits the bounded reviewed snapshot, records checkpoint hashes, and deletes the temporary repository before releasing success. No user `.git` directory is imported. Persistent undo uses encrypted task snapshots. This option temporarily materializes authorized source on disk; deletion does not prove forensic erasure.

Fixed `sandbox.test`, `sandbox.lint` and `sandbox.typecheck` tools become runnable only on Linux with Docker/runsc already installed, `AEGIS_SANDBOX_ENABLED=1` and `AEGIS_SANDBOX_IMAGE=sha256:<installed-image-id>`. The reviewed image must contain Python plus pytest/ruff/mypy as needed. Aegis never builds or pulls it. Containers use runsc, no network, no host mounts, read-only root, a non-root user, dropped capabilities, bounded memory/CPU/PIDs/output/time and temporary writable filesystems. Source arrives over stdin. Cleanup must be confirmed before a result is released. Model output and test output remain untrusted. Test PASS is bound to the tested file-map hash and becomes stale after any later edit.

Windows has no fallback to host test execution. Shell commands, dependency installs, network tools, arbitrary image tags and deployment remain denied. Configuring runsc is not evidence of isolation: independently run and record network, host-secret and cleanup adversarial checks on the target Linux host. [gVisor Docker setup](https://gvisor.dev/docs/user_guide/quick_start/docker/) describes the prerequisite runtime.

## API additions

| Route | Purpose |
|---|---|
| `GET /api/auth/status`, `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout` | Local account sessions |
| `GET/POST /api/providers`, `GET /api/providers/{id}`, `POST /api/providers/{id}/probe` | Immutable local provider connections |
| `GET /api/coding/repositories`, `/leases`, `/leases/{id}`, `/tasks` | Scoped discovery for terminal operation |
| `POST /api/coding/tasks/{id}/revert` | Review-hash-bound checkpoint undo |
| `GET /api/coding/capabilities`, `/sandbox` | Current optional capability status |
| `GET /api/control/receipts` | Account-visible audit records |
| `GET /api/telemetry/latest`, `/history`, `/workspace`, `/events` | Real host samples and scoped operation metadata |
| `GET /api/endpoints` | Route inventory; `/openapi.json` contains request schemas |

All operation APIs require a session, or explicit account-free demo mode. The legacy industrial signed package import/quarantine, Capsule comparison, source disclosure, purpose lease, version/rollback policy, retention sweep, approval and receipt APIs remain available through the CLI's generic API command. Their physical OT and package qualification adapters remain simulations.

## Verification and remaining boundaries

The test suite covers authenticated workflow contracts, impersonation denial, session expiry/revocation, brute-force throttling, provider transport/proposals, source quarantine, cross-compartment checks, encrypted retention, checkpoint continuation/undo, Git worktrees, retrieval ranking, telemetry redaction and export review. Live browser checks exercise measured telemetry, account provisioning disabling persona mode, login and logout. Test counts and final run outcome are recorded in the task response.

This is a functional local prototype, not completion of every production item in the research report. Optional live model quality, real embedding-model execution, installed Tree-sitter grammars and Linux/gVisor isolation must be validated on a configured deployment. Enterprise identity, OPA policy-service integration, independent model/runtime measurement, TUF/Cosign/in-toto imports, hardware-backed key custody, physical OT integration and held-out coding benchmarks remain beyond this local implementation. Existing software HMAC signatures, local finite scanners and application counters must not be presented as hardware attestation, complete DLP, OS zero egress or physical zeroization.
