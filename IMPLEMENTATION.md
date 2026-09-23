# Aegis prototype implementation

The implementation follows `deep-research-report.md`: the model proposes actions, and deterministic code owns authority. This milestone adds a governed coding workbench to the existing industrial control-plane simulation. It does **not** complete the report's full five-to-six-week roadmap.

## Run and try it

```powershell
python -m pip install -r requirements-dev.txt
python run_aegis.py --demo
```

Open `http://127.0.0.1:8000/#coding`. Startup remains empty. The demo flag enables local persona-based workflows; it does not seed or approve anything.

1. As **Operator**, select **Reference fixture (no LLM)** and request Capsule approval.
2. Switch to **Model Custodian**, approve; switch to **Security Officer**, approve; switch back to **Model Custodian**, activate the Capsule.
3. As **Data Owner**, import the port-validation sample, or explicitly select your own UTF-8 files. Choose the snapshot, Capsule, recipient and ASK/PLAN/EXECUTE mode. Issue a 15-minute lease. Patch download is off unless selected here.
4. As the lease's recipient, run a task. The reference adapter only locates `valid_port` and proposes the known `0 <= port` to `1 <= port` fixture repair. It is not general coding intelligence.
5. In EXECUTE, inspect the diff and apply it to the encrypted task snapshot. The imported baseline and host checkout are unchanged. Python syntax checking uses `ast.parse`; it does not execute tests or source code.
6. If the lease permits export, request patch download. **Data Owner** and **Security Officer** can inspect the bound diff and approve it. Return to the recipient, reopen the task from history and download the approved patch.
7. Close the task to remove its retained content and wrapped key from active application records. Revoking a lease does the same for its tasks; expiry cleanup runs every 30 seconds and on state access. Leases are checked synchronously before any content release, even between sweeps.

**Run Aegis adversarial validation** runs the original 17 control-plane checks plus 15 coding checks in a separate process with disposable synthetic storage. The original control-plane button retains its original 17-test scope. The validation result explicitly lists properties it cannot verify.

## Implemented boundaries

| Research requirement | Current code and behavior |
|---|---|
| Complete stack identity | `aegis/control/capsules.py`; coding binds provider/model manifest digest, system prompt, tool/proposal schemas, mode policy, retrieval version and source hashes for the coding implementation and shared gates. Rechecked before decryption, each proposal/action and output release. |
| Purpose-bound authority | `aegis/coding/service.py`; a separate signed coding lease binds persona, purpose, mode, exact immutable snapshot digest, compartment, Capsule, tool set, expiry and export flag. Industrial leases remain in `aegis/control/leases.py`. |
| Compartment-first retrieval | Snapshot authorization and signature verification precede decryption. Coding searches only that snapshot's authorized, non-quarantined files. No global candidate index. |
| STAIR foundation | `aegis/coding/tools.py`; literal matching plus Python function/class AST ranking, line references, bounded excerpts and untrusted evidence envelopes. No embeddings, semantic search, Tree-sitter or incremental index yet. |
| Tool Broker | Strict proposal and argument schemas; ASK/PLAN permit read/search only. EXECUTE can stage exact-match edits, inspect diffs and validate Python syntax. Shell, network, dependency installation, destructive tools, deployment and OT writes are denied. Unknown tools never reach an executor. |
| Coding loop | At most eight proposal turns, 24 actions, 48,000 context characters, and bounded model responses. Ambiguous edits, expired leases, changed Capsules and unsafe output abort the entire staged batch. |
| Review and export | Diff-hash-bound application; export requires explicit lease permission and distinct Data Owner/Security Officer approvals tied to task, lease, recipient and exact diff. New tasks cannot reuse another task's export approval. |
| At-rest protection | Imported file maps and retained task content are encrypted with Fernet. Metadata, labels, counts, hashes and decisions remain visible in the local DB. Raw prompts, code and model messages are excluded from receipt bodies. |
| Context firewall | Existing finite rules plus host-secret instructions and secret-like values. Suspicious files are withheld before search/model context. False positives are possible; this is not a complete injection or DLP detector. Tool authority remains independent of scanner results. |
| Tripwires and receipts | Existing compartment canaries, authenticated local receipt chain, plus coding action decisions, source snapshot digest, diff hash, provider-call counts, approvals and cleanup evidence. |
| Memory lifecycle | No host worktree or source execution. Task-local references are released; retained content uses a task-specific wrapped key and expires with the lease. The local Ollama adapter requests unload after each response; server/GPU cleanup is not verified. |

Snapshot imports accept 1-64 UTF-8 files, at most 128 KB each and 512 KB total, with PUBLIC or INTERNAL classification. Nested relative paths can be submitted through the API; the browser file picker uses root filenames. Absolute paths, traversal, reserved Windows names, credential directories, `.env` files, duplicate case-folded paths and file/directory collisions are rejected. Existing-file edits only; file creation/deletion and host repository access are future work.

## Optional local Ollama

No model is installed or downloaded by this application. Run and review your own local Ollama service first, disable its cloud capabilities/outbound access at the deployment layer, and explicitly configure an installed model:

```powershell
$env:AEGIS_OLLAMA_MODEL = 'your-local-model:reviewed-tag'
$env:AEGIS_OLLAMA_DIGEST = '<64 lowercase hex characters from the installed model manifest>'
$env:AEGIS_OLLAMA_LOCAL_ONLY = '1'
python run_aegis.py --demo
```

These are placeholders; use an actual installed model and its digest. The acknowledgement is a deployment prerequisite, **not** evidence that the model server is isolated. The adapter uses a fixed `127.0.0.1:11434` connection, bypasses proxies and DNS, rejects redirects, verifies the installed name/digest before each inference request, asks for a strict JSON proposal schema, and has no pull/download or cloud fallback path. Its model list and structured-chat protocol follow [Ollama model listing](https://docs.ollama.com/api/tags) and [chat API](https://docs.ollama.com/api/chat).

Select **Local Ollama** when registering a new Capsule, then repeat approval. Changed configuration or source measurements require a new approved Capsule. The manifest digest includes the model package's configuration, but the application does not independently hash all weight blobs, prove tokenizer/runtime integrity, or attest the model server. Do not equate an API-reported manifest digest with hardware-backed attestation. Live model quality and latency need measurement on an installed local model; protocol tests use a fake transport.

If measured source files change while the server is running, coding requests fail with `RUNTIME_RESTART_REQUIRED`. Restart before registering a new Capsule so a changed on-disk implementation cannot be approved while an older module remains loaded.

## API sketch

All coding operations require demo mode and an `X-Aegis-Actor` header. This header selects a local test persona; it is not an authenticated identity.

| Endpoint | Role and purpose |
|---|---|
| `POST /api/coding/repositories` | Data Owner; name, files map, compartment, classification |
| `POST /api/coding/capsules` | Operator; provider `reference` or `ollama`; returns Capsule and approval |
| `POST /api/control/approvals/{id}/decide` | Each required reviewer; APPROVE or REJECT |
| `POST /api/control/capsules/{id}/approve` | Model Custodian; bound approval ID |
| `POST /api/coding/leases` | Data Owner; repository, Capsule, recipient, mode, 1-15 minutes, export flag |
| `POST /api/coding/tasks` | Lease recipient; lease ID, prompt, exact lease purpose |
| `GET /api/coding/tasks/{id}` | Task owner; gated internal preview |
| `POST /api/coding/tasks/{id}/apply` | Task owner; exact reviewed diff hash |
| `POST /api/coding/tasks/{id}/export-request` | Owner; create bound two-person approval |
| `GET /api/coding/approvals/{id}/review` | Data Owner/Security Officer; inspect the exact export diff |
| `POST /api/coding/tasks/{id}/export` | Owner; approved bound approval ID |
| `POST /api/coding/tasks/{id}/close` | Owner; remove retained content |
| `POST /api/coding/leases/{id}/revoke` | Data Owner; revoke access and remove task retention |
| `POST /api/coding/validation` | Run the finite combined adversarial corpus |

The existing localhost Host/Origin protections and hosted-preview write denial apply to these endpoints. No external message, Git push or production deployment is performed.

## Threat model and remaining work

The primary attacker is untrusted repository content or an unreliable model attempting to exceed an authorized task. Application gates protect against unauthorized tools, snapshot paths, purposes, compartments, stale approvals, output canaries and selected secrets. They assume the local Python process and its software trust root are trusted.

Host administrators, stolen local keys, malicious inference servers, compromised Python dependencies, hostile same-user processes and forensic recovery of old DB pages/backups are outside the demonstrated boundary. Local personas do not separate real people. HMAC signatures and software measurement are not HSM/TPM attestation. Closing a task removes active records; it does not prove physical or backup erasure. Viewing an authorized diff cannot prevent copying, screenshots or manual transcription. Model-call counters record adapter activity, not OS network observations.

Next report milestones:

1. A Linux sandbox backend with independently tested no-network and host-secret containment before exposing test/lint execution; then Git worktrees/checkpoints and the test/fix loop.
2. Real identity and policy service integration (OPA), independent model/runtime measurement, reviewed offline imports using TUF/Cosign/in-toto, and stronger key custody.
3. Tree-sitter and local semantic retrieval with measured relevance; local model coding benchmarks and a held-out adversarial corpus.

## Validation

```powershell
python -m pytest -q
node --check frontend/js/coding.js
```

Tests use private temporary databases. Coding coverage includes encryption, complete reference repair, read-only modes, exact edit conflicts, path escapes, expiry during inference, revocation, Capsule changes before decryption, source quarantine before retrieval, tripwires, secret-like output, denied tools, bounded loops, review/approval binding, ownership, retention cleanup, applicable Git patches and loopback provider protocol failures. None of these results imply that generated code was executed in an OS sandbox.

Validated on 2026-09-23: **173 tests passed**; JavaScript syntax and Git whitespace checks passed. Browser checks exercised Capsule approval/activation, snapshot import, EXECUTE lease issuance, reference repair, diff application, two-person export review, persisted task reopening and **32/32** adversarial results. The export request produced a verified receipt and patch response; the in-app browser did not expose a completed download event, so saving that response to the device was not confirmed. The browser fixture uses a separate ignored `data/coding-browser-ready` directory and never populates the normal application database.
