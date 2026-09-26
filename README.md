# Aegis

Aegis is a local governed coding and image prototype. **Operate from aegis-cli; use the website for measured telemetry and audit status.** Accounts, provider profiles, approved Capsules, purpose-bound leases, compartment checks, reviewed outputs and receipt chains share one local backend.

## Start

Start with the [short setup guide for Windows, Linux and macOS](QUICKSTART.md).
One-time offline setup creates the dedicated environment; no activation is needed.

| | Windows | Linux / macOS |
| --- | --- | --- |
| Set up once | `.\Aegis.bat setup` | `sh ./Aegis.command setup` |
| Create an account | `.\Aegis.bat cli users set operator` | `sh ./Aegis.command cli users set operator` |
| Open each day | `.\Aegis.bat` | `sh ./Aegis.command` |

The daily command starts the local API and CLI together. `/exit` stops the server
it started. Use `/help` for workflows and `/doctor` for local diagnostics.
Core operation does not require optional image/embedding libraries. Select
`setup --profile media` or `setup --profile full` when preparing those features.

Each `users set` prompts for a password. Provisioning is a local administrator action; it also resets that account's password and revokes existing sessions. Assign separate credentials to the actual reviewers. There are no default passwords. Use the same `AEGIS_DATA_DIR` for provisioning and the server; the default is this checkout's ignored `data/` directory.

The legacy-default `operator` account in this checkout was disabled and then reset locally during the security follow-up; the former default no longer matches. See [security and recovery](SECURITY_AND_RECOVERY.md) for owner-only storage, encrypted backup and restore, Windows key protection, and the model-server network boundary. The [offline model custody guide](OFFLINE_MODEL_TRUST.md) covers signed bundles and qualification gates.

The [second security review](SECURITY_REAUDIT_2026-09-25.md) documents authenticated approvals, restore-time session revocation, local-path restrictions and offline installation hardening. Restart after updating and request fresh reviews for older unsigned approval records.

In another terminal:

```powershell
.\.venv\Scripts\python.exe aegis_cli.py
```

Then `/login operator` and `/help`. One-shot commands also work. The old upstream Gemini application is reference code; the supported Aegis startup does not run it or request a Google login.

Open [the local dashboard](http://127.0.0.1:8000) and sign in to view measured CPU, RAM, disk and process memory, your task statuses, approvals and receipt summaries. GPU measurements are marked unavailable. The browser has no task/provider/approval mutation controls. Audit accounts can inspect request metadata; prompts, source code, bodies and tokens do not enter telemetry.

## Providers and operations

`/providers`, `/provider-add profile.json` and `/provider-probe PROVIDER-ID` support explicitly configured local Ollama, llama.cpp, LM Studio and vLLM servers. Connections use numeric loopback addresses, bounded responses and no redirects, proxies, automatic downloads or cloud fallback. A reference adapter is available for the finite port-validation fixture; it is not a general coding model.

The complete workflow is documented in [IMPLEMENTATION.md](IMPLEMENTATION.md): import a bounded source snapshot, register and approve a Capsule, issue/select a lease, run ASK/PLAN/EXECUTE, review/apply a diff, collect export approvals and save a patch. `/endpoints` lists the API; `/api` operates additional industrial control, registry and policy endpoints.

Optional capabilities include isolated temporary Git worktrees, installed Tree-sitter grammars, pinned local embeddings, and a Linux/gVisor fixed test/lint/type-check runner. They require explicit local setup. These adapters are not proof of OS isolation or model quality; see the implementation and validation limits before enabling them.

Local vision understanding and AUTOMATIC1111 image generation/editing have a separate reviewed media workflow: `/media-register`, `/media-prepare`, `/media-review`, `/media-run`, and approved `/media-export`. Install `requirements-media.txt` for image decoding. See [local models and images](LOCAL_MODELS_AND_IMAGES.md) for configuration, approvals and limits. `/capacity 1000 --bits 4` estimates weight storage; tokenization and retrieval embeddings do not make trillion-parameter models fit in limited RAM. The [audit report](AUDIT-2026-09-25.md) distinguishes verified integrations from remaining hardware, model-quality and isolation work.

For the current 8-core, 64 GiB Windows PC, see the [performance plan](PERFORMANCE_PLAN.md). It records an approximately 8x improvement in synthetic lexical-search latency and a CPU-first evaluation path for smaller local text and vision checkpoints. No live model throughput has been measured.

For incident response, a Security Officer can run `aegis_cli.py lockdown enable`.
It blocks governed execution and content release; `lockdown disable` requires
fresh task authorization. See [security operations](SECURITY_AND_RECOVERY.md#incident-execution-stop)
for commands and the limits of this application control.

For terminal guidance, run `python aegis_cli.py help` or `help coding`.
`doctor` reports local setup/security checks without calling models. In the
shell, `/context` checks the selected lease and `/compose` supports multiline
prompts with explicit `/send` and `/cancel`. Use `--json doctor` for scripts or
`--plain shell` for an unstyled terminal. See [CLI guidance](IMPLEMENTATION.md#operator-help-and-diagnostics).

## Explicit demonstration mode

`.\.venv\Scripts\python.exe run_aegis.py --demo` enables synthetic fixture commands without automatically loading records. Before accounts exist, `/persona operator` selects a clearly labeled demo identity. Creating the first account disables identity headers even if `--demo` remains enabled. Synthetic data stays separate from real host measurements.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest -q
node --check frontend/js/app.js
node --check frontend/js/telemetry.js
```

Install optional test tools only from a reviewed local wheelhouse. Tests use isolated temporary storage. The native runtime has no hosted deployment mode; it accepts local clients only.
