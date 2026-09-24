# Aegis

Aegis is a local governed coding prototype. **Operate from aegis-cli; use the website for measured telemetry and audit status.** Accounts, provider profiles, approved Capsules, purpose-bound leases, compartment checks, reviewed patches and receipt chains share one local backend.

## Start

Python 3.11+ is required. From this checkout:

```powershell
python -m pip install -r requirements.txt
python aegis_cli.py users set operator
python aegis_cli.py users set model-custodian
python aegis_cli.py users set security-officer
python aegis_cli.py users set data-owner
python run_aegis.py
```

Each `users set` prompts for a password. Provisioning is a local administrator action; it also resets that account's password and revokes existing sessions. Assign separate credentials to the actual reviewers. There are no default passwords. Use the same `AEGIS_DATA_DIR` for provisioning and the server; the default is this checkout's ignored `data/` directory.

In another terminal:

```powershell
python aegis_cli.py
```

Then `/login operator` and `/help`. One-shot commands also work, such as `python aegis_cli.py login operator`. The repository's Node entrypoint runs the same native operator:

```powershell
cd gemini-cli
npm start
```

No npm install or Gemini build is needed for this launcher. `AEGIS_PYTHON` selects a Python executable. The old upstream Gemini application remains reference code under `start:legacy`; the supported Aegis entrypoint does not launch it or request a Google login.

Open [the local dashboard](http://127.0.0.1:8000) and sign in to view measured CPU, RAM, disk and process memory, your task statuses, approvals and receipt summaries. GPU measurements are marked unavailable. The browser has no task/provider/approval mutation controls. Audit accounts can inspect request metadata; prompts, source code, bodies and tokens do not enter telemetry.

## Providers and operations

`/providers`, `/provider-add profile.json` and `/provider-probe PROVIDER-ID` support explicitly configured local Ollama, llama.cpp, LM Studio and vLLM servers. Connections use numeric loopback addresses, bounded responses and no redirects, proxies, automatic downloads or cloud fallback. A reference adapter is available for the finite port-validation fixture; it is not a general coding model.

The complete workflow is documented in [IMPLEMENTATION.md](IMPLEMENTATION.md): import a bounded source snapshot, register and approve a Capsule, issue/select a lease, run ASK/PLAN/EXECUTE, review/apply a diff, collect export approvals and save a patch. `/endpoints` lists the API; `/api` operates additional industrial control, registry and policy endpoints.

Optional capabilities include isolated temporary Git worktrees, installed Tree-sitter grammars, pinned local embeddings, and a Linux/gVisor fixed test/lint/type-check runner. They require explicit local setup. These adapters are not proof of OS isolation or model quality; see the implementation and validation limits before enabling them.

## Explicit demonstration mode

`python run_aegis.py --demo` enables synthetic fixture commands without automatically loading records. Before accounts exist, `/persona operator` selects a clearly labeled demo identity. Creating the first account disables identity headers even if `--demo` remains enabled. Synthetic data stays separate from real host measurements.

## Verify

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check frontend/js/app.js
node --check frontend/js/telemetry.js
```

Tests use isolated temporary storage. A hosted Vercel preview remains read-only and does not represent a working persistent deployment.
