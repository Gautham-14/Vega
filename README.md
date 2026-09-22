# Aegis

Aegis is a local FastAPI workspace with a sovereign AI control-plane prototype: approved stack identities, signed purpose leases, encrypted assets, selective disclosure, compartment isolation, two-person approval, controlled export, memory hygiene and chained receipts. The interface starts empty; synthetic fixtures are loaded only by an explicit demo action.

## Run locally

Requires Python 3.11 or newer.

```bash
python -m pip install -r requirements.txt
python run_aegis.py
```

Open `http://127.0.0.1:8000`. The server binds to localhost by default. Set `AEGIS_DATA_DIR` to choose where SQLite records and generated files live; otherwise Aegis uses `data/` beside the source code. That directory is ignored by Git.

The **Model registry** stores metadata, resource requirements, and a SHA-256 checksum of the manifest fields. It does not install or validate model weights. Newly registered manifests remain in quarantine. The **Knowledge base** accepts your own text and metadata, including revision, department, classification, and approval status. The **Security center** scans submitted text with local rules. It is a finite heuristic check, not a complete defense against malicious instructions.

Synthetic task, self-test, qualification, comparison, and simulated hardware actions are disabled by default. Run `python run_aegis.py --demo` (or set `AEGIS_ENABLE_DEMO_ENDPOINTS=1`) and open **Control plane** to prepare and approve the synthetic workflow. This does not seed records automatically. The page demonstrates Capsule changes, attestation before decryption, purpose-bound denial, a cross-compartment privacy tripwire, cache isolation, cleanup and receipt-chain verification.

The **Quick guide** links to the main workflows. Control plane separates **Setup & approvals**, **Run a task**, and **Audit & records**, with a next-step guide based on current approvals and lease expiry. Its shortcut switches the demo persona and focuses the relevant action; approvals and task execution still require explicit clicks. Arrow keys navigate the workflow tabs. On small screens, navigation opens as a drawer and approval requests stack vertically.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the walkthrough, API usage, requirements-to-code map and precise simulation boundaries. The protected control-plane source store is encrypted and separate from the original metadata registries. The prototype uses selectable local personas to demonstrate separation of duties; it does not provide production authentication, real model inference, hardware attestation or operating-system network isolation.

## Simulated telemetry

The Overview resource card and **Telemetry** page show clearly labeled, browser-generated CPU, memory, GPU/VRAM and disk activity. Choose Idle workspace, Inspection review or Busy queue; pause/resume the feed or reset its two-minute sample history. Samples update every three seconds while the tab is visible. Reduced-motion preferences start the feed paused. No models, downloads or extra dependencies are needed. This display is separate from actual hardware eligibility checks and workspace/audit records, and also works in the read-only hosted preview.

## Test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The tests create private temporary storage and explicitly load synthetic fixtures. They do not populate the normal application database.

## Repository layout

- `aegis/` Ã¢â‚¬â€ API, registries, context rules, runtime and receipt code.
- `frontend/` Ã¢â‚¬â€ local HTML, CSS, JavaScript, and favicon.
- `tests/` Ã¢â‚¬â€ isolated regression tests and synthetic fixtures.
- `run_aegis.py` Ã¢â‚¬â€ local launcher.
## Vercel hosted preview

Vercel detects the FastAPI entrypoint in `pyproject.toml`. On Vercel, Aegis uses temporary function storage and disables all mutating API requests. The hosted site is a read-only interface preview: it cannot persist model manifests, documents, scans, or receipts. Run Aegis locally for the working private workspace. Do not upload private data to the hosted preview.
