# Vega

Vega is a local FastAPI workspace for recording model manifests and documents, inspecting text with a rule-based context scanner, and reviewing stored receipts. The interface starts empty: it does not load sample models, documents, tasks, or security events into the application database.

## Run locally

Requires Python 3.11 or newer.

```bash
python -m pip install -r requirements.txt
python run_vega.py
```

Open `http://127.0.0.1:8000`. The server binds to localhost by default. Set `VEGA_DATA_DIR` to choose where SQLite records and generated files live; otherwise Vega uses `data/` beside the source code. That directory is ignored by Git and Docker builds.

The **Model registry** stores metadata, resource requirements, and a SHA-256 checksum of the manifest fields. It does not install or validate model weights. Newly registered manifests remain in quarantine. The **Knowledge base** accepts your own text and metadata, including revision, department, classification, and approval status. The **Security center** scans submitted text with local rules. It is a finite heuristic check, not a complete defense against malicious instructions.

Synthetic task, self-test, qualification, comparison, and simulated hardware actions are disabled by default. Developers can opt in with `VEGA_ENABLE_DEMO_ENDPOINTS=1`; this does not seed records automatically. Vega does not currently run a real model or enforce operating-system network isolation. Do not use the prototype as an industrial approval system.

## Test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The tests create private temporary storage and explicitly load synthetic fixtures. They do not populate the normal application database.

## Repository layout

- `vega/` — API, registries, context rules, runtime and receipt code.
- `frontend/` — local HTML, CSS, JavaScript, and favicon.
- `tests/` — isolated regression tests and synthetic fixtures.
- `run_vega.py` — local launcher.
- `Dockerfile` and `docker-compose.yml` — optional container deployment.

The Docker image installs runtime dependencies only and exposes the app on the host loopback interface through Compose. Docker bridge networking by itself does not block outbound traffic from the container.
