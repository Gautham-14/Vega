# Local setup and operation

For the prepared development installation on this workstation, account,
credential and verified recovery locations are in
[LOCAL_OPERATIONS.md](LOCAL_OPERATIONS.md).

Use a reviewed Python 3.11+ installation. Aegis launchers do not download
dependencies or models automatically. Set up from a reviewed local wheelhouse
and its separate SHA-256 manifest:

```text
python aegis.py setup <wheelhouse-directory> <hash-manifest> --profile core
```

Use `--profile media` for image decoding, or `full` for optional local embeddings
and tokenization. Wheel files must match the operating system, architecture and
Python version. Every wheel must be in the manifest, with its exact hash.

For connected development only, you must create a virtual environment exactly named `.venv` in the repository root and install the dependencies:

```text
python -m venv .venv
.\.venv\Scripts\pip install -e .[cli]
```

Start the local API and CLI together:

```text
python aegis.py start
```

On Windows, `Aegis.bat` starts the same session. The API uses port 8000 by
default; `start --port 8001` selects another port. `/exit` stops the session.
There is no browser dashboard. `/docs` contains local API documentation.

Host administrators provision accounts through another terminal, using the
same `AEGIS_DATA_DIR` as the server. Passwords are read with hidden prompts:

```text
python aegis.py cli users set operator
python aegis.py cli users set data-owner
python aegis.py cli users set model-custodian
python aegis.py cli users set security-officer
```

For named accounts, use `users set alice --like operator`. Named accounts need
an explicit built-in role template. Roles are immutable. Each person signs in
with their own account; independent approvals require different reviewers.

Within the CLI shell, prefix commands with `/`. From a terminal, use
`python aegis.py cli <command>`:

1. Data Owner: `login data-owner`, then `import <directory> --name Example`.
   Keep the returned repository ID.
2. Operator: `login operator`, then `register reference`. Keep the Capsule
   and approval IDs. `reference` only handles the built-in port-validation fixture.
3. Model Custodian and Security Officer each sign in and run
   `approve <approval-id> approve`.
4. Model Custodian: `activate <capsule-id> <approval-id>`.
5. Data Owner: `lease --repo <repository-id> --capsule <capsule-id>
   --recipient operator --mode PLAN`.
6. Operator: `use <lease-id>`, then `context` and `run <prompt>`.

Live providers use `provider-add profile.json`, followed by `register <provider-id>`.
Unverified live providers accept PUBLIC data only. The normal coding import is
INTERNAL; [provider assurance](PROVIDER_ASSURANCE.md) is therefore required for
that workflow with a live model. `help import` describes classification options.

`EXECUTE` can stage snapshot edits for review. `diff` and `apply` require the
exact reviewed diff hash. Export requires lease permission and independent
Data Owner and Security Officer approval. Host source is not modified.

Use `help start`, `help coding`, `help models`, `help images`, `help security`,
`help recovery`, and `help <command>` for exact arguments. `doctor` checks the
local account, API, incident controls and receipt chain without calling models.

For source-grounded industrial/document assistance, use `help advisory` and
[WORKFLOW_READINESS.md](WORKFLOW_READINESS.md). `provider-preflight <id>` checks
configuration without contacting a model. Plain shell prompts require a selected
valid coding lease; an error never triggers a demo or a replacement model.
`demo`/`pipeline` explicitly request the server's enabled deterministic fixture.
