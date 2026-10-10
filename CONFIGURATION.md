# AEGIS environment settings

Set environment variables for the application process, before startup/import.
Unless stated otherwise, an unset flag is disabled; flags require the literal
`1`. Numeric values and private local paths are validated by their consumers.
Production requires a separately provisioned Linux host; see DEPLOYMENT_ACCEPTANCE.md.

| Setting | Default / meaning |
| --- | --- |
| `AEGIS_DATA_DIR` | Source checkout: `data/`; installed wheel: `~/.aegis/runtime`. Private state, SQLite, documents, workspaces, models and receipts. Created explicitly at startup. |
| `AEGIS_CLIENT_DIR` | `~/.aegis`. Private per-origin CLI sessions. |
| `AEGIS_API_URL` | `http://127.0.0.1:8000/api`. Numeric HTTP loopback only; redirects and proxies refused. |
| `AEGIS_ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]`. Comma-separated HTTP Host allowlist; does not broaden the bind interface. |
| `AEGIS_SECURITY_PROFILE` | `development` or `production`. Production rejects non-Linux, root API identity and demo mode. |
| `AEGIS_ENABLE_DEMO_ENDPOINTS` | Disabled. Explicit fixture endpoints and, only without provisioned accounts, simulated personas. Never production authorization. |
| `AEGIS_KEY_BROKER_SOCKET` | Unset: development local custody. Production: separate key-custody Unix socket. |
| `AEGIS_KEY_BROKER_UID` | Required with broker; positive numeric peer UID distinct from runtime/witness. |
| `AEGIS_AUDIT_WITNESS_SOCKET` | Independent Linux audit witness socket; required in production. |
| `AEGIS_AUDIT_WITNESS_UID` | Numeric witness peer UID; distinct unprivileged identity. |
| `AEGIS_ATTESTOR_SOCKET` | Independent Linux attestor socket; required in production. |
| `AEGIS_ATTESTOR_UID` | Numeric peer UID; production requires 0 for the trusted host attestor, not the API. |
| `AEGIS_INSTALLATION_ID` | Required for independent anchoring; stable deployment identity. |
| `AEGIS_PROVIDER_TRUST_POLICY` | Administrator-provisioned trust-policy path outside provider bundles; required in production. |
| `AEGIS_RECOVERY_KEYRING` | Offline broker-keyring backup path for explicit stopped-service recovery. No automatic export of live keys. |
| `AEGIS_RUNTIME_UID` | Linux deployment service-template substitution for the restricted runtime UID; not a Python runtime setting. |
| `AEGIS_SANDBOX_ENABLED` | Enables configured validation sandbox, subject to platform/image checks. |
| `AEGIS_SANDBOX_IMAGE` | Explicit immutable sandbox image reference; no usable default. |
| `AEGIS_SANDBOX_BROKER_SOCKET` | Optional independent Linux validation-broker socket, avoiding runtime Docker authority. |
| `AEGIS_SANDBOX_BROKER_UID` | Expected numeric validation-broker peer UID. |
| `AEGIS_GIT_WORKTREES` | Opt-in Git-backed temporary task worktrees; does not authorize host checkout modification. |
| `AEGIS_OLLAMA_MODEL` | Unset. Explicit local Ollama model name for configured coding provider. |
| `AEGIS_LOCAL_MODELS_CONFIG` | Explicit pinned local-runtime/model JSON. Source launchers default to ignored `.runtime/local-models.json` if present; an empty value disables it. Installed wheels need an explicit path. |
| `AEGIS_LOCAL_MODELS_CONFIG_HASH` | Generated runtime binding of the managed inventory; never set manually. A changed configuration requires restart. |
| `AEGIS_PROVIDER_LOCAL_MODELS_API_KEY` | Generated per-launch managed-server credential; never set manually or put in CLI arguments/reports. |
| `AEGIS_OLLAMA_DIGEST` | Unset. Required model identity pin for Ollama. |
| `AEGIS_OLLAMA_LOCAL_ONLY` | Must be `1` for configured Ollama profile; not proof of host isolation. |
| `AEGIS_PROVIDER_<NAME>_API_KEY` | Optional secret reference for a registered local provider. NAME: uppercase letters, digits or underscore, 1–64 characters. Do not put secrets in files/command arguments/reports. |
| `AEGIS_EMBEDDING_MODEL_DIR` | Unset. Operator-selected offline embedding bundle; never auto-downloads. |
| `AEGIS_EMBEDDING_DIGEST` | Expected pinned embedding inventory digest. |
| `AEGIS_EMBEDDING_MRL_DIMENSIONS` | Unset. Optional explicit supported Matryoshka dimensions; only applicable to compatible trained embeddings. |
| `AEGIS_EMBEDDING_COARSE_DIMENSION` | Unset. Optional coarse retrieval dimension selected from the configured supported dimensions. |
| `AEGIS_MANAGED_STORAGE_BYTES` | 1 GiB; accepted range 16 MiB–16 GiB. Managed storage admission ceiling. |
| `AEGIS_MIN_FREE_BYTES` | 64 MiB; accepted range 1 MiB–1 GiB. Minimum free-disk admission margin. |
| `AEGIS_MAX_RECEIPTS` | 100000; range 100–1000000. Ledger ceiling; existing receipts are never silently pruned. |

`AEGIS_ASCII_LOGO`, `AEGIS_BANNER`, `AEGIS_LOGO_RICH` and
`AEGIS_INFO_PANEL` are Python display constants, not environment settings.
Former `ZERO_EGRESS_ENFORCED` and `ALLOW_EXTERNAL_CALLS` constants were unused
and removed; actual provider/network enforcement is implemented at request and
deployment boundaries, not claimed by a configuration boolean.
