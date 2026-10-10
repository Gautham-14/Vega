# Architecture

Aegis is a local operator console and numeric-loopback FastAPI service. A model
is never downloaded or called simply by starting the service.

- Entry points: root compatibility launchers; installed `aegis`, `aegis-server`
  and `aegis-vm`.
- `aegis/operator/`: parser, bounded loopback HTTP transport, terminal display,
  interactive shell, local administration and private file import/export.
  `aegis/cli.py` retains command dispatch and public compatibility aliases.
- `aegis/api/`: authenticated routes, request boundaries and startup lifespan.
- `aegis/control/`: authenticated roles, labels, approvals, capabilities,
  incident state and independently anchored audit receipts.
- `aegis/coding/`, `advisory/`, `media/`: domain workflows and explicit provider
  dispatch. Provider identity, authorization and revocation are checked around requests.
- `aegis/security/`: authentication, recovery, supply-chain validation, private
  storage, resource limits, custody, attestation and validation brokers.
- `aegis/storage/`: constrained SQLite connections and central schema migrations.
- `aegis/models/local_runtime.py`: explicitly configured and SHA-256-pinned
  offline llama.cpp process lifecycle. A generated per-launch credential stays
  in private files/environment, not command-line arguments. Startup lists
  aliases but does not load model weights or perform inference.
- `aegis/models/prompt_routing.py` and `aegis/api/routes/chat.py`: authenticated,
  explicitly PUBLIC-only chat. Images require vision; code intent selects the
  coder; other text uses a bounded local semantic specialization classifier.
  Live RAM and conservative context checks reject requests without a weaker
  fallback. The dispatcher serializes model switching. Classifier output can
  never grant permissions, tools, protected-source access or lease authority.
- `aegis/vm/`: host-specific QEMU acceleration policy, pinned inventory,
  mutual-TLS virtio framing, loopback host gateway and restricted Linux guest
  bridge. The guest must pass production prerequisites before the gateway
  accepts requests. This source implementation is not infrastructure acceptance.
- `deploy/`: hardened Linux service and isolation templates; configuration alone
  is not evidence of host containment. `deploy/vm/` adds non-installing guest
  bridge/device examples and a deliberately unusable placeholder host policy.

Startup explicitly creates private storage and upgrades SQLite before accepting
requests. Importing configuration only resolves settings and validates paths.
The single application version is `aegis/version.py`; policy, schema, protocol
and monotonic signed-release versions are separate compatibility identifiers.

Database upgrades use `PRAGMA user_version`, an immediate transaction and
idempotent legacy initialization. Version 0 means an unversioned database;
version 1 supplies baseline tables; version 2 adds task artifacts and session
MFA timestamps when absent; version 3 adds signed expiry tombstones. Newer unknown schemas are rejected. Back up and
stop services before upgrades; never downgrade a migrated database in place.

SQLite access uses one process connection under a reentrant lock, with savepoints
for nested helpers. A verified receipt checkpoint avoids rescanning historical
rows on every append and lockdown check. Changes to ledger tables, commits from
other connections, database replacement and connection reopening invalidate it.
Head signatures and the independent witness are still checked. Startup, recovery
and explicit audits retain full verification; this cache is not a new trust anchor.

Authenticated incident routes have four reserved admission leases (two per
actor), separate from sixteen ordinary leases. Incident uploads have two
reserved readers and a 16 KiB cap. MFA step-up for privileged actors also uses
reserved capacity. Scanner API text is capped at 65,536 characters, direct
scanner inputs at 1,000,000; adversarial verb and comment matching uses linear
scans. Security events retain at most 4,000 bounded metadata rows; unsafe source
references become SHA-256 digests and request text is not persisted.

`aegis maintenance status` reports object quotas and their 75% high-water mark.
`aegis maintenance archive` requires a Security Officer or Key Custodian and
archives signed expired operational records without retained ciphertext or
running work. Maintenance at the high-water mark and admission at the 4,096
per-kind ceiling also attempt expiry archival. Receipt commitments are published
before deletion; signed tombstones prevent API identity reuse. Audit receipts,
revocations, accounts and policy history are preserved. Archival reduces active
object counts, not the immutable ledger or overall disk-budget requirements.

Installed packages default to `~/.aegis/runtime`; source checkouts retain
`data/`. `AEGIS_DATA_DIR` overrides both. Sensitive paths reject network storage,
symbolic links, junctions and hard-linked files.

## Deployment boundaries

Windows, macOS and Linux can run the native local operator/development service.
Hardened production uses the independently provisioned Linux guest on those
hosts, or the native hardened Linux services. The VM has no configured NIC,
host share, clipboard or GPU passthrough. The host/hypervisor administrator
remains trusted; this is not confidential computing. The x86-64 guest profile
uses TCG on non-x86 hosts; an ARM-native guest is not implemented.

Native PUBLIC chat is separate from exact-provider-bound INTERNAL workflows.
Selecting a coding lease disables ordinary-prompt PUBLIC auto-chat. A model
answer is untrusted text, never proof that code was executed or an operation
completed. Chat output is not stored by the application; content-free receipts
record the model, routing policy and prompt hash. This does not establish
physical memory erasure or independently verified serving-engine retention.

See LOCAL_MODELS.md for setup and synthetic quality checks, VM_DEPLOYMENT.md
for guest provisioning requirements, and DEPLOYMENT_ACCEPTANCE.md for the
unperformed hardware/security/model acceptance gates.
