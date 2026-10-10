# Model-free workflow readiness

Aegis can be configured and its workflows tested without a GPU or model weights.
No startup, Capsule registration, capability inspection or provider preflight
loads/downloads a model. Explicit task execution and qualification commands call
an operator-configured local inference server. This implementation was developed
using synthetic responses; actual model quality and hardware containment still
need deployment qualification when that server is available.

## Supported integration contracts

| Workflow | Serving interface | Model requirements |
| --- | --- | --- |
| Coding ASK/PLAN/EXECUTE | Ollama chat or OpenAI-compatible chat | Explicit model/digest pin; bounded JSON proposals |
| Source-grounded advisory | Same text interfaces | Advisory JSON schema, citations and abstention |
| Image understanding | Same chat interfaces | Profile declares vision; server owns its image processor |
| Image generation/editing | Local AUTOMATIC1111 API | Already loaded pinned checkpoint; reviewed image request |
| Semantic retrieval | Optional local sentence-transformers | Reviewed local safetensors layout and inventory hash |

llama.cpp, LM Studio and vLLM use the OpenAI-compatible adapter. Models, context
windows and devices are serving-server configuration, not interchangeable
tokenizer settings. An arbitrary checkpoint is not automatically compatible with
every task. Unsupported capabilities, wrong identities, incomplete generations
and malformed output fail closed. There is no cloud/model fallback or automatic
dependency installation.

For text profiles, `structured_output` can be `json_schema` (default),
`json_object`, or `prompt_json`. Select the mode your local server supports;
changing it requires a new immutable profile and Capsule approval. All modes use
the same strict application validation. No failed request is silently retried in
a weaker mode. Context uses a conservative UTF-8 byte estimate plus output and
framing reserves; exceeding it requires narrowing the request or configuring a
larger supported model context.

## Advisory setup for later model use

1. Provision independent Operator, Data Owner, Model Custodian and Security
   Officer accounts using [QUICKSTART.md](QUICKSTART.md). Start the local API.
2. Model Custodian: `provider-add profile.json`. This registers configuration
   only. `provider-preflight <id>` inspects it without contacting a server.
3. Data Owner: `advisory-source source.json`. Sources are encrypted and immutable;
   import a new ID for a new revision. Explicit fields and disclosure rules are
   required. This workflow accepts PUBLIC/INTERNAL sources. Arbitrary PDF parsing
   is not part of source ingestion; prepare reviewed UTF-8 fields first.
4. Operator: `advisory-register <provider-id>`. Model Custodian and Security Officer
   independently `approve <approval-id> approve`; Model Custodian then
   `activate <capsule-id> <approval-id>`.
5. Later, when an appropriate local model is running, Model Custodian explicitly
   runs `provider-qualify-advisory <provider-id> evaluations/advisory-public.json`.
   This tests a candidate, not production approval. INTERNAL content additionally
   requires the independently approved release in
   [PROVIDER_ASSURANCE.md](PROVIDER_ASSURANCE.md).
6. Data Owner: `advisory-lease lease.json`, naming the Capsule, user, equipment,
   skill, purpose, source IDs, recipient and a lifetime of at most fifteen minutes.
   Export is off by default. For combined compartments, Operator first uses
   `advisory-lease-review lease.json`, requests a `combined-analysis` approval with
   its returned binding through `/api/control/approvals`, and obtains independent
   Data Owner/Security Officer decisions. Put that approval ID in the lease.
7. Operator: `advisory-run request.json`. This is the explicit inference step.
   Use `advisory-task <id>` to inspect the result. There are no OT write connectors
   or arbitrary tool calls in this workflow.
8. `advisory-export-request <task-id>` returns the exact export binding. Data Owner
   and Security Officer approve independently. `advisory-export <task-id>
   <approval-id>` retrieves the approved JSON result through the local CLI.
9. `advisory-close <task-id>` destroys retained application content;
   `advisory-revoke <lease-id>` invalidates the lease and associated retained tasks.

Example lease request (replace IDs with your registered objects):

```json
{
  "capsule_id": "<approved-capsule-id>",
  "source_ids": ["PUBLIC-SYNTHETIC-PUMP"],
  "equipment": "Pump P-204",
  "skill": "inspection-review-v3",
  "purpose": "maintenance-risk-assessment",
  "user": "operator",
  "recipient": "operator",
  "minutes": 15,
  "allow_export": false
}
```

Example run request:

Prompts over 300 characters require an explicit `retrieval_query` of at most
300 characters. The full prompt goes to inference; retrieval never silently
truncates it. Both inputs are hash-bound in the task receipt.

```json
{
  "lease_id": "<issued-advisory-lease-id>",
  "prompt": "Review Pump P-204 vibration using the approved evidence",
  "purpose": "maintenance-risk-assessment"
}
```

`examples/advisory-source.json` contains synthetic data only. Importing it does
not register or call a model. No real industrial operating thresholds are
recommended by this fixture.

## Security invariants

- Authenticate account and authorize every source before decryption. Leases bind
  identity, purpose, equipment, source revisions/content/metadata, Capsule,
  recipient, expiry and provider release. Combined analysis has an additional
  exact-bound independent approval.
- Recheck authorization at source disclosure, immediately before provider
  dispatch, after inference, before retention, and on every read/export. Source
  replacement, expiry, revocation, incident lockdown and account reset block
  ongoing work. Previously transmitted bytes cannot be retracted.
- Only fully exposed fields enter advisory inference. Masked/removed/tool-only/
  recipient-only/pseudonymized fields cannot become model evidence. Protected
  values are checked against returned output; no token restoration occurs here.
- Documents and model outputs grant no tool authority. The model can propose
  quotes, fixed division calculations, or explicitly unverified inferences. Quotes
  must match the named disclosed field and revision; division is independently
  calculated with bounded finite Decimal operands. Inferences always require
  human review. Unsupported claims are excluded; no surviving evidence yields
  abstention. Free-form model reasons cannot bypass the evidence gate.
- Provider requests use numeric loopback, finite endpoint allowlists, response
  limits and deadlines. Duplicate JSON fields and non-finite JSON are rejected.
  vLLM cache salts are gateway-issued and scoped to task/user/lease/Capsule;
  llama.cpp prompt caching is disabled and Ollama receives an unload request.
  These request settings do not themselves prove server retention behavior.
- Results are encrypted, sealed, owner-scoped, short-lived and revocable. Receipts
  bind policy, workload, sources, provider configuration, decisions and output
  hashes without retaining raw prompts or claim text. Revocation is ledger-backed;
  replaying an old signed lease cannot revive it.
- Production custody, MFA, independent audit anchoring, signed offline releases
  and recovery remain governed by [SECURITY_IMPLEMENTATION.md](SECURITY_IMPLEMENTATION.md).
  Hardware TEE attestation and RAM/VRAM erasure are not claimed by software tests.
  GPU confidentiality requires independently verified CPU/GPU coverage when that
  hardware is deployed; a Docker container alone does not establish it.
- Supply-chain custody verifies independently signed offline bundles and pinned
  file inventories. Legacy SLSA/Cosign/TUF interfaces now fail closed instead of
  returning simulated success; those protocols require separately configured
  verification/signing authorities.

## AI stack depth

- Model-native tokenization is owned by the inference server. The optional pinned
  `tokenizer.json` utility does not replace a pretrained model vocabulary. Fake
  BLT/parity tokenizer implementations and unmeasured fairness percentages were
  removed. BLT requires a corresponding trained architecture.
- Lexical ranking is real BM25 with identifier-aware terms, exact text evidence
  and supported structural parsers. Installed `colbert`/`faiss` packages no longer
  alter scores by simulated multipliers.
- Optional dense retrieval uses pinned local CPU embeddings, finite vectors,
  native dimensions and cosine ranking. Invalid configured embeddings fail
  closed; they do not silently switch to another backend.
- For an independently reviewed MRL-trained embedding model, set
  `AEGIS_EMBEDDING_MRL_DIMENSIONS` to supported dimensions (e.g. `64,128`) and
  `AEGIS_EMBEDDING_COARSE_DIMENSION` to one of them. The actual pipeline shortlists
  at that width and reranks at native width. The bounded index uses exact search;
  no ANN speed or storage-saving claim is made. This configuration is Capsule-bound.
- `knowledge.ranking.late_interaction` implements normalized token MaxSim as a
  future encoder integration contract. A ColBERT encoder is not bundled or
  automatically loaded, and the active retrieval path reports
  `late_interaction: NOT_CONFIGURED`. ColBERT is dense multi-vector retrieval,
  not sparse lexical retrieval.
- Existing coding tools enforce finite action schemas outside model inference.
  Media uses separate vision/diffusion capability gates and independent request
  review. Model adapters now use immutable local-provider profiles instead of
  `NotImplementedError` placeholders.

## Verification without models

```text
python -m pytest -q
```

Tests use disposable storage, synthetic model responses, mocked embedding
encoders and loopback HTTP fixture servers. They do not require GPUs, real
weights, model servers, publisher credentials or industrial connections.
Optional tokenizer tests train a tiny text-only tokenizer fixture, not a language
model. The complete suite also covers coding/media, supply-chain verification,
provider assurance, incident controls, recovery, receipts and platform launchers.

Model-free tests prove application and protocol behavior. They do not prove a
future checkpoint's reasoning accuracy, physical containment, model-specific
performance, a live Linux/gVisor deployment, or certification. Run explicit
candidate evaluations and deployment validation after the model/hardware exists.

The current workstation's account setup, authenticated checks and completed
backup/restore drill are recorded in [LOCAL_OPERATIONS.md](LOCAL_OPERATIONS.md).
[DEPLOYMENT_ACCEPTANCE.md](DEPLOYMENT_ACCEPTANCE.md) defines the remaining
evidence and acceptance conditions for later model/hardware deployment.
