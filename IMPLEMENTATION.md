# Vega prototype implementation map

`Vega_Prototype_Implementations_Now.md` defines the current implementation scope. `Vega.md` supplies the broader product direction; `Sovereign AI Security Gap Analysis.pdf` supplies architectural context. Hardware-backed production claims in the latter two documents are deliberately outside the prototype, as required by sections 37–38 of the implementation document.

## Run the demonstration

```powershell
python -m pip install -r requirements.txt
python run_vega.py --demo
```

Open `http://127.0.0.1:8000/#control`.

1. As **Operator**, select **Prepare demo**. This explicitly creates one synthetic encrypted document, one verified/qualified mock package, an unapproved Capsule, and two approval requests. Startup itself remains empty.
2. Select **Model Custodian** and approve both requests. Select **Security Officer** and approve both requests.
3. Select **Model Custodian**, then **Activate approved stack**.
4. Select **Data Owner**, then **Issue / renew purpose lease**. The lease is valid for 15 minutes and permits only an approval note for the Operator.
5. Select **Operator**, then **Run protected task**. Inspect the approved redacted deliverable, classification, source revisions, retrieval route, attestation, key-release decision, labels, cleanup, and receipt.
6. Run **Change Capsule component**, **Attempt wrong purpose**, **Inject Finance tripwire**, and **Compare cache isolation**. Each executes real prototype policy code; the changed Capsule stays unapproved and the Finance canary blocks output.
7. Select **Verify receipt chain** and **Run 17 adversarial tests**. Self-tests run in a subprocess with disposable storage; only results, events, and a summary receipt reach the active workspace.

Approval requests expire after 15 minutes. **Prepare demo** renews expired or rejected requests without replacing previous audit records. **Issue / renew purpose lease** creates a fresh signed lease. Source and package data remain unchanged.

## Requirements mapped to code

| Document sections | Implementation | Enforcement / observable result |
| --- | --- | --- |
| 1, 36.1 | `vega/control/capsules.py` | Canonical hash binds all nine stack components; component diffs identify changes. Approved Capsule seals are checked against active package/runtime/skill/retrieval policy before decryption and inference. |
| 2, 36.2 | `capsules.TaskKey`, `runtime.GovernedRunner` | Software-simulated attestation gates temporary key generation and encrypted source access. Mismatch leaves source ciphertext intact. Temporary keys are destroyed on completion and failure. |
| 3, 36.3 | `vega/control/leases.py` | HMAC-signed leases bind sources, compartments, purpose, Capsule, skill, principal/role, expiry, export, memory/training permissions, output type and recipient. Validation repeats at access, inference and export. |
| 4 | `data.disclose`, `artifacts.export_artifact` | Explicit expose/mask/pseudonymize/remove/tool-only/recipient-only field rules. Hidden fields and encrypted source objects never enter the mock adapter. Only the bound authorized recipient can request restoration of permitted tokens. |
| 5, 9 | `policy.label`, `policy.authorize_label` | Source restrictions are unioned across compartments and the highest classification is retained on context, reports, artifacts, temporary files, tool outputs and task memory. Combined analysis requires two-role approval. |
| 6, 7 | `policy.classify`, `policy.SKILLS`, `policy.tool_guard` | Deterministic task classification, purpose/skill selection, compartment and data-class restrictions, tool allowlists, output policy, evidence requirements and action/approval classification. |
| 8, 10, 11, 36.5 | `data.Workspace`, `data.IsolatedCache` | Separate encrypted temporary folders; task/principal/compartment-scoped HMAC cache keys; sensitive cache reuse disabled. Cleanup clears query/vector placeholders, caches, memory, files, logs and task key references before final receipts. Cleanup failure prevents export. |
| 12 | `vega/control/artifacts.py`, server lifespan | Retained mock artifacts have encrypted bytes, separate wrapped keys, owner, label, expiry and derivative references. Export and a 30-second local sweep enforce expiry, revoke keys, delete ciphertext and append destruction receipts. Failed deletion is recorded and retried. |
| 13, 36.4 | `data.canaries`, `data.tripwire` | Unique compartment markers scan disclosed context, raw model output, workspace files/logs and exports, including restored output. Cross-compartment matches create an event and block release. |
| 14, 15, 16 | `vega/control/retrieval.py` | Separate department namespaces and key identities; query/vector state is task-local and never audited verbatim. Embedding, vector, lexical and reranker protocols support replacement. Exact IDs/titles use lexical matching; semantic queries use mock vector candidates; mixed queries combine them. |
| 17 | `data.add_source`, `data.source_current`, `HybridRetrieval` | Owner, authority, department, classification, revision, effective date, status, equipment and skills are stored. Superseded, future, conflicting and unauthorized sources are rejected; a newer current revision also prevents stale use through an older lease. |
| 18 | `retrieval.verify_claim`, existing `runtime/evidence_gate.py` | Governed mock output uses exact disclosed-source support with source ID/revision/authorization. Unauthorized, superseded, conflicting and unsupported evidence is excluded. Existing inspection evidence gate supplies deterministic numeric verification and inferred/unsupported distinctions. |
| 19 | `data.context_check`, existing `security/firewall.py` | Allow/sanitize/quarantine/block outcomes; injection, hidden directives, external links, file paths and unauthorized source/compartment references are checked before the adapter. Sanitization is explicit; the task path defaults to quarantine/block. Audit records omit raw input. |
| 20–22, 27, 28 | `vega/control/packages.py` | Controlled imports for model/tokenizer/adapter/policy/skill/retrieval/runtime packages. Checks artifact bytes, manifest, local simulated signer, version, minimum/revoked versions and current approved version. Qualification runs expected/prohibited behavior fixtures; shadow results cannot approve a package. Only approved, unrevoked model packages can run. |
| 23, 32 | `policy.request_approval`, `policy.decide`, `policy.approved` | Six fixed demo roles; two distinct required roles, no requester self-approval or duplicate vote, expiry, immutable action binding and per-decision receipt. Package/Capsule activation, sensitive key release, combined analysis, export, policy changes and OT writes consume bound approvals. |
| 24 | `artifacts.export_artifact` | Mandatory gateway checks identity, recipient, lease, output, label, live Capsule/package approval, tripwire, sensitive fields, links, cleanup and high-classification approval. Returns approved/redacted/second-approval/blocked; every attempt appends a receipt. No automatic external transmission occurs. |
| 25, 26 | `vega/control/store.py` | Transactional ordered receipts include prior/current hashes and an HMAC-authenticated head. Modification, middle deletion and tail deletion fail verification; appending to a damaged chain is refused. Events contain policy metadata, not confidential query content. |
| 29 | `packages.compatibility`, existing hardware modules | CPU, low-memory laptop, workstation and GPU profile compatibility; unsupported runtime, excessive memory and other-profile-only results. Actual task execution checks local available resources. |
| 30 | `governance.network_call`, runtime receipt | Mock execution uses no network clients. The external-call interface refuses before DNS/socket operations. Receipts report zero application API calls, no Internet dependency and explicitly do not claim host egress measurement. |
| 31 | `policy.tool_guard`, task classification | Read-only/advisory/high-risk physical action classes. OT write simulation requires explicit approvals bound to the equipment and action hash; no PLC/SCADA connection exists. |
| 33 | `governance.learning_plan`, lease policy | Training, chat learning and persistent memory default to disabled. Future training plan validation requires approved data/compartment/purpose, two-role authorization, a separate adapter and a newly approved Capsule. It cannot execute training. |
| 34 | `vega/control/self_test.py`, `tests/test_control.py` | All 17 specified attack cases, plus lease-field mutations, recipient restoration, chain truncation/concurrency, approval reuse, sensitive key/export flow and API/empty-start regression coverage. |
| 35, 36, 39 | `runtime.GovernedRunner`, `/api/control`, `frontend/js/control.js` | End-to-end governed task flow and visible demonstrations in the Sovereign control plane page. |
| 37, 38 | Runtime boundaries below | Functional software simulations; production-only systems remain out of scope. |

## API and integration

Interactive schemas are available at `/docs`. All `/api/control` routes except `/status` require local demo mode. `X-Vega-Actor` selects one fixed persona; callers cannot invent roles. This intentionally simulates identity and is **not production authentication**. The hosted preview remains read-only and the new controls are hidden there.

- Register protected structured sources with `POST /api/control/sources` as Data Owner. These are encrypted separately from the legacy plaintext knowledge metadata registry.
- Import a mock package with `POST /api/control/packages/import`, qualify/shadow it, request a package approval, record two decisions and activate it. Offline signing uses a local demonstration trust root; no production publisher verification is claimed.
- Register a complete stack with `POST /api/control/capsules`; approve its identity before issuing a lease.
- `POST /api/control/tasks/classify` returns the classification and exact bindings needed for sensitive key-release, combined-analysis and OT approvals. Bindings include source IDs; physical-action bindings also include an action hash and equipment.
- `POST /api/control/tasks` runs the protected task. Its mock adapter receives only disclosed fields and source IDs/revisions. The default extractive fixture requires a `finding` field; insufficient evidence fails closed.
- A pending export returns an immutable approval binding and withholds content. Request/approve that binding, then retry `POST /api/control/artifacts/{id}/export`.
- `/api/control/policies/versions` applies approved minimum-version increases and revocations. A rollback exception requires a separate `rollback-override` approval bound to `{family, version, manifest_hash}` (the canonical manifest SHA-256). Supply its ID when importing. The exception is rechecked at package approval and execution, expires with its approval, never lowers the version floor, and cannot resurrect a revoked version. Normal package qualification, package approval and Capsule approval are still required.
- `/api/control/learning/review` validates a future training plan without enabling training or retaining chat history.
- `/api/control/retention/sweep` lets Security Officer or Key Custodian immediately apply expiry. A background sweep also runs while local demo mode is enabled.

The original manifest registry, document list, six-test legacy demo, evidence gate and self-hashed legacy receipts remain available for compatibility. They cannot access the new protected source ciphertext or retained artifact keys. The protected path and its chained audit records are surfaced together on the new control-plane page; the legacy Receipts page retains its original format. Run Vega directly with Python.

## Runtime boundaries

- Real Fernet encryption, SHA-256 and HMAC protect prototype records relative to a **local software key** in `VEGA_DATA_DIR/control.key`. A host administrator can read that key. There is no TPM, TEE, HSM, remote attestation or protection from a compromised OS.
- Receipt verification detects tampering relative to the retained local head/key. It is not an external audit anchor and cannot prove that an attacker did not replace the entire database, key and history together.
- Removing temporary keys/caches and encrypted files is prototype hygiene, not proof of physical RAM/VRAM/disk zeroization or backup erasure. Existing source records remain under their separate department source keys; task artifact expiry does not delete the approved source library.
- Mock dense retrieval is a deterministic candidate simulation. It does not claim semantic embedding quality. Mock qualification/shadow fixtures do not establish real-model capability or industrial safety.
- The finite context scanner and canaries demonstrate policy behavior; they cannot detect every malicious instruction or information leak. All results are advisory synthetic demonstrations.
- No real model training, automatic learning, production identity, OS sandboxing, full embedding index, or physical control system is added.

## Validation

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests use private temporary storage. The 17-case UI self-test also uses disposable storage and runs without external services. No tests seed the user's ordinary database. Browser verification covered preparing fixtures, two-role approvals, activating the stack, issuing a lease, successful redacted export, Capsule mismatch, Finance tripwire denial and the 17/17 self-test display; no browser console errors were observed.
