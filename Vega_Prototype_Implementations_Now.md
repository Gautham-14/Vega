# Vega Prototype — Implementations To Be Done Now

## Scope

This document defines **what must now be implemented inside the Vega prototype**.

It is about **features, modules, control logic, security behavior, demo flows, and prototype simulations** — not software/applications to install.

The prototype must remain lightweight and portable. Where production hardware is unavailable, Vega should implement a clear software simulation of the control flow without claiming hardware-backed guarantees.

---

# 1. Sovereign Model Capsule

Implement a **Capsule identity** for the complete approved AI stack.

The Capsule must bind together:

- model identity / model manifest
- tokenizer identity
- quantization configuration
- system prompt hash
- adapter / LoRA identity
- inference runtime identity
- skill policy
- retrieval configuration
- relevant security policy version

Vega must:

- generate a deterministic Capsule ID
- store approved Capsule IDs
- detect any component change
- mark a changed stack as a new Capsule
- block execution of an unapproved Capsule
- show exactly which component caused the Capsule ID to change

### Prototype demo

1. Approve Capsule A.
2. Change one configuration item.
3. Recalculate Capsule ID.
4. Vega detects mismatch.
5. Execution is denied until reapproval.

---

# 2. Simulated Attestation Before Decryption

Implement the production control flow in software.

Vega must:

1. measure the active Capsule
2. compare it against the approved Capsule
3. verify required security policy state
4. release a temporary task key only if verification succeeds
5. keep protected demo assets encrypted when verification fails
6. destroy the temporary task key when the task ends

### Important

The prototype must clearly label this as:

**Software-simulated attestation**

Production integration with TPMs, TEEs, confidential GPUs, or hardware attestation remains outside the prototype.

---

# 3. Cryptographic Purpose Leases

Implement **purpose-bound access**, not only user/role access.

Every protected task should be associated with a lease defining:

- dataset / document
- security compartment
- approved purpose
- approved Capsule
- approved skill
- requesting user / role
- expiry
- export permission
- persistent-memory permission
- training permission
- allowed output type

Example:

```yaml
data: pump-inspection-204
purpose: maintenance-risk-assessment
allowed_capsule: capsule-7f92
allowed_skill: inspection-review-v3
expires_after: 15_minutes
allow_training: false
allow_persistent_memory: false
allow_export: approval-note-only
```

Vega must deny access if:

- lease expired
- purpose does not match
- wrong Capsule is running
- wrong skill is used
- wrong user/role requests the data
- wrong compartment is involved
- requested export exceeds the lease

---

# 4. Selective Disclosure Before Inference

Implement a trusted preprocessing layer that decides **what the AI is allowed to see**.

Vega must support explicit field rules such as:

- expose
- mask
- pseudonymize
- remove
- tool-only
- recipient-only

Example:

```text
Supplier: Deccan Industrial Systems
        ↓
Supplier_A
```

The actual identity should remain outside the simulated inference context.

Vega must also support controlled restoration of protected fields only for an authorized final recipient.

---

# 5. Information-Flow Labels

Implement security labels that **follow derived information**.

Labels must be attached to:

- source documents
- retrieved context
- generated summaries
- generated reports
- tool outputs
- temporary files
- task memory
- exportable artifacts

Example:

```text
HR-CONFIDENTIAL document
        ↓
summary
        ↓
HR-CONFIDENTIAL
```

A rewrite, summary, format conversion, or tool call must not automatically remove the source restrictions.

When information from multiple compartments is combined, Vega must enforce the combined authorization requirement.

---

# 6. Task and Context Classification

Implement the trusted classifier/routing layer used before task execution.

The classifier should determine:

- task type
- intended purpose
- required skill
- required data source
- security compartment
- sensitivity level
- whether export is expected
- whether human approval is required
- whether the request is read-only or action-oriented

The classifier should primarily use deterministic rules and configured policies in the prototype.

The LLM must not be the final authority for security classification.

---

# 7. Skill Policy System

Implement task-specific **Vega Skills**.

Each skill must define:

- skill name and version
- permitted task types
- permitted tools
- permitted data classes
- permitted compartments
- permitted output types
- export rules
- evidence requirements
- approval requirements

A task must not be allowed to call a tool or access data outside the active skill policy.

---

# 8. Task Enclave / Temporary Workspace

Implement one isolated temporary workspace per task.

Each task workspace should contain only:

- the authorized files
- temporary task metadata
- permitted derived artifacts
- temporary key material
- task-local cache simulation
- task-local logs

Vega must:

- create the workspace when the task begins
- allow only authorized assets into it
- prevent unrelated task files from being visible
- clean it at task completion
- record the cleanup in the final receipt

---

# 9. Compartment Isolation

Implement separate security compartments such as:

- Engineering
- Maintenance
- Finance
- HR
- General / Public

Vega must prevent:

- direct cross-compartment file access
- cross-compartment retrieval
- cross-compartment task-cache reuse
- unauthorized combined outputs
- cross-compartment exports

Every protected object must carry a compartment identity.

---

# 10. KV / Prompt Cache Isolation Simulation

Implement the **policy behavior** of compartment-aware cache isolation.

The prototype does not need a real LLM KV cache.

Instead, create a simulated cache layer in which:

- cache entries belong to a user or security compartment
- cache keys include a compartment/principal-specific keyed identity
- one compartment cannot receive another compartment's cache hit
- highly sensitive tasks can disable cache reuse entirely

The demo must show:

```text
Finance cache entry
        ≠
Engineering cache entry
```

even when the underlying prompt prefix is identical.

---

# 11. Memory Hygiene Engine

Implement a task-completion hygiene process.

Track and clean prototype state such as:

- temporary task files
- prompt-cache simulation
- retrieval-cache simulation
- temporary query data
- temporary keys
- generated temporary artifacts
- temporary logs
- task workspace

The final task status should report items such as:

```text
Temporary workspace: DESTROYED
Prompt cache: CLEARED
Retrieval cache: CLEARED
Task key: DESTROYED
Cross-compartment reuse: BLOCKED
```

Do not claim physical RAM/VRAM zeroization in the lightweight prototype.

---

# 12. Controlled Retention and Cryptographic Erasure

Implement retention rules for protected task artifacts.

Each sensitive task artifact should have:

- retention policy
- owning task
- owning compartment
- encryption-key reference
- expiry
- derivative references

When retention expires, Vega must:

1. revoke/destroy the task key
2. delete task-local protected artifacts
3. clear related prototype caches
4. preserve only allowed audit metadata
5. record destruction in the receipt chain

---

# 13. Privacy Tripwires

Implement unique canary markers per security compartment.

Example:

```text
Finance     → VG-FIN-...
HR          → VG-HR-...
Engineering → VG-ENG-...
```

Vega should scan:

- generated output
- temporary files
- logs intended for release
- export artifacts
- cross-compartment transfers

If a canary appears outside its allowed compartment:

```text
CROSS-COMPARTMENT LEAK DETECTED
EXPORT BLOCKED
SECURITY EVENT GENERATED
```

This must be one of the main live prototype demonstrations.

---

# 14. Query and Embedding Sovereignty — Prototype Layer

Implement the **security architecture around retrieval** even if the prototype does not run a full embedding model.

The prototype should represent:

- separate department indexes
- separate encryption-key identities
- separate retrieval namespaces
- confidential query handling
- task-local query vectors/placeholders
- deletion of temporary query state
- document-ID based audit records instead of storing complete raw queries
- rejection of cross-compartment retrieval

Do not create one global organization-wide knowledge index in the prototype architecture.

---

# 15. Retrieval Abstraction Layer

Implement Vega so that the security architecture is not tied to Qdrant or one embedding model.

Create interfaces for:

- embedding provider
- vector/search backend
- lexical retrieval backend
- reranker

The prototype can use mock retrieval, but the architecture must allow later replacement with different engines.

---

# 16. Hybrid Retrieval Logic — Lightweight Prototype

Implement a simple retrieval router that distinguishes between:

- semantic questions
- exact IDs / tags / serial numbers
- document-title lookups
- structured identifiers
- mixed queries

Prototype behavior:

```text
Semantic question
    ↓
mock dense retrieval

Exact industrial identifier
    ↓
exact / lexical retrieval

Mixed query
    ↓
combine candidates
```

The purpose is to demonstrate that Vega does not depend exclusively on dense vector similarity.

---

# 17. Authority-Aware Document Governance

Implement document metadata such as:

- document owner
- department
- classification
- revision
- effective date
- superseded status
- approved authority
- applicable equipment / process
- permitted skills

Vega must prefer the **current authorized revision** and must be able to reject or flag superseded documents.

---

# 18. Evidence and Claim Verification

Implement evidence states for generated or mock-generated claims.

Example states:

- VERIFIED
- SUPPORTED
- PARTIALLY SUPPORTED
- UNSUPPORTED
- CONFLICTING SOURCE
- SUPERSEDED SOURCE
- NOT AUTHORIZED

For a prototype response, Vega should be able to show:

- which document supported a claim
- document revision
- evidence state
- whether the source was authorized for the task

---

# 19. Context Firewall

Implement an inspection layer for all imported/retrieved context before it reaches the model adapter.

Detect prototype cases such as:

- prompt injection embedded in documents
- instructions pretending to override Vega policy
- hidden or suspicious directives
- unauthorized file references
- cross-compartment references
- prohibited external links
- requests to bypass security policy

The firewall should:

- allow
- sanitize
- quarantine
- block

based on configured policy.

---

# 20. Offline Model / AI Package Registry

Implement a local registry for approved AI components.

Track:

- package ID
- model identity
- version
- model hash
- tokenizer hash
- quantization
- adapter hash
- runtime version
- Capsule ID
- approval state
- qualification state
- quarantine state

A model/package must not execute simply because a file exists on disk.

---

# 21. Secure Import Gateway

Implement a controlled offline import flow for:

- model packages
- tokenizer packages
- adapters
- policy updates
- skills
- retrieval configuration
- Vega runtime updates

The prototype should verify:

- package manifest
- artifact hash
- expected signer / simulated signature
- version
- approval state
- rollback/downgrade rule

Invalid imports must go to **quarantine**.

---

# 22. Rollback / Downgrade Protection

Implement version protection.

A previously valid but obsolete package must not automatically become acceptable again.

Vega should track:

- current approved version
- minimum accepted version
- revoked versions
- package status

Prototype demo:

1. approve version 3
2. attempt import of correctly signed version 1
3. Vega rejects it as a rollback attempt

---

# 23. Multi-Party Approval / Separation of Duties

Implement prototype roles so that one account is not omnipotent.

Suggested authority split:

- Model Custodian
- Security Officer
- Data Owner
- Operator
- Auditor
- Key Custodian

Critical prototype actions should support two-person approval, especially:

- model/Capsule approval
- major policy changes
- high-classification exports
- key release for sensitive tasks
- rollback override

---

# 24. Sovereign Export Gateway

Implement a mandatory gateway for anything leaving a protected task.

Before export, Vega must check:

- source classification
- derived information-flow label
- requesting user
- recipient / destination
- purpose lease
- permitted output type
- tripwire status
- sensitive fields
- embedded links or prohibited content
- approval requirement

Possible results:

```text
EXPORT APPROVED
EXPORT APPROVED WITH REDACTION
EXPORT REQUIRES SECOND APPROVAL
EXPORT BLOCKED
```

Every export attempt must create a receipt.

---

# 25. Tamper-Evident Sovereignty Receipts

Implement a receipt for every significant action/task.

Receipt metadata should include:

- task ID
- user / role
- active skill
- purpose
- Capsule ID
- policy version
- authorized source IDs
- source revisions
- security compartment
- evidence status
- key-release state
- hygiene result
- export decision
- zero-external-call status
- previous receipt hash
- current receipt hash

Receipts must form a hash chain.

Changing or deleting an older receipt must cause chain verification to fail.

---

# 26. Security Event Ledger

Implement events for:

- Capsule mismatch
- unauthorized data request
- expired purpose lease
- compartment violation
- tripwire leak
- context-firewall detection
- rollback attempt
- failed import verification
- unauthorized export
- receipt-chain failure
- task-hygiene failure

The ledger should store security metadata, not unnecessary confidential prompt content.

---

# 27. Model Qualification and Quarantine

Implement a simple qualification lifecycle:

```text
IMPORTED
    ↓
QUARANTINED
    ↓
VERIFIED
    ↓
QUALIFIED
    ↓
APPROVED
```

Prototype tests can evaluate:

- manifest integrity
- Capsule consistency
- expected metadata
- basic behavior fixtures
- prohibited-output fixtures
- compatibility with approved skills

Failed packages remain quarantined.

---

# 28. Shadow Mode Simulation

Implement a mode where a candidate model/package can be evaluated without becoming authoritative.

In Shadow Mode:

- it receives approved test inputs
- it produces outputs
- outputs cannot directly affect production/demo decisions
- outputs are compared with expected behavior
- qualification results are recorded

No real LLM is required; mock model profiles can demonstrate the lifecycle.

---

# 29. Hardware and Resource Profile Awareness

Implement local hardware profiling and model compatibility logic.

Vega should maintain profiles such as:

- CPU-only device
- low-memory laptop
- workstation
- production GPU server

The prototype should show whether a registered model/package is:

- compatible
- too large
- unsupported
- permitted only on another hardware profile

This is a policy/selection demonstration, not real heavy inference.

---

# 30. Network Sovereignty Check

Implement a prototype guarantee that task execution does not require external network access.

The task receipt should record:

```text
External API calls: 0
Internet dependency: NONE
Execution mode: OFFLINE
```

The demo should include an attempted prohibited external call that Vega blocks or reports.

---

# 31. OT-Safe Action Boundary — Simulation

Because Vega targets industrial use, implement an advisory-vs-action boundary.

Classify tools/actions as:

- read-only
- advisory
- low-risk approved action
- high-risk physical action

Prototype rules should demonstrate:

- telemetry/read operations can be permitted
- direct physical write/action requests require explicit policy
- high-risk actions require human approval
- unapproved control actions are blocked

The prototype does not need to connect to real PLCs or SCADA.

---

# 32. Human Approval Workflow

Implement approval checkpoints for high-risk decisions.

Examples:

- high-classification export
- model approval
- sensitive key release
- cross-department combined analysis
- OT write/action
- policy override

Vega should record:

- requester
- approver
- action
- timestamp
- decision
- relevant receipt

---

# 33. Governed Learning Policy

Implement the **policy controls**, but not real adapter training.

The prototype must show:

```text
Training: DISABLED BY DEFAULT
Automatic learning from chat history: DISABLED
Persistent memory: DISABLED unless authorized
```

If future training is requested, Vega should require:

- approved dataset
- approved compartment
- approved purpose
- explicit authorization
- separate adapter identity
- new Capsule approval

Actual LoRA/adaptor training is outside the current prototype.

---

# 34. Adversarial Self-Test Suite

Implement automated prototype tests for the major guarantees.

At minimum:

1. modify one Capsule component
2. expired purpose lease
3. wrong-purpose request
4. wrong-compartment request
5. unauthorized file access
6. cross-compartment cache attempt
7. privacy-tripwire leak
8. prompt injection in a document
9. superseded document use
10. unsupported claim
11. invalid package hash
12. rollback attempt
13. unauthorized export
14. receipt tampering
15. task cleanup failure
16. prohibited network call
17. unauthorized high-risk action

Each test should produce:

```text
PASS
FAIL
EXPECTED BLOCK
SECURITY EVENT
```

---

# 35. Main Demonstration Workflow

The completed prototype should be able to demonstrate this end-to-end flow:

```text
User submits industrial task
        ↓
Task + context classification
        ↓
Skill selected
        ↓
Purpose lease created / verified
        ↓
Security compartment established
        ↓
Approved Capsule verified
        ↓
Simulated attestation succeeds
        ↓
Temporary task key released
        ↓
Authorized data selectively disclosed
        ↓
Context firewall checks retrieved data
        ↓
Task enclave created
        ↓
Mock retrieval / mock model execution
        ↓
Evidence and information-flow labels attached
        ↓
Privacy tripwire scan
        ↓
Export gateway decision
        ↓
Memory hygiene process
        ↓
Temporary key destroyed
        ↓
Tamper-evident sovereignty receipt generated
```

---

# 36. Five Features That Must Be Visibly Demonstrable

The prototype should make these especially clear in the SIH demo:

## 1. Sovereign Model Capsule
Changing any approved AI-stack component changes the Capsule identity and blocks execution.

## 2. Attestation Before Decryption
Protected assets are usable only after the approved runtime/Capsule is verified.

## 3. Cryptographic Purpose Lease
Data access is limited by purpose, Capsule, skill, time, user, and allowed output.

## 4. Privacy Tripwire
A deliberate cross-compartment leak is immediately detected and blocked.

## 5. Memory Hygiene + Sovereignty Receipt
Task state is destroyed and the cleanup/security decisions are recorded in a tamper-evident receipt.

---

# 37. Implement Now, But Only as Simulation

These belong in the prototype as **functional simulations/interfaces**:

- attestation
- key broker behavior
- KV-cache namespace isolation
- embedding/index compartment isolation
- model execution
- model qualification
- shadow mode
- cryptographic erasure of mock assets
- OT read/write boundary
- signed update approval
- hardware compatibility profiles

The prototype must demonstrate the control logic without claiming production hardware guarantees.

---

# 38. Do Not Implement Now

The following should remain outside the current prototype:

- training a new LLM
- building a production open-weight model
- full Byte Latent Transformer
- custom BLT training
- production parity-aware tokenizer training
- GPU tokenizer/cuBPE
- training a new embedding model
- production Matryoshka embedding training
- ColBERT/SPLADE training
- real confidential-computing hardware integration
- TPM/TEE/HSM deployment
- confidential GPU deployment
- Kubernetes Confidential Containers
- full production Key Broker Service
- production SIEM
- real PLC/SCADA control
- automatic continuous learning
- autonomous model retraining
- organization-wide production RAG
- advanced cumulative privacy-budget scoring

These can remain as production/future architecture items.

---

# 39. Current Vega Prototype Definition

After these implementations, Vega should no longer be presented as only:

```text
Local LLM + RAG + Docker
```

The prototype should demonstrate Vega as:

```text
A sovereign AI control plane
        +
approved AI-stack identity
        +
purpose-bound data access
        +
compartment isolation
        +
controlled context and retrieval
        +
runtime hygiene
        +
controlled export
        +
tamper-evident governance
```

The underlying LLM, embedding model, vector database, and tokenizer are replaceable components.

The core prototype innovation is the **trusted control, policy, isolation, verification, and audit layer around them**.
