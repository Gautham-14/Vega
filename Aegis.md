# Aegis

## Self-Defending Sovereign Industrial AI Runtime

**Implementation status (2026-09-25):** This document describes the target
architecture. The current checkout is an application-security prototype, not
proof of end-to-end industrial assurance. Local authorization, sealed approvals,
offline bundle verification, governed coding/media flows, encrypted recovery and
an incident execution stop are implemented. Real-model qualification, verified
runtime binding, measured host isolation, independent claim verification and
separate-media recovery remain acceptance requirements. See the
[security review](SECURITY_REAUDIT_2026-09-25.md) and
[operations guide](SECURITY_AND_RECOVERY.md) for verified scope and limitations.

> **Aegis is a self-defending sovereign industrial AI runtime that qualifies every model, isolates every task, distrusts every external context, verifies every important claim, adapts assurance to task risk, and produces verifiable proof of how each deliverable was generated — entirely on-premise and without external AI APIs.**

## Why Aegis Exists

Open-weight models, local inference runtimes, embedding models, vector databases, RAG systems, OCR engines, and agent frameworks already exist.

The problem is  **deployable, secure, reliable, maintainable, air-gapped industrial AI system** that can be trusted inside refineries, PSUs, government departments, defence-linked environments, and other confidential enterprises.

A normal local AI setup:

```text
User → Ollama → Local LLM → Answer
```

Aegis:

```text
User Task
   ↓
Risk Assessment
   ↓
Skill / Workflow Selection
   ↓
Authorized Data + Tools
   ↓
Local Model Selection
   ↓
Secure Execution
   ↓
Evidence Verification
   ↓
Artifact Generation
   ↓
Sovereignty Receipt
```

## Core Architecture

```text
┌──────────────────────────────────────────────────────┐
│                       AEGIS                           │
│      SELF-DEFENDING SOVEREIGN AI RUNTIME            │
├──────────────────────────────────────────────────────┤
│  1. Offline Model Registry                          │
│  2. Model Quarantine & Shadow Qualification         │
│  3. Resource-Aware Model Scheduler                  │
│  4. Risk-Adaptive Assurance Engine                  │
│  5. Skill / Workflow Runtime                        │
│  6. Industrial Context Firewall                     │
│  7. Claim-Level Evidence Gate                       │
│  8. Ephemeral Task Enclaves                         │
│  9. Authority-Aware Knowledge Layer                 │
│ 10. Sovereignty Receipt                             │
│ 11. Graceful Degradation Engine                     │
│ 12. Private Feedback Learning                       │
│ 13. Adversarial Self-Test Mode                      │
├──────────────────────────────────────────────────────┤
│                 LOCAL AI COMPONENTS                 │
│ Open-Weight LLMs • Vision Models • Embeddings       │
│ OCR • Vector DB • Rerankers • Code Sandbox          │
│ Office Artifact Generators • Local Databases        │
└──────────────────────────────────────────────────────┘
```

## 1. Offline Model Registry

A truly air-gapped production server cannot simply download models from the internet.

```text
Internet-Connected Staging
        ↓
Download Model
        ↓
Security Scan
        ↓
License Check
        ↓
Dependency Validation
        ↓
Benchmark
        ↓
Quantization
        ↓
Package Signing
        ↓
Approved Offline Bundle
        ↓
Secure Transfer
══════════ AIR GAP ══════════
        ↓
Aegis Runtime
        ↓
Signature Verification
        ↓
Local Qualification
        ↓
Model Registry
```

## 2. Model Quarantine & Shadow Qualification

A newly imported model should not immediately become production-ready.

```text
New Model
   ↓
QUARANTINE
   ↓
Security & Integrity Checks
   ↓
Offline Benchmark
   ↓
Capability Profile
   ↓
Shadow Production Mode
   ↓
Compare Against Approved Model
   ↓
APPROVE / RESTRICT / REJECT
```


## 3. Resource-Aware Model Scheduler

Multiple models may need to share limited GPU resources.

```text
             TASK QUEUE
                 │
                 ▼
        RESOURCE SCHEDULER
                 │
      ┌──────────┼──────────┐
      ▼          ▼          ▼
     VRAM       RAM        CPU
                 │
                 ▼
       MODEL RESIDENCY MANAGER
                 │
      ┌──────────┼──────────┐
      ▼          ▼          ▼
     LOAD       EVICT     OFFLOAD
```

The scheduler considers available VRAM, model size, quantization, modality, task priority, latency requirements, current model residency, and concurrent users.

## 4. Risk-Adaptive Assurance Engine

Not every task deserves the same verification depth.

```text
TASK
 ↓
Risk Classification
 ↓

LOW RISK
→ Single model
→ Standard verification

MEDIUM RISK
→ Primary model
→ Secondary verifier
→ Evidence validation

HIGH RISK
→ Independent models
→ Deterministic calculations
→ Evidence gate
→ Human approval
```

This spends extra compute only where consequences justify it.

## 5. Skill / Workflow Runtime

A Skill can define:

- Allowed models
- Allowed datasets
- Allowed tools
- Allowed directories
- Retrieval method
- Validation rules
- Human approval requirements
- Output format
- Risk level

Example:

```text
InspectionReview.skill

Allowed Data:
✓ Maintenance SOPs
✓ Inspection Reports
✓ Equipment Manuals

Allowed Tools:
✓ OCR
✓ Internal Search
✓ Python Calculator
✓ DOCX Generator

Forbidden:
✕ HR Files
✕ Finance Records
✕ Internet Access

Validation:
✓ Every recommendation must have evidence
✓ Every calculation must be independently executed
✓ High-risk recommendations require approval

Output:
Inspection_Approval_Note.docx
```

## 6. Industrial Context Firewall

Every external context is treated as untrusted, including uploaded files, OCR text, RAG chunks, spreadsheet cells, and tool output.

```text
Document
   ↓
File Sanitization
   ↓
Macro / Link / Hidden Text Scan
   ↓
Prompt Injection Detection
   ↓
Provenance Classification
   ↓
Instruction / Evidence Separation
   ↓
QUARANTINE Suspicious Content
   ↓
Authorized Context
```

## 7. Claim-Level Evidence Gate

Aegis verifies important claims individually.

```text
Claim:
"P-204 vibration exceeds the permitted limit."

        ↓
Evidence Search
        ↓
Inspection Report
+
Applicable SOP
+
Current Equipment Manual
        ↓
VERIFIED
```

Claim states can include:

```text
VERIFIED
CALCULATED
INFERRED
UNSUPPORTED
CONFLICTING
```

For high-risk workflows, unsupported claims can be prevented from entering the final deliverable.

## 8. Ephemeral Task Enclaves

Every task executes inside a temporary isolated environment.

```text
User Task
   ↓
Create Temporary Enclave
   ↓
Mount Authorized Files Only
   ↓
Attach Authorized Tools Only
   ↓
Network = Disabled
   ↓
Execute Task
   ↓
Export Approved Artifact
   ↓
Destroy Enclave
```

This enforces least-privilege access.

## 9. Authority-Aware Knowledge Layer

Industrial retrieval must consider more than semantic similarity.

Aegis can use:

- Revision
- Effective date
- Supersedes / superseded by
- Plant
- Unit
- Equipment ID
- Approval state
- Issuing authority
- Applicability
- Classification
- User permission

Example:

```text
SOP Rev 4
Similarity: 98%
Superseded: YES
Decision: REJECT

SOP Rev 8
Similarity: 91%
Current: YES
Approved: YES
Applicable: YES
Decision: AUTHORITATIVE
```

## 10. Sovereignty Receipt

Every important execution can produce a signed machine-readable receipt.

```text
AEGIS EXECUTION RECEIPT

Task ID: VX-29118
Task: Pump P-204 Inspection Review

Models: LOCAL
Model Hashes: RECORDED
Knowledge Snapshot: RECORDED
Policy Version: RECORDED

Sources Used: 7
Verified Claims: 16 / 16
Calculations: 3 / 3 Passed

External DNS: 0
External HTTP: 0
External API Calls: 0
Network Egress: 0 bytes

Generated Artifact:
Pump_Inspection_Approval.docx

Artifact Hash: RECORDED
Receipt Signature: VALID
```

## 11. Degradation Engine

If the preferred model cannot run because of hardware limits, Aegis recalculates a safe alternative.

```text
Preferred Pipeline
     ↓
Insufficient VRAM
     ↓
Smaller Model
+
Stronger Retrieval
+
Additional Verifier
+
Reduced Context
     ↓
Maintain Assurance Threshold
```


## 12. Adversarial Self-Test Mode

Aegis can include built-in sovereignty and security tests.

```text
AEGIS SELF-TEST

Hidden Prompt Injection       BLOCKED
Unauthorized File Access      BLOCKED
Superseded SOP                REJECTED
Internet Access Attempt       BLOCKED
Dangerous Shell Command       BLOCKED
Unsupported Final Claim       BLOCKED

6 / 6 SECURITY TESTS PASSED
```

## Multimodal Industrial Processing

Aegis can process scanned documents, images, and engineering drawings using deterministic processing plus multimodal open-weight models.

```text
P&ID
 │
 ├── OCR
 ├── Layout Detection
 ├── Symbol Recognition
 ├── Line / Connection Extraction
 ├── Vision-Language Model
 └── Internal Knowledge Retrieval
 │
 ▼
STRUCTURED ENGINEERING CONTEXT
```

## Local RAG and Knowledge Retrieval

Aegis can use local embedding models and local vector stores.

Possible embedding models include BGE, E5, Qwen Embedding, or other local models.

Possible retrieval systems include Qdrant, FAISS, pgvector, Milvus, and Chroma.

```text
Document
   ↓
Parser
   ↓
Chunking
   ↓
Embedding Model
   ↓
Local Vector Database
   ↓
Hybrid Retrieval
   ↓
Reranking
   ↓
Authority Filter
   ↓
Permission Filter
   ↓
Trusted Evidence
   ↓
Local LLM
```

## Zero-Egress Runtime

```text
          ORGANIZATION BOUNDARY

┌───────────────────────────────────┐
│ Models                LOCAL       │
│ OCR                   LOCAL       │
│ Embeddings            LOCAL       │
│ Vector DB             LOCAL       │
│ Documents             LOCAL       │
│ Code Execution        LOCAL       │
│ Artifact Generation   LOCAL       │
│ Logs                  LOCAL       │
│ Authentication        LOCAL       │
└───────────────────────────────────┘
                  │
                  X
              INTERNET
```

Measured proof can include:

```text
External DNS Requests:   0
External HTTP Requests:  0
External API Calls:      0
Network Egress:          0 bytes
```

## Air-Gapped Software Supply Chain

The air-gap applies to more than the LLM.

Aegis can package and validate Python wheels, NPM packages, Docker images, OCR models, embedding models, fonts, document conversion libraries, application binaries, runtime configuration, checksums, signatures, and SBOM data.

## Example End-to-End Workflow

User:

> Review this scanned pump inspection report against the applicable maintenance SOP, calculate severity, and prepare an approval note.

Aegis:

```text
1. Classify Task
   → Engineering Inspection

2. Assign Risk
   → HIGH

3. Create Task Enclave
   → Network Disabled
   → Engineering files only

4. Inspect Uploaded File
   → Prompt injection scan
   → Sanitization

5. Select Workflow
   → Inspection Review Skill

6. Select Models
   → Vision Model
   → Reasoning Model
   → Embedding Model

7. Perform OCR

8. Retrieve Knowledge
   → Current authoritative SOP only
   → Applicable equipment manuals

9. Execute Calculations

10. Generate Recommendations

11. Verify Every Claim

12. Request Human Approval if Required

13. Generate:
   Pump_Inspection_Approval.docx

14. Generate:
   Aegis Sovereignty Receipt
```


## Final Pitch

> **Aegis turns open-weight AI from a collection of local models into a governed industrial system. It securely imports and qualifies models, schedules them around limited hardware, isolates every task, blocks hostile context, retrieves only authoritative evidence, verifies important claims, generates real enterprise artifacts, and produces proof that the entire workflow remained local and trustworthy.**
