# Aegis

## Self-Defending Sovereign Industrial AI Runtime

> **Aegis is a self-defending sovereign industrial AI runtime that qualifies every model, isolates every task, distrusts every external context, verifies every important claim, adapts assurance to task risk, and produces verifiable proof of how each deliverable was generated Ã¢â‚¬â€ entirely on-premise and without external AI APIs.**

## Why Aegis Exists

Open-weight models, local inference runtimes, embedding models, vector databases, RAG systems, OCR engines, and agent frameworks already exist.

The problem is  **deployable, secure, reliable, maintainable, air-gapped industrial AI system** that can be trusted inside refineries, PSUs, government departments, defence-linked environments, and other confidential enterprises.

A normal local AI setup:

```text
User Ã¢â€ â€™ Ollama Ã¢â€ â€™ Local LLM Ã¢â€ â€™ Answer
```

Aegis:

```text
User Task
   Ã¢â€ â€œ
Risk Assessment
   Ã¢â€ â€œ
Skill / Workflow Selection
   Ã¢â€ â€œ
Authorized Data + Tools
   Ã¢â€ â€œ
Local Model Selection
   Ã¢â€ â€œ
Secure Execution
   Ã¢â€ â€œ
Evidence Verification
   Ã¢â€ â€œ
Artifact Generation
   Ã¢â€ â€œ
Sovereignty Receipt
```

## Core Architecture

```text
Ã¢â€Å’Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â
Ã¢â€â€š                       AEGIS                           Ã¢â€â€š
Ã¢â€â€š      SELF-DEFENDING SOVEREIGN AI RUNTIME            Ã¢â€â€š
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â¤
Ã¢â€â€š  1. Offline Model Registry                          Ã¢â€â€š
Ã¢â€â€š  2. Model Quarantine & Shadow Qualification         Ã¢â€â€š
Ã¢â€â€š  3. Resource-Aware Model Scheduler                  Ã¢â€â€š
Ã¢â€â€š  4. Risk-Adaptive Assurance Engine                  Ã¢â€â€š
Ã¢â€â€š  5. Skill / Workflow Runtime                        Ã¢â€â€š
Ã¢â€â€š  6. Industrial Context Firewall                     Ã¢â€â€š
Ã¢â€â€š  7. Claim-Level Evidence Gate                       Ã¢â€â€š
Ã¢â€â€š  8. Ephemeral Task Enclaves                         Ã¢â€â€š
Ã¢â€â€š  9. Authority-Aware Knowledge Layer                 Ã¢â€â€š
Ã¢â€â€š 10. Sovereignty Receipt                             Ã¢â€â€š
Ã¢â€â€š 11. Graceful Degradation Engine                     Ã¢â€â€š
Ã¢â€â€š 12. Private Feedback Learning                       Ã¢â€â€š
Ã¢â€â€š 13. Adversarial Self-Test Mode                      Ã¢â€â€š
Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â¤
Ã¢â€â€š                 LOCAL AI COMPONENTS                 Ã¢â€â€š
Ã¢â€â€š Open-Weight LLMs Ã¢â‚¬Â¢ Vision Models Ã¢â‚¬Â¢ Embeddings       Ã¢â€â€š
Ã¢â€â€š OCR Ã¢â‚¬Â¢ Vector DB Ã¢â‚¬Â¢ Rerankers Ã¢â‚¬Â¢ Code Sandbox          Ã¢â€â€š
Ã¢â€â€š Office Artifact Generators Ã¢â‚¬Â¢ Local Databases        Ã¢â€â€š
Ã¢â€â€Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Ëœ
```

## 1. Offline Model Registry

A truly air-gapped production server cannot simply download models from the internet.

```text
Internet-Connected Staging
        Ã¢â€ â€œ
Download Model
        Ã¢â€ â€œ
Security Scan
        Ã¢â€ â€œ
License Check
        Ã¢â€ â€œ
Dependency Validation
        Ã¢â€ â€œ
Benchmark
        Ã¢â€ â€œ
Quantization
        Ã¢â€ â€œ
Package Signing
        Ã¢â€ â€œ
Approved Offline Bundle
        Ã¢â€ â€œ
Secure Transfer
Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â AIR GAP Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
        Ã¢â€ â€œ
Aegis Runtime
        Ã¢â€ â€œ
Signature Verification
        Ã¢â€ â€œ
Local Qualification
        Ã¢â€ â€œ
Model Registry
```

## 2. Model Quarantine & Shadow Qualification

A newly imported model should not immediately become production-ready.

```text
New Model
   Ã¢â€ â€œ
QUARANTINE
   Ã¢â€ â€œ
Security & Integrity Checks
   Ã¢â€ â€œ
Offline Benchmark
   Ã¢â€ â€œ
Capability Profile
   Ã¢â€ â€œ
Shadow Production Mode
   Ã¢â€ â€œ
Compare Against Approved Model
   Ã¢â€ â€œ
APPROVE / RESTRICT / REJECT
```


## 3. Resource-Aware Model Scheduler

Multiple models may need to share limited GPU resources.

```text
             TASK QUEUE
                 Ã¢â€â€š
                 Ã¢â€“Â¼
        RESOURCE SCHEDULER
                 Ã¢â€â€š
      Ã¢â€Å’Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â¼Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â
      Ã¢â€“Â¼          Ã¢â€“Â¼          Ã¢â€“Â¼
     VRAM       RAM        CPU
                 Ã¢â€â€š
                 Ã¢â€“Â¼
       MODEL RESIDENCY MANAGER
                 Ã¢â€â€š
      Ã¢â€Å’Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â¼Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â
      Ã¢â€“Â¼          Ã¢â€“Â¼          Ã¢â€“Â¼
     LOAD       EVICT     OFFLOAD
```

The scheduler considers available VRAM, model size, quantization, modality, task priority, latency requirements, current model residency, and concurrent users.

## 4. Risk-Adaptive Assurance Engine

Not every task deserves the same verification depth.

```text
TASK
 Ã¢â€ â€œ
Risk Classification
 Ã¢â€ â€œ

LOW RISK
Ã¢â€ â€™ Single model
Ã¢â€ â€™ Standard verification

MEDIUM RISK
Ã¢â€ â€™ Primary model
Ã¢â€ â€™ Secondary verifier
Ã¢â€ â€™ Evidence validation

HIGH RISK
Ã¢â€ â€™ Independent models
Ã¢â€ â€™ Deterministic calculations
Ã¢â€ â€™ Evidence gate
Ã¢â€ â€™ Human approval
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
Ã¢Å“â€œ Maintenance SOPs
Ã¢Å“â€œ Inspection Reports
Ã¢Å“â€œ Equipment Manuals

Allowed Tools:
Ã¢Å“â€œ OCR
Ã¢Å“â€œ Internal Search
Ã¢Å“â€œ Python Calculator
Ã¢Å“â€œ DOCX Generator

Forbidden:
Ã¢Å“â€¢ HR Files
Ã¢Å“â€¢ Finance Records
Ã¢Å“â€¢ Internet Access

Validation:
Ã¢Å“â€œ Every recommendation must have evidence
Ã¢Å“â€œ Every calculation must be independently executed
Ã¢Å“â€œ High-risk recommendations require approval

Output:
Inspection_Approval_Note.docx
```

## 6. Industrial Context Firewall

Every external context is treated as untrusted, including uploaded files, OCR text, RAG chunks, spreadsheet cells, and tool output.

```text
Document
   Ã¢â€ â€œ
File Sanitization
   Ã¢â€ â€œ
Macro / Link / Hidden Text Scan
   Ã¢â€ â€œ
Prompt Injection Detection
   Ã¢â€ â€œ
Provenance Classification
   Ã¢â€ â€œ
Instruction / Evidence Separation
   Ã¢â€ â€œ
QUARANTINE Suspicious Content
   Ã¢â€ â€œ
Authorized Context
```

## 7. Claim-Level Evidence Gate

Aegis verifies important claims individually.

```text
Claim:
"P-204 vibration exceeds the permitted limit."

        Ã¢â€ â€œ
Evidence Search
        Ã¢â€ â€œ
Inspection Report
+
Applicable SOP
+
Current Equipment Manual
        Ã¢â€ â€œ
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
   Ã¢â€ â€œ
Create Temporary Enclave
   Ã¢â€ â€œ
Mount Authorized Files Only
   Ã¢â€ â€œ
Attach Authorized Tools Only
   Ã¢â€ â€œ
Network = Disabled
   Ã¢â€ â€œ
Execute Task
   Ã¢â€ â€œ
Export Approved Artifact
   Ã¢â€ â€œ
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
     Ã¢â€ â€œ
Insufficient VRAM
     Ã¢â€ â€œ
Smaller Model
+
Stronger Retrieval
+
Additional Verifier
+
Reduced Context
     Ã¢â€ â€œ
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
 Ã¢â€â€š
 Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ OCR
 Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ Layout Detection
 Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ Symbol Recognition
 Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ Line / Connection Extraction
 Ã¢â€Å“Ã¢â€â‚¬Ã¢â€â‚¬ Vision-Language Model
 Ã¢â€â€Ã¢â€â‚¬Ã¢â€â‚¬ Internal Knowledge Retrieval
 Ã¢â€â€š
 Ã¢â€“Â¼
STRUCTURED ENGINEERING CONTEXT
```

## Local RAG and Knowledge Retrieval

Aegis can use local embedding models and local vector stores.

Possible embedding models include BGE, E5, Qwen Embedding, or other local models.

Possible retrieval systems include Qdrant, FAISS, pgvector, Milvus, and Chroma.

```text
Document
   Ã¢â€ â€œ
Parser
   Ã¢â€ â€œ
Chunking
   Ã¢â€ â€œ
Embedding Model
   Ã¢â€ â€œ
Local Vector Database
   Ã¢â€ â€œ
Hybrid Retrieval
   Ã¢â€ â€œ
Reranking
   Ã¢â€ â€œ
Authority Filter
   Ã¢â€ â€œ
Permission Filter
   Ã¢â€ â€œ
Trusted Evidence
   Ã¢â€ â€œ
Local LLM
```

## Zero-Egress Runtime

```text
          ORGANIZATION BOUNDARY

Ã¢â€Å’Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Â
Ã¢â€â€š Models                LOCAL       Ã¢â€â€š
Ã¢â€â€š OCR                   LOCAL       Ã¢â€â€š
Ã¢â€â€š Embeddings            LOCAL       Ã¢â€â€š
Ã¢â€â€š Vector DB             LOCAL       Ã¢â€â€š
Ã¢â€â€š Documents             LOCAL       Ã¢â€â€š
Ã¢â€â€š Code Execution        LOCAL       Ã¢â€â€š
Ã¢â€â€š Artifact Generation   LOCAL       Ã¢â€â€š
Ã¢â€â€š Logs                  LOCAL       Ã¢â€â€š
Ã¢â€â€š Authentication        LOCAL       Ã¢â€â€š
Ã¢â€â€Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€Ëœ
                  Ã¢â€â€š
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

Aegis can package and validate Python wheels, NPM packages, OCR models, embedding models, fonts, document conversion libraries, application binaries, runtime configuration, checksums, signatures, and SBOM data.

## Example End-to-End Workflow

User:

> Review this scanned pump inspection report against the applicable maintenance SOP, calculate severity, and prepare an approval note.

Aegis:

```text
1. Classify Task
   Ã¢â€ â€™ Engineering Inspection

2. Assign Risk
   Ã¢â€ â€™ HIGH

3. Create Task Enclave
   Ã¢â€ â€™ Network Disabled
   Ã¢â€ â€™ Engineering files only

4. Inspect Uploaded File
   Ã¢â€ â€™ Prompt injection scan
   Ã¢â€ â€™ Sanitization

5. Select Workflow
   Ã¢â€ â€™ Inspection Review Skill

6. Select Models
   Ã¢â€ â€™ Vision Model
   Ã¢â€ â€™ Reasoning Model
   Ã¢â€ â€™ Embedding Model

7. Perform OCR

8. Retrieve Knowledge
   Ã¢â€ â€™ Current authoritative SOP only
   Ã¢â€ â€™ Applicable equipment manuals

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
