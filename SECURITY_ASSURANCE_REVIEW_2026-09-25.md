# Aegis security and protocol assurance review — 2026-09-25

## Verdict

The [second security review](SECURITY_REAUDIT_2026-09-25.md) records subsequent fixes, approval compatibility changes, recovery semantics and current validation.

`Aegis.md` defines the right problem: a governed, confidential, air-gapped industrial AI system that can produce trustworthy evidence. The current project is a useful **local control-plane prototype**, not an assured industrial deployment. It demonstrates authorization, scoped tools and data, approvals, local provider restrictions, encrypted retention, backup/restore, and tamper-evident local receipts. It does not yet establish that a real model was imported safely, qualified on relevant tasks, isolated from network access, or used to verify a real high-risk deliverable. No live models are installed in this environment.

The key distinction is *application control* versus *independent evidence*. A loopback endpoint limits where Aegis sends requests; it does not prove what the model process loads, where it or a plugin sends data, or that Windows made no other network connections. A manifest checksum detects a change to metadata; it does not establish model-weight integrity or publisher authenticity. An HMAC receipt can detect local changes when its key remains safe; it does not provide an external witness or hardware attestation.

The legacy industrial demo stores document content, task artifacts and receipt text in ordinary SQLite text columns (`aegis/storage/database.py`). It must remain synthetic-data-only. The newer control-plane sources and short-term coding/media retention use application encryption, but Windows disk encryption, filesystem ACLs, secure deletion, backups and the model-server process remain separate deployment boundaries.

## Traceability to `Aegis.md`

| Promised stage | Current evidence | Assurance status |
| --- | --- | --- |
| Offline model registry and supply chain | `aegis/models/registry.py` stores metadata and compares its own canonical hash; `aegis/control/packages.py` hashes a supplied demo string and signs with the local control key. Real provider profiles accept custodian-asserted or server-reported digests. | **Demo/partial.** No independently trusted signature, complete checkpoint/tokenizer/projector bundle verification, SBOM, or runtime binding. |
| Quarantine, benchmark, shadow approval | Legacy registry uses fixed scores; control packages compare fixed `safe`/`unsafe` outputs. | **Simulated.** No candidate model is executed in held-out tests, no real baseline comparison. |
| Resource-aware scheduler | Hardware eligibility and model routing exist; synthetic profiles use RAM/VRAM metadata. | **Partial.** No real multi-model residency, admission control, eviction, or latency guarantee. |
| Risk-adaptive assurance | `aegis/control/policy.py` classifies a bounded task vocabulary; demo runner and evidence gate vary decisions by risk. | **Partial/demo.** No enforced independent secondary model/verifier for a real high-risk task. |
| Skill/workflow runtime | Capsules, labels, leases, allowed tools, bound approvals and real coding/media workflows exist. | **Prototype controls present.** Industrial OT and inspection workflows remain simulations. |
| Context firewall | `aegis/security/firewall.py` applies finite text rules and hidden-character detection; access checks limit source disclosure. | **Partial.** No general file-format sanitization, macro/link/embedded-object parsing, OCR prompt-injection validation, or proof against novel attacks. |
| Claim-level evidence gate | `aegis/runtime/evidence_gate.py` checks a narrow synthetic pump-report grammar; control runner checks selected fixture claims. | **Demo.** No general claim extraction, citation-to-source-span validation, or reviewer on real generated reports. |
| Ephemeral task enclaves | Application-owned temporary folders and cleanup exist; optional Linux gVisor coding sandbox exists. | **Partial.** Windows task folders are not OS sandboxes. No measured process/child-process network deny. |
| Authority-aware knowledge | Revision, approval, equipment, compartment and classification filters are present in bounded retrieval flows. | **Prototype controls present.** Needs real corpus ingestion, provenance and stale-source tests. |
| Sovereignty receipts | Local HMAC chain for control receipts; legacy demo produces self-hashed JSON/Markdown with simulated counters. | **Partial/demo.** No independent signing key/witness or measured host/network proof. |
| Degradation engine | Hardware eligibility and fallback routing to demo adapters exist. | **Demo.** No proof that a lower-cost real pipeline preserves the assurance threshold. |
| Adversarial self-test | Six synthetic tests cover known patterns and fixture records. | **Demo.** A simulated egress probe opens no socket and cannot validate Windows firewall or model process isolation. |
| Multimodal/RAG/artifacts | Loopback image understanding and generation/editing adapters, local embedding/tokenizer options, and Markdown/patch outputs exist. | **Partial.** No installed model, real P&ID/OCR/layout validation, or production `.docx` inspection note. |

## Changes made in this review

- Legacy model records are now reported as `DEMO_QUALIFIED`, including older records stored as `QUALIFIED`. Metadata checks are identified as manifest checks. API responses explicitly say that weights, publisher signatures, and runtime binding were **not** verified and that production eligibility is false.
- Fixture benchmark results identify their scores as unmeasured. The mock router accepts only demo-qualified fixtures. The dashboard reports zero production-qualified models and separately counts demo-qualified fixtures; network counters are `NOT_MEASURED` instead of fabricated zeros.
- Mock model imports and industrial control-package/import/task/self-test endpoints require explicit demo mode; persisted mock packages are not executable after demo mode is disabled. Control-package responses identify their string-artifact/HMAC scope and simulated shadow mode. Legacy demo receipts identify the model as demo-qualified and disclose missing weight/runtime verification.
- A regression test checks that a valid metadata checksum plus simulated qualification cannot become production eligibility and that the import API is unavailable outside demo mode.

## Highest-priority protocol work

1. **Establish a real trust root for offline imports.** Build an offline bundle containing exact weight shards, tokenizer, vision projector/encoders, runtime binary/configuration, dependency list/SBOM, licenses, immutable manifest, source provenance, and test plan. Verify file sizes/hashes and a signature against preinstalled, independently held public keys. Reject missing/extra files, links, unsafe serialization/code, rollback, and unverifiable licenses. Keep signing private keys off the Aegis host. TUF-style role separation and threshold keys are appropriate for larger deployments. A local HMAC made by the importer is insufficient.
2. **Bind verified files to the serving process.** Start an approved local server from a pinned executable/configuration; verify its loaded model and related files at launch and after updates. Restrict filesystem access and child processes. Require reapproval when any component changes. Server-reported model names/hashes alone do not establish this binding.
3. **Enforce and measure network denial.** Use a dedicated Windows service account or stronger VM boundary for model, OCR, conversion and agent processes; deny outbound traffic for them and their children and log blocked attempts. Verify with an actual controlled egress attempt and independent firewall/packet evidence. Only then may a receipt claim zero egress for a measured interval and process set. An air-gapped physical network is stronger when the threat model requires it.
4. **Qualify real models before sensitive use.** Keep imports quarantined; run reproducible, held-out and adversarial tests for each text, vision, image-generation and retrieval capability on the target machine. Include leakage, prompt-injection, cross-compartment retrieval, hallucinated citations, refusal under uncertainty, image metadata/hidden text, and performance. Run a real baseline shadow comparison, have domain and security reviewers approve recorded evidence, and restrict approved models to tested tasks. High-risk industrial conclusions need deterministic calculations and independent human review.
5. **Protect data against loss.** Keep encrypted, versioned backups on separate offline media with independently held recovery keys. Automate restore drills to fresh storage, verify database and receipt chains, and measure recovery-point and recovery-time targets. The validated local backup/restore flow is a good starting point; a same-drive backup does not cover drive failure or theft.
   Keep real confidential source text out of the legacy demo SQLite tables; migrate any future general industrial ingestion to an encrypted store with scoped decryption and an explicit retention policy.
6. **Complete the high-risk workflow.** Add real scanned-document parsing and format sanitization, provenance per extracted field, claim-to-source-span verification, citation and calculation checking, approval before export, and a real `.docx` generator. Fail closed when any step lacks evidence. Keep OT writes out of scope until separately safety reviewed and physically isolated.

## Release gate

Until the above is evidenced on the target Windows host, mark the system **prototype/advisory only**. Never label a fixture score as measured model quality, a metadata checksum as a verified model artifact, or a simulated zero counter as network proof. A release candidate for sensitive data requires, at minimum, a signed offline bundle, reproducible real-model qualification, enforced process isolation, observed network-denial evidence, successful recovery drill, and an end-to-end high-risk document reviewed by an independent domain expert.

### Follow-up implementation

Aegis now includes a separately signed, exact-file [offline bundle verifier](OFFLINE_MODEL_TRUST.md), an offline staging signer, anti-rollback/revocation/license-policy checks, a read-only Windows process/firewall preflight, and a restore-and-verify backup drill. The plaintext legacy knowledge-upload route is demo-only. Unverified live providers can receive PUBLIC coding or image data but cannot receive INTERNAL content. These are software release gates; there is still no installed model, measured network denial, real model qualification, independently witnessed receipt, or approved industrial end-to-end artifact.

The prioritization follows [NIST AI RMF measurement and documented deployment-context validation](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/), [CISA's secure AI development and deployment guidance](https://www.cisa.gov/news-events/alerts/2023/11/26/cisa-and-uk-ncsc-unveil-joint-guidelines-secure-ai-system-development), [TUF's separated signed metadata and target hashes](https://theupdateframework.io/docs/metadata/), and [OWASP's prompt-injection and sensitive-data disclosure risks](https://genai.owasp.org/llm-top-10/).

## Validation

The final local regression suite passed: **363 passed, 2 skipped** (`python -m pytest -q -p no:cacheprovider`). The two media test modules require optional Pillow and were skipped in this environment. This verifies the implemented software behavior under tests; it does not replace live-model, Windows network-isolation, or industrial document validation.
