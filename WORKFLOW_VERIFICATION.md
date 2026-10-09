# Workflow completion audit

Scope: prepare security, inference and retrieval workflows for later use with
compatible operator-selected models, without loading models or requiring a GPU.
The application does not train or convert arbitrary checkpoints into different
architectures. Real model accuracy, serving configuration and physical isolation
remain explicit deployment qualification steps.

Latest complete regression on the pinned Windows environment, 9 October 2026:

- **669 passed, 3 skipped, no failures**, in 356.11 seconds.
- Skips: Linux separate-UID custody, native POSIX ownership/modes, and the
  native symlink test because this Windows account cannot create symlinks.
- Full report: `.audit-tmp/final-operations-results.xml`; captured output:
  `.audit-tmp/final-operations-tests.log`.
- The provisioned local installation also passed authenticated role-boundary
  checks, encrypted backup verification, restored account logins and actual
  launcher startup/exit. See [LOCAL_OPERATIONS.md](LOCAL_OPERATIONS.md).

Earlier verification evidence, retained for traceability:

- Full regression: 667 passed, 2 Linux-only skips, and 3 failures in new
  supply-chain tests whose disposable database was not initialized.
- After correcting only that test setup, the complete boundary module passed
  all 6 tests, including the 3 previously failing cases. Runtime code did not
  change between these runs.
- Matching unique testcase identities across the two reports verifies 670
  passing tests and 2 platform skips, with no unresolved failures.
- Reports are saved locally in `.audit-tmp/workflow-results.xml`,
  `.audit-tmp/boundary-results.xml` and `.audit-tmp/verification-summary.json`.
  The real Windows launcher startup/exit and empty model-directory checks pass.
- The offline wheel's workflow/security modules match current source bytes;
  example and qualification schemas validate; `uv pip check` and `git diff
  --check` pass.

| Requirement | Current implementation | Verification evidence |
| --- | --- | --- |
| No models during setup | Immutable provider configuration, configuration-only preflight, adapter construction without probes | `test_preflight_never_contacts_or_loads_a_model`; `test_adapters_construct_and_report_configuration_without_model_calls` |
| Later local inference | Shared Ollama/OpenAI-compatible structured transport; adapters for Ollama, llama.cpp and vLLM | `test_actual_loopback_transport_and_schema_contract_without_weights`; `test_guarded_adapter_uses_local_structured_contract`; existing provider tests |
| Native tokenizer compatibility | Serving engine owns pretrained tokenizer/chat template; bounded input/output context; explicit JSON response mode | `test_structured_output_modes_are_explicit_and_always_locally_validated`; `test_context_guard_reserves_output_and_counts_utf8_bytes` |
| Source-grounded industrial assistance | Authenticated advisory API/CLI, encrypted immutable source revisions, read-only advisory results | `test_authenticated_api_runs_reads_and_closes_advisory_without_demo_mode`; `test_complete_workflow_discloses_only_authorized_fields_and_retains_encrypted_output` |
| Complete workload identity | Capsule binds implementation, prompt/schema, provider, retrieval and policy; changed source/configuration blocks work | `test_every_capsule_component_is_bound`; advisory source-revision and record-tampering tests |
| Identity and purpose enforcement | Short leases bind user, source revisions, equipment, skill, purpose, recipient and release; checks at disclosure, dispatch, completion and reads | Advisory wrong-user, expiry, account-reset and authorization-change tests; `test_dispatch_rechecks_authorization_before_disclosing_request` |
| Independent sensitive release | Signed bundle and separate attestor evidence, independent approval, exact release binding | `tests/test_review_fixes.py` assurance regressions; `tests/test_advisory_assurance.py` positive INTERNAL path and release-replacement tests |
| Compartment separation | Authorize sources before decryption, task-local retrieval/memory, exact approval for combined analysis | `test_combined_compartment_analysis_requires_bound_independent_approval`; `test_cache_separates_principals_compartments_and_tasks` |
| Cache isolation | Gateway-issued vLLM cache salts, llama.cpp cache disabled, no persistent application vector index | `test_vllm_cache_scope_is_gateway_issued_and_isolates_tasks`; loopback transport test checks `cache_prompt: false` |
| Real hybrid retrieval | BM25, exact/structural evidence, optional pinned CPU dense embeddings, reviewed MRL shortlist/native reranking | `tests/test_coding_retrieval.py`; `tests/test_local_models.py`; BM25/MRL regressions in `tests/test_ai_stack_depth.py` |
| Honest advanced AI features | Real MaxSim math contract; no fake ColBERT/FAISS score multipliers or BLT/parity tokenizer claims | `test_late_interaction_uses_per_query_token_maxima`; `test_packages_do_not_turn_lexical_counts_into_colbert_or_faiss` |
| Evidence quality and abstention | Exact quote/revision/field checks, independently checked finite division, labeled inferences, abstention without evidence | Advisory evidence, pathological numeric, unsupported-claim and no-relevance tests; synthetic later qualification suite |
| Untrusted instructions and output | No advisory tools/OT write connector; strict schemas and context/output inspection; malformed JSON rejected | Advisory injection test; adversarial tool/path tests; duplicate/non-finite JSON tests including numeric overflow |
| Revocation, cleanup and export | Ledger-backed irreversible revocation, encrypted sealed short-lived results, independent exact-bound export approval | Lease replay tests; advisory export/revocation/account-reset/API-close tests; coding/media retention regressions |
| Operational audit and recovery | Hash-bound receipts without raw advisory prompt/output; existing MFA, custody, witness, rollback, lockdown, quota and backup controls retained | `tests/test_security_implementation.py`, `tests/test_security_reaudit.py`, `tests/test_auth.py` and existing recovery tests |
| Usable delivery | New API routes/CLI commands, example requests, later qualification suite, all subpackages included in installable wheel | Offline `uv build`; wheel contents checked; CLI help loads; example schemas validate |
| Windows launcher readiness | Dedicated hash-pinned environment; native process-token SID lookup retains private ACLs without account lookup subprocesses | `tests/test_launch_readiness.py`; Windows wrapper test in `tests/test_platform_startup.py`; `uv pip check` |
| No simulated supply-chain approval | Active independently signed bundle custody; unsupported legacy SLSA/Cosign/TUF calls deny authorization | `test_unconfigured_supply_chain_interfaces_cannot_report_success`; signed bundle/release tamper tests |

## Verification boundary

Tests run against disposable storage, mock encoders, synthetic completions and
loopback fixture HTTP servers. Signed assurance fixtures contain dummy bytes and
synthetic process measurements; they test independent evidence verification, not
real loaded weights or a hardware TEE.

On Windows, Linux custody integration and native POSIX permission tests are
platform-specific skips. Native symlink creation can also skip when the current
Windows account lacks that capability. Optional tokenizer tests can skip when
`tokenizers` is absent. Live Linux/gVisor containment and CPU/GPU confidentiality need their
actual deployment environments. Server cache controls require independent
runtime validation; request parameters alone do not prove erasure or retention.

The local `.venv` contains the exact runtime/test versions from
`requirements-dev.lock`, installed with SHA-256 verification. Unused experimental
packages were removed from the core `requirements.txt` so it agrees with the
core dependency lock and project metadata. Optional embedding serving remains a
separate reviewed dependency/model setup. No model weights were acquired.

ColBERT encoder serving, ANN acceleration, a trained BLT architecture, custom
tokenizer training, and stateful-token architectures are not active retrieval or
inference backends. They cannot be supplied by renaming a standard model or
installing a package. The working core reports these limits explicitly. Add them
only with compatible pinned models and independently measured qualification.

See [WORKFLOW_READINESS.md](WORKFLOW_READINESS.md) for supported contracts and
the complete later onboarding sequence. Qualification commands are explicit
inference operations; preflight and registration are model-free.
