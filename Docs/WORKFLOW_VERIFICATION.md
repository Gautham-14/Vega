# Workflow completion audit

## Current software verification: 10 October 2026 (Asia/Kolkata)

**754 passed, 3 skipped, 0 failed**, with one existing Starlette/HTTPX
deprecation warning, in **425.20 seconds** on Windows 11 build 26200,
Python **3.14.7**. The fresh local **source release gate passed** for application
version **1.0.0**, including dynamic GGUF routing, the VM host/guest source,
and the concurrent CLI registration/goal changes. The earlier interrupted
verification has now been completed. The three failures in the first rerun
were outdated launcher test doubles; they now verify owned Windows process-tree
shutdown rather than the previous single-process termination contract.

Ruff lint/format pass for all 202 Python files in scope. Strict mypy passes for
the configured two security-sensitive modules, not the entire application.
UTF-8/version checks, compilation, `pip check`, fresh hash-pinned wheel install,
all three console commands, piped plain shell and installed API startup pass.
The package smoke test explicitly disables operator model configuration.
Both development/CLI dependency audits found no known vulnerabilities; the CI
Bandit medium/high-severity, high-confidence threshold passes, with other
informational findings remaining. The SBOM was regenerated.

Every critical coverage module remains above its enforced 80% floor:
auth 86.80%, policy 88.51%, recovery 80.40%, coding dispatch 85.65%, advisory
dispatch 94.37%, and media dispatch 82.52%. Overall combined statement/branch
coverage is **75.50%**; added source contains unexercised paths, so this is not
a claim of complete coverage or security.

Skips: Linux root/separate-UID custody; symlink creation unavailable to this
Windows account; native POSIX owner/mode semantics. They remain target-platform
acceptance obligations, not passing tests.

The tests ran on the uncommitted working tree based on commit
`7a5b874430602be28dd05cb7f83f9276dd33e76c`. Its verified source SHA-256 is
`74309bf2f8dff4f55762c60574b0ad08be2c0036227c34c412a01de1e5726da1`.
The lock hashes below are unchanged. Machine-readable evidence is retained in
[verification/latest.json](verification/latest.json); full generated reports
are ignored under `.audit-tmp/completion-final-20261010/`:

- `results.xml`: `d2a124e1a2be9ba23753430b16b3ddefbb6a3365fb13beafabe65a2eb347ded9`.
- `coverage.json`: `b832a19f7a59b9c3826ed40f9cdce2c0c7d49bcaa0dbf7b4a565d929edf26a25`.
- `package.json`: `1bdda03135982b7d8a7b2b103ea04ccfaa92bb42d3f2f9235f37f977b135d50c`.
- `verification.json`: `4fe35011cbe6c60a2814c9b58c21116f1ddd2e65dc675923cd84c7cc3a07b5d3`.
- `wheel/aegis_runtime-1.0.0-py3-none-any.whl`:
  `40246cc95b2717f3d43952c28e50fd8b27bad0182709dd5aec3c86dcc0e0e57f`.

**Model quality is NOT qualified.** Two identical 12-case synthetic PUBLIC
probes selected the expected local alias in **12/12** cases, but only **7/12**
narrow fact/AST answer checks passed. Diagnostics revealed incorrect heat-flow
direction, JavaScript instead of requested Python, and missing blue/green color
answers. No generated code was executed and no operator data used. Reports are
`.audit-tmp/completion-20261010/local-model-evaluation.json` and its diagnostic
counterpart; see LOCAL_MODELS.md for limitations and reproducible commands.

**Infrastructure is NOT accepted.** No VM was installed or booted, as instructed.
Restricted guest service/device templates and a deliberately non-deployable
placeholder host policy are supplied in `deploy/vm/`; software tests do not
validate guest provisioning, isolation, hardware or model quality.

The owner authorized publishing a new branch for the expanded Windows/macOS/
Linux Python 3.11-3.14 CI matrix. Its result is separate from this local record.
The last remote base-commit run passed Windows/Linux Python 3.11/3.12 and custody/
dependency jobs only; it does not certify the newly expanded matrix or changes.

Original maintenance scope: prepare security, inference and retrieval workflows
for later use without loading models or requiring a GPU. The owner subsequently
authorized connecting the local models and explicit synthetic PUBLIC inference.
The application does not train or convert arbitrary checkpoints into different
architectures. Real model accuracy, serving configuration and physical isolation
remain explicit deployment qualification steps.

## Historical maintenance snapshot: 10 October 2026 (superseded)

**Historical qualification:** after the passing run below, a concurrent edit
to `aegis/operator/shell.py` added `/clear`, briefly added `/cls`, then removed
that alias; `tests/test_cli_experience.py` also changed. These concurrent edits
were preserved. The latest full rerun returned **699 passed, 3 skipped, 0 failed**
in **255.69 seconds**, but source changed during that run. The release gate
correctly rejected its snapshot mismatch. At that time final verification was
pending coordination with the concurrent shell work; the prior PASS must not
be reused for the current source. The earlier passing gate record is archived
locally as `.audit-tmp/verified-62ec28d5.json`.

The results, coverage, package report and wheel paths below were reused by later
checks. Their historical hashes describe the passing snapshot; do not assume
the files at those paths still have those hashes. Regenerate and archive a
consistent set after the current working tree is stable.

**698 passed, 3 skipped, 0 failed**, with 1 Starlette/HTTPX deprecation warning,
in **321.96 seconds**. The run started at 11:39:45 IST and exercised 701 cases
under Windows 11 build 26200, AMD64, Python **3.14.7**.

The local **source release gate passed**: fresh reports, unchanged source/locks,
consistent application version **1.0.0**, UTF-8 validation, Ruff lint/format,
incremental strict mypy, critical coverage and fresh wheel installation.
Mypy currently covers schema migrations and production prerequisites (two
modules), not the entire application. Ruff checks/formats all 185 Python files
in its configured scope; import cleanup preserves pytest fixture registration.

| Critical module | Combined statement/branch coverage |
| --- | --- |
| Authentication | 86.80% |
| Role/label/approval policy | 88.51% |
| Encrypted recovery | 80.40% |
| Coding provider dispatch | 85.65% |
| Advisory dispatch | 94.37% |
| Media dispatch | 82.52% |

Each critical module has an enforced 80% floor. Overall application
statement/branch coverage is **78.26%**; this is not a claim of complete security.
The three skips remain Linux root/separate-UID custody, native POSIX owner/mode
semantics, and symlink creation unavailable to this Windows account.

Current source and artifact identities:

- Base commit: `7a5b874430602be28dd05cb7f83f9276dd33e76c`.
  The working tree is uncommitted; this commit does not contain the changes.
- Tested source SHA-256:
  `62ec28d5489f2e4f1a4e89e901e38f46285314246b3240e5f2c26bcad9a505a2`.
  `scripts.project_checks` includes tracked and new non-ignored files, excludes
  Markdown and the reserved `verification/latest.json` evidence path, sorts
  repository-relative paths, then hashes each UTF-8 path, NUL byte and binary
  SHA-256 content digest. Generated/private ignored files are not inventoried.
- JUnit `.audit-tmp/results.xml`:
  `79f56bd46806b603af4d0be5b3f399538796a4026ff835ea8564aac891fd41c3`.
- Coverage `.audit-tmp/coverage.json`:
  `78413fab45327bac460e18238d07fe384baf73761291aaefa223d657a2f6acdb`.
- Package report `.audit-tmp/package.json`:
  `d92ac3074616a19903e8f9046a5de9551d18030f1140ff484e21bc36f1846f6a`.
- Wheel `.audit-tmp/wheel/aegis_runtime-1.0.0-py3-none-any.whl`:
  `7bc62d22e7ac30352b8ae5590b439a3fbeb8d7fd1becfdd767222789e1c1b590`.
- Machine-readable source snapshot and verification:
  `.audit-tmp/source-snapshot.json`, `.audit-tmp/verification.json`.
  These current local artifacts exist but are ignored and absent in a fresh
  checkout; reproduce and archive them using [RELEASE.md](RELEASE.md).

Dependency lockfile SHA-256 hashes for this run:

```text
requirements.lock          cc3ad78616db7cca1cc124c300ba7a263f9c757cd7d704f0182d01ef38371cc3
requirements-dev.lock      39683ae7d7ff802375a7b40930c4c4389c58ba064e99401d78e370701534b221
requirements-cli.lock      88cba40ed5a79b929f456c91392fa83b8c9284cfe35a374c433d344d72ee0805
requirements-quality.lock  f86b9cfc2866975ffab2bdf4280b66579b47c21b7502977c87316166483c53c9
requirements-security.lock e663d63534464b5257272a844817f36abb582721e5bf51135525e29bb549c9c9
```

The optional CLI dependency is now pinned in both the CLI and development
profiles. Quality/build tools have their own reviewed hash-pinned profile.
The clean wheel test compared all bundled Python/JSON files to current source,
installed outside the checkout with hash-pinned dependencies, checked metadata
and bundled skills, invoked both console commands, consumed piped plain-shell
input, started the unauthenticated-disabled-demo API and shut down its Windows
process tree. No model was downloaded or loaded.

Additional checks passed: compilation of package/scripts/tests/root launchers,
`pip check`, dependency audits of the development and CLI profiles, the CI
Bandit severity/confidence filter, and `git diff --check`.

CI now schedules Python 3.11–3.14 on Windows and Linux, with a separate Linux
root custody job and archived verification artifacts. Those remote jobs were
**not executed from this local session**. Repository branch protection must
be enabled by the owner. Actual hardened Linux/provider/model-hardware
acceptance remains **not performed**; see DEPLOYMENT_ACCEPTANCE.md.

## Previous priorities 1–7 regression: 10 October 2026 (superseded)

The following record identifies the earlier working tree and locks, not the
current maintenance source. Its optional-dependency limitation is now resolved.

**675 passed, 3 skipped, 0 failed**, with 1 dependency deprecation warning, in
290.14 seconds. The run started at 11:08 IST and tested 678 cases.

- Current JUnit report: `.audit-tmp/priority-1-7-results.xml` (generated locally,
  ignored by Git; not included in a fresh checkout).
- Report SHA-256:
  `aa6c0a42b49c546fa7f275f676cc6d1e390998cce7e0f3bd24b398c4474bc46f`.
- Skips: Linux root/separate-UID custody integration, native POSIX owner/mode
  semantics and symlink creation unavailable to this Windows account.
- Warning: Starlette's current `TestClient` deprecates the installed HTTPX
  transport. The warning did not fail tests; dependency migration remains
  separate from the priorities 1-7 fixes.
- Both plain and default launcher modes started the local API, consumed piped
  `/exit` input, shut down cleanly and left the model directory empty.

The initial review run returned **661 passed, 4 failed, 7 skipped**. The changes
for priorities 1-7 address plain/redirected shell startup, live hardware
dependencies in demo tests, the PowerShell fixture invocation and CI compilation
targets. The current source also includes the purple ASCII layout correction.

Tested environment and source identity:

- Windows 11, build 26200, AMD64; Python **3.14.7** in the project's `.venv`.
- Base commit: `7a5b874430602be28dd05cb7f83f9276dd33e76c`. This is the base
  commit, not a commit containing these uncommitted changes.
- Tested source SHA-256:
  `68a5396d957659b7702d42f32acd1bff818b7e790e5c24b84c26b91151d77828`.
  This fingerprints 202 tracked files excluding Markdown, sorted by
  repository-relative path: hash the concatenation of each UTF-8 path, a NUL
  byte and the binary SHA-256 digest of that file's current bytes. Markdown is
  excluded so writing this evidence record does not change the tested identity.
- Pytest 9.1.1, FastAPI 0.142.2, Starlette 1.7.0 and HTTPX 0.28.1.
- Optional CLI packages already installed: `prompt_toolkit` 3.0.53 and
  `wcwidth` 0.9.2; these are not currently covered by `requirements-dev.lock`.
- Git for Windows was added to the test process's PATH so Git-dependent tests
  execute. This does not change the workstation's persistent PATH.
- Demo workflow tests explicitly select `PROFILE_WORKSTATION` and reject live
  hardware detection; the application's default remains `REAL`.

Dependency lockfile SHA-256 hashes:

```text
requirements.lock          cc3ad78616db7cca1cc124c300ba7a263f9c757cd7d704f0182d01ef38371cc3
requirements-dev.lock      95e9f0c7f1d5e3a9f478c2840e45ccb0de8e49bebfaede88fb7c3aa8b09fa799
requirements-security.lock e663d63534464b5257272a844817f36abb582721e5bf51135525e29bb549c9c9
```

Reproduce the full regression from the repository root in PowerShell:

```powershell
# Use an installed Git if it is not already on PATH (adjust its location).
$env:PATH = 'C:\Program Files\Git\cmd;' + $env:PATH
.\.venv\Scripts\python.exe -m pytest -q -ra -p no:cacheprovider --junitxml=.audit-tmp/priority-1-7-results.xml
```

Additional checks passed: `pip check`, `pip_audit` against the development lock
with hash verification, the CI Bandit severity/confidence filter, compilation
of `aegis`, `scripts`, `tests` and the three root Python launchers, and
`git diff --check`. These checks do not replace deployment acceptance.

## Historical reports (not available in this checkout)

The following are previously recorded results from 9 October 2026. Their ignored
reports were absent when checked on 10 October 2026 and could not be reverified.
They do not describe the current working tree.

- **669 passed, 3 skipped, no failures**, in 356.11 seconds.
- Skips: Linux separate-UID custody, native POSIX ownership/modes, and the
  native symlink test because this Windows account cannot create symlinks.
- Historical full report: `.audit-tmp/final-operations-results.xml`; captured output:
  `.audit-tmp/final-operations-tests.log`.
- The previous record reported successful authenticated role-boundary checks,
  encrypted backup verification, restored account logins and actual launcher
  startup/exit. See [LOCAL_OPERATIONS.md](LOCAL_OPERATIONS.md).

Earlier reported verification, retained as historical context:

- Full regression: 667 passed, 2 Linux-only skips, and 3 failures in new
  supply-chain tests whose disposable database was not initialized.
- After correcting only that test setup, the complete boundary module passed
  all 6 tests, including the 3 previously failing cases. Runtime code did not
  change between these runs.
- The previous analysis reported 670 matching passing testcase identities and
  2 platform skips across the two reports. Those reports are unavailable here.
- Historical report locations: `.audit-tmp/workflow-results.xml`,
  `.audit-tmp/boundary-results.xml` and `.audit-tmp/verification-summary.json`.
  The previous record reported successful Windows launcher startup/exit and
  empty model-directory checks.
- The previous record reported wheel/source agreement, valid example and
  qualification schemas, and passing `uv pip check` and `git diff --check`.
  Wheel build/install verification has not been repeated for this working tree.

## Implementation and test references

The table maps implemented behavior to tests or historical checks. A named test
does not establish real model, hardware or production deployment acceptance.

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

Runtime/test dependencies in `.venv` were installed from
`requirements-dev.lock` with SHA-256 verification. Additional optional CLI and
audit tools are identified in the current regression record; the environment is
not a pristine installation containing only that lockfile. Unused experimental
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
