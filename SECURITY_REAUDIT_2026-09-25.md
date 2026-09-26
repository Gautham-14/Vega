# Second security review — 2026-09-25

## Decision

Aegis has stronger application controls after this review, but remains a prototype for sensitive industrial use. `Aegis.md` describes the intended end-to-end assurance system. Real model qualification, binding approved bytes to a serving process, measured process isolation, independent claim verification and a separate recovery copy remain deployment/release requirements. No model or separate backup medium is available on this PC.

## Findings and fixes

| Weakness | Change | Verification |
| --- | --- | --- |
| Approval objects could be edited in SQLite without invalidating their authorization. Receipt-chain integrity did not authenticate the approval object itself. | HMAC seals now bind approval identity, binding, action, required roles, decisions and expiry. Decision and authorization paths reject changed or unsigned records. | Mutations to decision lists, status, binding, roles and seal are rejected. |
| Restoring an old database revived bearer sessions and approved execution state. | Restore clears all sessions and marks approvals/Capsules for fresh review. The restored DB gets its own digest; the archive is unchanged. Receipt history remains verifiable. | A full encrypted backup/drill verifies sessions are absent and previous execution approvals no longer authorize work. |
| Authenticated archives could contain Windows alternate-stream/device paths, case aliases or file/directory collisions. | Every managed restore component passes portable filename validation before staging. Case aliases and parent-file conflicts are rejected. Restore rejects executable SQLite schema such as triggers and views. | Crafted authenticated archives and a session-resurrection trigger are rejected. |
| Losing the control key could cause silent creation of an unrelated replacement. | Existing receipts or protected objects require the original key. Missing-key recovery fails closed with an explicit restore instruction. | Removing the temporary test key does not create another key. |
| Some local-file helpers accessed UNC/network paths and allowed hard-link aliases. | A shared path guard rejects network/device/alternate-stream paths before filesystem access, checks mapped-drive type on Windows, and rejects reparse points and hard-linked files. CLI imports/exports, keys, backups, model bundles, configuration and SQLite use it. | Filesystem access is trapped in network-path tests; hard-linked files are rejected. |
| Offline wheel verification happened before pip consumption; `--no-index` alone did not disable dependency URL resolution. | Installation uses explicit local wheel URIs with original manifest hashes, `--require-hashes`, `--no-deps`, isolated pip settings, no cache, and a subsequent dependency check. | Tests inspect pip's consumed lock and prove inherited `PIP_FIND_LINKS` is removed. A full real wheelhouse installation remains pending. |
| Default FastAPI documentation loaded vendor CDN assets. | `/docs` is now a local static index to the OpenAPI schema; CDN-backed ReDoc is disabled. Browser CSP limits scripts, assets and connections to the local origin and forbids framing. | API tests check the local documentation and response policy. |
| Firewall preflight could accept a block rule scoped to only one profile/protocol/address. | Rule checks now include profile, application, package, address, port, protocol, service and interface scopes. The selected process must match the selected executable. Paths receive local-drive/reparse checks. | PowerShell fixtures reject partial rules; all scripts parse. No real host rule was applied or measured. |

Additional robustness changes bound archive/manifest/signature reads, stop hashing files that grow beyond their declared sizes, reject unreadable or oversized bundle inventories, include core dependencies in the full offline requirements list, and allow the qualification runner to use the legacy pinned Ollama configuration without a missing-protocol error.

## Compatibility and recovery

### Incident-control follow-up

A persistent Security Officer lockdown now gates provider calls, candidate
qualification, coding/document leases and media tasks. Signed generations
prevent old work from becoming usable when lockdown is lifted. Coding, media
and document execution check authorization after inference, and document
retention checks it again under the same lock used for incident changes.
Tampered or deleted state, a replayed older state, and damaged receipt history
deny execution. The CLI and authenticated API expose status/enable/disable.
This is a cooperative application control, not an OS process termination or
network isolation mechanism; see [operations](SECURITY_AND_RECOVERY.md#incident-execution-stop).

Request-body reception now has a total deadline, a concurrent-reader ceiling,
bounded byte-buffer accumulation and content-length consistency checks. Public
coding status no longer probes embedding/model files. Focused regressions cover
role enforcement, state tampering/replay, revoked in-flight output, permanently
stale authorizations, body timeout, reader admission and small-chunk uploads.

The review did not enable lockdown or change live accounts, keys or backups.

Restart Aegis after updating: running Python processes do not automatically load these changes. Previously stored unsigned approval records cannot authorize a new operation; request fresh approvals through the normal CLI/API. Existing independently sealed Capsules are not automatically migrated or re-signed. A restored Capsule explicitly requires reapproval. No existing live account, key, backup or model file was changed as part of these tests.

Restoration intentionally changes the authentication and approval tables, so its database digest differs from the archived database digest. The drill verifies against this defined transformation and checks the original receipt chain. Restored account passwords still reflect the snapshot date: reset credentials if they changed after that snapshot or if recovery follows a compromise. A backup is a historical copy and cannot supply later password changes or revocations.

The signature/seal keys remain protected by local software and Windows account controls. A compromised current Windows account or administrator remains outside the application-only security boundary. Signed bundles prove inspected file identity, not safe model behavior or what a running process has loaded. CSP does not constrain non-browser processes. Firewall rule inspection does not measure traffic.

## Validation

Earlier review baseline: **388 passed, 2 skipped in 245.08 seconds** with `python -m pytest -q -p no:cacheprovider`. The two skipped modules require optional Pillow. Python compilation, PowerShell parsing and synthetic firewall scope checks passed. Whitespace checks passed for the changed tracked code; unrelated pre-existing whitespace remains in `deep-research-report.md`.

Incident-control follow-up: **408 distinct tests pass, 2 optional image modules
skipped, no unresolved failures** across the full run and focused rerun. The
full run passed 406 tests and exposed two older hardening tests that omitted
control-table initialization. Correcting that test fixture (application code
unchanged) and rerunning the entire hardening module plus incident tests passed
all **67 tests in 42.00 seconds**. All 20 new incident/resource tests passed,
including revocation before image-content decryption and upload cancellation.
Results are saved locally in `.audit-tmp/incident-regression.xml` and
`.audit-tmp/incident-hardening-rerun.xml`. Python compilation and whitespace
checks for this follow-up passed. This run does not validate a real model or
the skipped image codecs/fixture-server workflows.

Tests use synthetic data and disposable storage. The existing encrypted backup still matches its previously recorded SHA-256 (`c5bc9eba0a06a51b95ac6f36dd592f66f2c10f185bc275ca5213eca8fb4b960c`). Live-model quality, image workflows with the missing dependency, a full reviewed-wheelhouse installation and real firewall denial remain unvalidated.

The installer design follows [pip's secure-install guidance](https://pip.pypa.io/en/latest/topics/secure-installs/). SQLite schema handling follows [SQLite's guidance for databases of uncertain provenance](https://www.sqlite.org/security.html).
