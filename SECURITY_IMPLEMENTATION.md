# Security implementation and deployment

The local development workflow remains available. Production is an explicit
profile with stricter prerequisites; configuration alone is not certification.
No operational accounts, keys, models, firewall rules or services on the user's
Windows host were changed by this implementation.

## Implemented controls

| Area | Implementation |
|---|---|
| Process isolation | Reviewed systemd profiles separate API, model, key, witness, attestor and validation identities. Model/API share a private network namespace with only loopback. A host loopback socket proxy exposes the authenticated API. |
| Key custody | Production uses a kernel-authenticated Unix socket broker. Signing and encryption keys are independent and versioned. RPC cannot export/derive keys, rotate keys or choose file paths. Old keys remain available for historical verification/decryption. |
| Audit rollback | A separate, durable witness accepts only contiguous hash commitments for an administratively enrolled installation. An older local database or a fork of an acknowledged chain fails closed. Unacknowledged but valid local suffixes are reconciled after a crash. |
| Runtime evidence | A root-owned attestor policy pins the service, argv, independently signed bundle and qualification. The attestor checks UID, private network namespace, interfaces, process identity, executable hash and mapped weight inode/hash. It verifies restrictions and disables durable logging/cache retention. |
| Incident stop | Lockdown is persisted before supervisor termination. Failure to confirm termination remains an error with application execution locked. Repeating enable retries stopping. |
| Privileged access | TOTP enrollment/reset is host administration. Production custodians and security officers require MFA. Privileged sessions expire after 15 minutes, sensitive mutations require verification within 5 minutes, and each account has at most 3 active sessions. OTP reuse and repeated guessing are blocked. |
| Availability | Cross-process admission limits HTTP/inference concurrency and renews live leases. Disk/database/object/ledger quotas bound growth; security-event diagnostics have retention. Authenticated audit receipts are never silently pruned. |
| Recovery | Backup requires an OS quiescence lock. Archives include versioned keyrings; restore revokes sessions, active admission and execution approvals. Recovery drills verify restored bytes and the historical chain. |
| Releases | Universal, pinned SHA-256 dependency lockfiles; CycloneDX SBOM; complete Ed25519-signed application inventories; independent publisher pins, minimum release versions and revocation. CI runs tests, dependency audit, static analysis and Linux peer-credential integration. |
| Adversarial evaluation | Deterministic regressions exercise unauthorized tools, injected instructions, host paths and weakened supervisor settings. `evaluations/security-text.json` runs synthetic injection/disclosure cases against actual registered text providers. |

## Local account and key administration

Use the dedicated environment and the same `AEGIS_DATA_DIR` as the API.

```text
python -m aegis.cli users mfa-enroll security-officer
python -m aegis.cli login security-officer --mfa
python -m aegis.cli step-up
```

Enrollment displays the authenticator seed once. Store it in an authenticator;
never put seeds or verification codes in command arguments or logs. Resetting
MFA revokes sessions and retained work. Verification codes have a 30-second
period, a one-step clock window and persistent replay prevention.

For a development keyring, stop Aegis before migration or rotation:

```text
python -m aegis.cli keys init
python -m aegis.cli keys status
python -m aegis.cli keys rotate
```

Windows keyrings are DPAPI protected; POSIX files use owner-only permissions.
Do not delete older versions until all retained ciphertext has been migrated
and archival verification requirements have been resolved. Rotation changes
future writes; it does not erase older backup keys.

## Hardened Linux deployment

The systemd files in `deploy/systemd` are deployment templates for a trusted,
maintained Linux host with systemd network/mount namespaces. The initial model
adapter is a reviewed mmap-based llama.cpp CPU server with pinned GGUF files.
Windows/macOS production operators use the isolated guest backend described in
VM_DEPLOYMENT.md, with these same independent guest-side services. Other serving
engines still need independently reviewed isolation/attestation adapters. No
VM installation or real infrastructure acceptance was performed on this device.

1. Verify an application release with the separately pinned publisher policy.
   Install immutable, root-owned application files at `/opt/aegis`. Create the
   dedicated environment from `requirements.lock` using a reviewed offline
   wheelhouse and `--require-hashes --no-index`. Optional media/tokenizer
   dependencies are included in `requirements-dev.lock`; optional embeddings
   require a separately reviewed and pinned deployment dependency set.
2. Create static accounts `aegis`, `aegis-model`, `aegis-key`, `aegis-witness`,
   `aegis-validator`, `aegis-proxy`, and the shared `aegis-custody` group. Only
   the runtime and custody services join that group. Do not grant `aegis` Docker
   access. The validator alone has Docker access and accepts fixed commands.
3. Provision `/etc/aegis/custody.env` with `AEGIS_RUNTIME_UID=<aegis UID>`.
   Provision `/etc/aegis/runtime.env` with the actual numeric
   `AEGIS_KEY_BROKER_UID`, `AEGIS_AUDIT_WITNESS_UID`, `AEGIS_ATTESTOR_UID=0`,
   `AEGIS_INSTALLATION_ID` (32 lowercase hex digits), and
   `AEGIS_PROVIDER_TRUST_POLICY` pointing to a separate pinned attestor public
   key policy. Do not enable demo endpoints. Root owns these files and their
   directories; runtime identities cannot modify them.
4. Create protected `/var/lib/aegis-key` and `/var/lib/aegis-witness` under their
   service owners. After creating all static accounts, install and apply
   `aegis-tmpfiles.conf` to create the API/custody directories before services
   start. Under `aegis-key`, run
   `python -m aegis.security.key_custody init --keyring /var/lib/aegis-key/control.keyring`.
   Under `aegis-witness`, run
   `python -m aegis.security.audit_anchor enroll --database /var/lib/aegis-witness/witness.db --installation <ID>`.
   Enrollment of an existing ledger must use its independently verified current
   sequence/hash. An existing witness installation cannot be overwritten.
5. Provision an independently reviewed model bundle under
   `/opt/aegis-bundles/default`, with root-owned files not writable by runtime
   identities. Adjust the model service's exact pinned paths, alias, port,
   arguments and memory budget for that bundle. Logging and prompt caching
   must stay disabled. Create root-owned `/etc/aegis/model-default.env`, with
   only reviewed model settings and no API/custody secrets.
6. Install and start key/witness/attestor/model/API service templates. The
   attestor can initially have an empty provider map while PUBLIC registration
   and policy provisioning are completed. The API's production startup verifies
   custody and the independent ledger. Provision real accounts using the
   runtime UID/environment and enroll all privileged accounts in MFA. On this
   deployment, host CLI administration must run as `aegis`, because custody
   sockets deliberately reject other UIDs, including root.
7. Register the provider and bundle, then populate the root-owned attestor policy
   from independently reviewed metadata. It contains `signer_id`, `private_key`
   and `providers`. Each provider entry contains `unit`, `argv`, `endpoint`,
   `bundle_directory`, `bundle_trust_policy`, `provider_configuration_sha256`,
   `bundle_record_id`, `qualification_id` and `qualification_sha256`. Generate
   the separate Ed25519 private key outside the application/bundle and grant
   only root access. Run PUBLIC qualification first; an empty or failing suite
   never grants release approval.
8. Run `python -m scripts.check_deployment --policy /etc/aegis/attestor-policy.json --provider <ID>`
   as the Linux host administrator. It tests IPv4/IPv6/DNS blocking and denial
   of runtime/key/witness/Docker paths inside the model's actual namespaces,
   using only synthetic network probes and opening no protected file contents.
   Then import fresh evidence with `provider-attest-supervised <ID>` and obtain
   independent Model Custodian/Data Owner approvals before activation. Evidence
   expires after five minutes; use `provider-refresh-supervised <ID>` to refresh
   unchanged evidence within the existing
   fifteen-minute approval window. Restarted or changed processes need review.
9. Optionally install Docker/runsc and an already installed SHA-256-pinned test
   image. Configure `/etc/aegis/validator.env` with `AEGIS_SANDBOX_IMAGE`.
   Start `aegis-validator.service`, and add the same image pin plus
   `AEGIS_SANDBOX_BROKER_SOCKET=/run/aegis-validator/service.sock` and
   `AEGIS_SANDBOX_BROKER_UID` to the API environment. A missing or mismatched
   validator fails closed. Validate its real containment before enabling code
   execution in a production Capsule.

The socket-proxy executable path varies across Linux distributions; review
`aegis-proxy.service` against the installed systemd package. After lockdown stops
the model, restart the model and API together to establish the shared private
namespace again, then obtain fresh authorizations.

## Offline releases and recovery

```text
python -m scripts.release_security build <source> <new-output-outside-source> --private-key <publisher-key> --version 1
python -m scripts.release_security verify <release> --trust-policy <independent-policy>
python -m scripts.release_security sbom <new-sbom.json>
```

The release policy contains `public_key_path`, the SHA-256 of its raw Ed25519
public key in `public_key_sha256`, `minimum_version`, `expires_at`, and optional
`revoked_manifest_sha256`. Advance minimum versions during reviewed updates.
Use `SOURCE_DATE_EPOCH` for reproducible manifests. The offline setup script's
existing exact wheelhouse hash verification remains required.

Stop API and key services before broker rotation or offline recovery export.
Rotate under the broker identity with `key_custody rotate --keyring <path>`.
The broker holds an OS lock and refuses concurrent key rotation. Keep encrypted
backups of the broker keyring separately from runtime data. An offline Linux host
administrator creates the combined archive using
`python -m scripts.offline_recovery --runtime-data /var/lib/aegis --broker-keyring /var/lib/aegis-key/control.keyring --archive <new-backup>`.
This reads the keyring under the administrator identity and stages a coherent
snapshot privately; no key is exposed to the API identity. Live RPC never
exports it. `AEGIS_RECOVERY_KEYRING` also supports separately staged offline
archives. Restore to a new
directory and use `backup drill` before switching operational storage.

A restore older than the witness fails closed by design. Reconcile from a backup
that includes all witnessed receipts, or explicitly establish a new installation
after incident review; never reset the old witness to make stale state pass.
Keep witness state and exported commitments on independently controlled offline
media as well: a rollback of the entire host, including its witness, is outside
the protection of a witness stored on that same host.

## Validation and limits

Verified on Windows with Python 3.12.14:

- Full regression suite: **579 passed, 3 skipped**.
- Subsequent focused authentication, recovery, coding, media and adversarial
  checks: **169 passed**; final release, supervised-refresh, assurance and CLI
  checks: **91 passed**. These runs overlap and are not additive test totals.
- All **38** locked dependencies passed compatibility checks and a `pip-audit`
  scan with **0 known vulnerabilities** at the time of the scan.
- Bandit's medium/high severity, high-confidence gate reported **0 findings**.
- Syntax compilation, CLI help/SBOM smoke checks and `git diff --check` passed.

Skipped checks cover Linux root peer credentials, native POSIX permissions and
the unavailable reviewed local bootstrap interpreter. No Linux distribution or
running Docker engine was available for native containment validation.

Automated unit/regression tests use synthetic data. The CI Linux root job tests
real separate-UID peer rejection. Systemd containment, real gVisor execution,
real model injection behavior and recovery on the target host must be exercised
there; this Windows workspace cannot establish those deployment properties.

The key broker prevents key export, but a compromised authorized API process can
still invoke permitted cryptographic operations. Host root remains trusted.
Hardware TPM custody, secure boot attestation, physical RAM erasure, phishing-
resistant hardware MFA and off-host witness transport are not claimed.
Prompt-injection filters and preliminary model suites are supplementary;
deterministic tool, role, snapshot and release gates remain the authority.

Full audit validation streams historical rows and remains linear in history;
the receipt quota bounds its cost. Authenticated segment indexing is a future
performance improvement that must preserve detection of historical tampering.
