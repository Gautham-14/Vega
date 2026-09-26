# Security and recovery operations

Aegis applies local account checks, approved operations, loopback model transport,
encrypted short-term retention, and signed receipt chains. These controls do not
prove that a model server, its extensions, the host OS, or the GPU cannot retain
or transmit data. Use a separate local account or network-isolated VM/container
for model processes when handling sensitive data.

## Current operator state

The previously enabled `operator` account used the legacy default password.
It was disabled and all of its sessions were revoked during the security
follow-up. The operator then reset the password locally; a read-only check
confirmed that the account is enabled, the former default no longer matches,
and no old session remains. The `data/` directory and its existing contents
were given an owner-only Windows ACL. To rotate the password again:

```powershell
.\.venv\Scripts\python.exe aegis_cli.py users set operator
```

Enter the new password only at the local hidden prompt. The command re-enables
the account and revokes any sessions. Provision Data Owner and Security Officer
as separate people/accounts; never reuse the operator credential.

## Encrypted backup and restore

Stop Aegis before taking a snapshot so managed files cannot change beside the
SQLite snapshot. The backup contains the database, control key, and managed
knowledge, receipts, and retained artifacts. It excludes model weights,
temporary workspaces, and user-exported files. The archive is authenticated and
encrypted with a passphrase derived using scrypt and AES-GCM. Each archive is
bounded to 128 MiB of operational state; the command fails rather than creating
an incomplete archive. Store copies on separate media under your control.

```powershell
.\.venv\Scripts\python.exe aegis_cli.py backup create D:\Backups\aegis-2026-09-25.aegis-backup
.\.venv\Scripts\python.exe aegis_cli.py backup verify D:\Backups\aegis-2026-09-25.aegis-backup
.\.venv\Scripts\python.exe aegis_cli.py backup restore D:\Backups\aegis-2026-09-25.aegis-backup D:\Aegis-Restored
.\.venv\Scripts\python.exe aegis_cli.py backup drill D:\Backups\aegis-2026-09-25.aegis-backup D:\Aegis-Drill
```

Each command prompts locally for the passphrase; it is never accepted as a
command-line argument. `create` writes only a new owner-only file, verifies the
archive, then moves the live Windows control key to current-user DPAPI. `verify`
checks the archive authentication, SQLite integrity, file hashes, and receipt
chain. `restore` writes only to a new directory and protects the restored key
with current-user DPAPI on Windows. Test recovery by pointing a stopped Aegis
instance at that directory with `AEGIS_DATA_DIR`, then check login, receipt
verification, and representative content. Do not start two workers on one data
directory.

`backup drill` leaves a fresh restore directory, re-reads every restored
managed file and the DPAPI-protected control key, and rechecks SQLite integrity
and the receipt chain. It does not delete the drill directory. Follow it with
a manual login and representative-content check, then maintain a protected
offline copy of the encrypted archive on separate media.

Restores revoke all saved login sessions and require new execution/Capsule
approvals. The restored database therefore differs from the archived bytes;
the drill validates this intentional transformation and preserves receipt-chain
verification. Passwords still reflect the backup date: reset them if credentials
changed later or recovery follows a compromise. Missing live control keys now
stop recovery-sensitive operations instead of generating a replacement key.

DPAPI generally binds decryption to the same Windows user and machine; the
passphrase archive is the portable recovery copy. Losing both the profile and
the archive or its passphrase can make encrypted records unrecoverable. DPAPI
does not protect against compromise of the logged-in account or an administrator.
Deleting a former raw key file does not prove physical disk erasure. The archive
is a local software trust root, not an independent audit witness; place a verified
copy on protected separate media if you need to survive host loss or tampering.

This checkout has a verified encrypted archive at
`backups/live-recovery-2026-09-25.aegis-backup` (SHA-256
`c5bc9eba0a06a51b95ac6f36dd592f66f2c10f185bc275ca5213eca8fb4b960c`).
The operator entered the passphrase locally. A fresh restore succeeded and all
SQLite table contents, the 24-receipt chain, and the control key matched the live
state. The test restore directory was removed after verification. The archive is
still on the same drive as Aegis; copy it to separate protected media to cover
drive loss. Keep the passphrase separate from the archive.

## Network boundary for model servers

The Aegis launcher now accepts only numeric loopback bind addresses. Provider
requests permit numeric loopback destinations and do not follow redirects or
proxies. The host firewall is a separate control. On this Windows host the
Private and Public firewall profiles are enabled, but no Aegis-specific outbound
deny was established in this follow-up. No model server is installed yet.

After installing an exact model-server executable, preview and then apply the
outbound deny rule in an elevated PowerShell:

```powershell
.\scripts\Protect-LocalModelServer.ps1 -ExecutablePath 'C:\path\to\server.exe'
.\scripts\Protect-LocalModelServer.ps1 -ExecutablePath 'C:\path\to\server.exe' -Apply
```

Apply the same control to any helper executable that handles prompts or images.
The rule is scoped to exact executable paths and does not constrain child
processes, extensions, or other host applications. Verify the rule and server
bind address, then run an approved representative text and image task while
observing outbound traffic from the model process and its children. Test that
unapproved, expired, and revoked requests are rejected; inspect server logs and
caches after completion. A network-isolated VM/container provides a stronger
boundary than a process rule. Do not claim zero egress from simulated counters.

For Windows operation without Microsoft, Google or other vendor network
services, use the [offline setup](OFFLINE_WINDOWS_SETUP.md). Aegis's native
runtime is local-only, but application controls cannot stop Windows or unrelated
software from contacting vendors. A separate Windows network policy or physical
disconnection is required to assure host-wide network silence. The dedicated
`.venv` and model executables do not yet exist, so no process-specific outbound
deny rule has been applied or validated.

Signed offline model-file verification is now available through
`python aegis_cli.py bundle-verify`; see [offline model custody](OFFLINE_MODEL_TRUST.md).
The read-only `Test-LocalModelServerBoundary.ps1` checks a future process and
its Windows Firewall rule without claiming measured zero egress. Non-public
coding and image requests to unverified live providers fail closed. The legacy
plaintext knowledge-upload API is demo-only.

## Incident execution stop

After restarting Aegis with this code, a provisioned Security Officer can use:

```powershell
.\.venv\Scripts\python.exe aegis_cli.py login security-officer
.\.venv\Scripts\python.exe aegis_cli.py lockdown status
.\.venv\Scripts\python.exe aegis_cli.py lockdown enable
```

Lockdown defaults to off. This implementation review did not enable it on the
live database. Only the Security Officer role can change it. The setting is
stored locally with an HMAC seal and bound to its latest signed-chain receipt;
missing, changed or replayed state fails closed. Login, audit access, task
cleanup and revocation remain available. Demonstration API actions are blocked.

While enabled, the application denies new governed leases and media tasks,
provider transport and candidate qualification, and access to governed task
payloads or exports. Coding, media and document pipelines recheck authorization
after inference. A lockdown transition invalidates existing coding/document
leases and media tasks permanently, including requests already in flight when
their next authorization check runs. After investigating, use:

```powershell
.\.venv\Scripts\python.exe aegis_cli.py lockdown disable
```

Disabling lockdown permits fresh leases and newly reviewed media tasks; it does
not revive old ones. Existing retained ciphertext follows its normal cleanup
policy. Do not delete the lockdown row to reset it. Damaged state or receipt
history needs investigation and recovery from a trusted backup. A complete
rollback of the database and its signed history cannot be detected without an
independent checkpoint. Restoring an older backup also restores its historical
lockdown setting; check the setting before resuming service.

This is a cooperative application stop. It cannot terminate a separate model
server, retract a request already sent, wipe its caches/RAM/VRAM, or stop Windows
network services. Calls already past an authorization check may finish that
step before the next check denies them. If the API is unavailable, or host/model
compromise is suspected, stop the relevant processes and isolate the host using
your local administrative procedure. Run one Aegis worker per data directory.

Updating the measured coding/media implementation requires registering and
approving fresh Capsules before running new work. No existing account or
Capsule is silently reapproved by these changes.

## Request resource limits

Mutating HTTP bodies have a 15-second total receive deadline, at most four
concurrent body readers per worker, and existing 4 MB (12 MB media) size limits.
Tiny chunks accumulate in a byte buffer rather than an unbounded list of Python
objects. Invalid lengths return 400, timeouts 408, excess readers 429, and
oversized bodies 413. A reader slot is released on timeout, disconnect or
cancellation. Slots cover receiving uploads, not long-running inference.

These are application bounds, not a complete denial-of-service defence or an
OS process memory limit. Public coding status no longer reads or hashes model
files; authenticated `/api/coding/capabilities` reports verified retrieval
capabilities. The public status field `semantic_search` is now `null` with
`semantic_search_status: AUTHENTICATED_CAPABILITIES_REQUIRED`.

## Remaining acceptance work

There are no installed model weights or listeners to test. Fixture-server tests
cover app-level approvals and transport but cannot establish model quality,
server retention, GPU memory clearing, or OS isolation. The backup round-trip
and rejection tests exercise a fresh restore directory; they do not substitute
for an offline copy and a recovery drill on the actual deployment host.
