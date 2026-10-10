# Historical local operational setup

The following records describe an installation prepared on 9 October 2026
without loading or running models. On 10 October 2026, all credential, backup,
restore and verification paths listed below were absent from this checkout.
These historical records do not establish its current accounts, recovery
readiness or receipt-chain validity. Follow [QUICKSTART.md](QUICKSTART.md) to
prepare your own installation and [WORKFLOW_VERIFICATION.md](WORKFLOW_VERIFICATION.md)
for current source-regression evidence. Production deployment still requires
the independently provisioned Linux custody and isolation controls.

## Previously recorded operations (evidence unavailable here)

- Created separate `operator`, `data-owner`, `model-custodian` and
  `security-officer` accounts with independently generated passwords.
- Verified all four account identities and roles through authenticated API
  requests. Anonymous access was rejected, and Operator could not import a
  repository using Data Owner privileges. Demo identities are disabled.
- Checked the receipt chain, advisory source listing, media capabilities and
  incident-control endpoint without invoking inference.
- Created and authenticated an encrypted operational-state backup, restored it
  into a new directory, and verified restored file bytes and receipt integrity.
- Successfully signed in as all four accounts against the restored database;
  signed out afterward. The previous record reported no active test sessions.
- Started the actual API/CLI launcher against the provisioned installation and
  cleanly exited. Its managed model directory was recorded as empty.
- The previous record reported **669 passed, 3 platform-related skips, no
  failures**. Its reports are unavailable here and this is not the current
  regression result; see [WORKFLOW_VERIFICATION.md](WORKFLOW_VERIFICATION.md).

## Historical private artifact locations

These paths are ignored by Git and were absent on 10 October 2026. The historical
record described current-user-only Windows ACLs and a credential file containing
**plaintext generated passwords and the backup passphrase**. Their existence,
permissions and contents have not been verified in this checkout. Operational
control keys use current-user Windows DPAPI when provisioned on Windows.

| Artifact | Repository-relative location |
| --- | --- |
| Account credentials and backup passphrase | `.runtime/local-onboarding/20261009T171604Z-1dcaf9e6/credentials.json` |
| Setup and backup verification | `.runtime/local-onboarding/20261009T171604Z-1dcaf9e6/verification.json` |
| Actual launcher and restored-login verification | `.runtime/local-onboarding/20261009T171604Z-1dcaf9e6/launch-and-recovery.json` |
| Encrypted backup | `backups/local-operations-20261009T171604Z-1dcaf9e6.aegis-backup` |
| Fresh restore used for the recovery drill | `backups/restore-drill-20261009T171604Z-1dcaf9e6/` |

Start from the project directory:

```text
.\Aegis.bat start
```

After provisioning your accounts, `/login operator` securely prompts for the
password you assigned.
`/doctor` checks the authenticated local application; `/exit` stops the session.
The default data directory is `data/`. The historical restored directory was
used for a recovery drill and is absent here. Keep credentials and backups out
of source control.

## Remaining deployment actions

1. Assign roles to separate people. Use named accounts with immutable role
   templates if needed, then let each person reset their password locally.
   Shared administration on this workstation does not prove independent human
   review.
2. Each privileged account owner must enroll their own authenticator with
   `python aegis.py cli users mfa-enroll <account>`, then sign in using
   `login <account> --mfa`. Authenticator ownership cannot be established by
   generating all seeds on behalf of the reviewers.
3. Create and verify a new encrypted backup for your current installation, run
   a restore drill, copy the backup to separate offline media and keep its
   passphrase separately. The historical backup and passphrase are absent here.
4. When models and deployment hardware exist, complete
   [DEPLOYMENT_ACCEPTANCE.md](DEPLOYMENT_ACCEPTANCE.md). The onboarding commands
   and qualification suites are in
   [WORKFLOW_READINESS.md](WORKFLOW_READINESS.md).

The previous record reported a valid local receipt chain without independent
witnessing. Run `/doctor` after signing in to verify your current installation.
Account setup and recovery do not qualify a future model, prove server cache
erasure, or establish hardware confidentiality.
