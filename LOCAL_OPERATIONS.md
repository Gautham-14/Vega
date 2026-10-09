# Local operational setup

Prepared on 9 October 2026 without downloading, loading or running models.
This is a development installation on Windows; production deployment still
requires the independently provisioned Linux custody and isolation controls.

## Completed locally

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
  signed out afterward. No test sessions remain active.
- Started the actual API/CLI launcher against the provisioned installation and
  cleanly exited. The managed model directory is empty.
- Completed the full pinned regression: **669 passed, 3 platform-related skips,
  no failures**. The exact skips and reports are in
  [WORKFLOW_VERIFICATION.md](WORKFLOW_VERIFICATION.md).

## Private local artifacts

These paths are ignored by Git. Their directories and files use current-user-only
Windows ACLs. The credential file contains **plaintext generated passwords and
the backup passphrase**; its protection is the local ACL. Operational control
keys use current-user Windows DPAPI.

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

In the CLI, `/login operator` securely prompts for its generated password.
`/doctor` checks the authenticated local application; `/exit` stops the session.
The default data directory is `data/`. The restored directory is a recovery drill,
not the active installation. Keep credentials and backups out of source control.

## Remaining deployment actions

1. Assign roles to separate people. Use named accounts with immutable role
   templates if needed, then let each person reset their password locally.
   Shared administration on this workstation does not prove independent human
   review.
2. Each privileged account owner must enroll their own authenticator with
   `python aegis.py cli users mfa-enroll <account>`, then sign in using
   `login <account> --mfa`. Authenticator ownership cannot be established by
   generating all seeds on behalf of the reviewers.
3. Copy the verified encrypted backup to separate offline media and keep its
   passphrase separately. Both are currently on this workstation, so this
   completed drill does not protect against loss of the workstation.
4. When models and deployment hardware exist, complete
   [DEPLOYMENT_ACCEPTANCE.md](DEPLOYMENT_ACCEPTANCE.md). The onboarding commands
   and qualification suites are in
   [WORKFLOW_READINESS.md](WORKFLOW_READINESS.md).

The local receipt chain verifies correctly. It is not independently witnessed
in this development installation. Account setup and recovery do not qualify a
future model, prove server cache erasure, or establish hardware confidentiality.
