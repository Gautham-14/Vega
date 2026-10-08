# Aegis

Local Python AI runtime with authenticated accounts, role-based approvals,
purpose-bound coding and media tasks, encrypted retained output, and a local
receipt ledger. Python 3.11 or newer is required.

The operator interface is the CLI. Start with [QUICKSTART.md](QUICKSTART.md).
The API binds to numeric loopback; `/docs` serves local, offline documentation.

The `reference` provider and industrial demos are deterministic fixtures. Live
models require an explicitly configured local server. Internal data additionally
requires a verified offline bundle and an independently approved, short-lived
provider release. See [PROVIDER_ASSURANCE.md](PROVIDER_ASSURANCE.md).

Production custody, MFA, independent audit anchoring, hardened Linux services,
signed releases and recovery procedures are documented in
[SECURITY_IMPLEMENTATION.md](SECURITY_IMPLEMENTATION.md). Production mode refuses
startup when independent custody or audit prerequisites are missing.

Run tests in the dedicated environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Test storage is disposable and separate from the application's `data` directory.
Windows tests exercise current-user DPAPI and file ACLs; they need a normal
Windows user context. Linux/gVisor execution and real model quality require
separate deployment validation.
