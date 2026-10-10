# Reviewed guest provisioning examples (not installed)

These files are source templates, not a guest image, installer or acceptance
report. The owner declined VM installation/testing on the current device.
No command below should be run there without new authorization. The native
operator may run on Windows, macOS or Linux; these services belong **inside
the reviewed Linux guest**, not on the operator host.

## Guest baseline for later provisioning

1. Independently acquire/review the guest OS, Python, pinned application wheel,
   provider engine, container/sandbox images and model inventories. Install
   the application into `/opt/aegis/.venv`; the example assumes the source
   compatibility launcher `/opt/aegis/run_aegis.py` is also present.
2. Provision distinct `aegis`, `aegis-key`, `aegis-witness`, `aegis-validator`
   and attestor identities/permissions from `deploy/systemd/`. Do not merge
   their identities or put custody keys in the model/application account.
3. Prepare `/etc/aegis/runtime.env` and the separate service environment files
   with the real production prerequisites described in SECURITY_IMPLEMENTATION.md.
   Provision accounts/MFA and exact-bound provider approvals, not demo accounts.
   Keep `AEGIS_LOCAL_MODELS_CONFIG` empty for this production template: native
   PUBLIC auto-chat is not a hardened provider qualification/release.
4. Review `aegis-vm-bridge.service` alongside the existing API/model units. Its
   private network namespace joins `aegis-api.service`, which in turn joins
   the qualified provider namespace. The bridge uses the restricted API UID,
   not root, and must reach the fixed guest `127.0.0.1:8000` API. The bridge
   checks production prerequisites and configured, non-demo accounts itself.
5. Review `99-aegis-virtio.rules` for the guest's udev version. Only the named
   `org.aegis.api` character device is owned by `aegis` with mode `0600`.
   The service's closed device policy grants only that extra device. Verify
   the actual node, UID, mode and service device access on the guest; text
   checks are not a substitute for this acceptance.
6. Map all writable application, custody, witness and sandbox state to the
   explicitly provisioned state disk. The raw root disk is mounted read-only
   by QEMU. Guest mount/overlay policy, crash-safe persistence, backup recovery
   and sandbox filesystem requirements need independent review; no generic
   image builder is supplied to guess these decisions.
7. Install/enable the reviewed services only during later authorized guest
   provisioning. Archive the resulting immutable root image and its digest;
   retain mutable state separately. Changing the guest requires new review.

## Host inventory for later acceptance

`policy.example.json` illustrates schema 1, not deployable settings. Replace
every path with an absolute local host path and every zero hash with its
reviewed digest. Windows paths are examples; use POSIX paths on macOS/Linux.
Choose `tcg` for portability; `whpx`, `hvf` and `kvm` are permitted only on
their corresponding x86-64 host platforms. Non-x86 hosts currently use TCG.

The runtime policy verifies the QEMU executable, immutable raw root, complete
firmware directory and TLS server certificate. Host OS/QEMU dependencies are
still part of infrastructure inventory/review, not fully measured hardware
attestation. The state disk must be a distinct, nonempty raw file. Its content
is deliberately not immutable; application recovery verifies stored state.

Provision a dedicated reviewed CA and server/client identities. The host TLS
directory needs `ca-cert.pem`, `server-cert.pem`, `server-key.pem`,
`client-cert.pem`, and `client-key.pem`. Server identity needs the `localhost`
DNS SAN and server-auth usage; the client needs client-auth usage. Pin the
SHA-256 of the server certificate's **DER bytes**, not PEM text. Do not share
these identities with guest custody/attestation services. The host owns both
transport sides, so this transport does not protect secrets from host admins.

For an approved, already provisioned inventory, the read-only command is:

```text
aegis-vm check --policy <absolute-local-reviewed-policy.json>
```

Only a later explicit VM start boots infrastructure. No automatic QEMU download,
guest download, certificate generation or fallback is implemented. Review
VM_DEPLOYMENT.md limitations and complete DEPLOYMENT_ACCEPTANCE.md on each
intended host before claiming hardened-production parity.
