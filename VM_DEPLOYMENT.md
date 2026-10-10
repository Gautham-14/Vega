# Isolated VM backend: source implementation only

Aegis's native operator and development runtime target Windows, macOS and Linux.
For hardened production the owner selected an isolated Linux guest on those
host platforms, reusing the independent custody/witness/attestor and sandbox
services. Native Linux services remain another deployment option.

The `aegis-vm check/start --policy <absolute-local-policy>` launcher, bounded
mutual-TLS virtio-serial API bridge and strict QEMU inventory are implemented.
The fixed command includes no NIC, shared folders, clipboard, GUI or passthrough.
Root/state images are explicit raw disks, root read-only. Executable, firmware,
root image and TLS server identity need reviewed SHA-256 pins. Imports and
inventory checks do not provision infrastructure; startup explicitly protects
mutable files. The API gateway is IPv4 loopback only and preserves guest
authentication/authorization; there is no native or plaintext fallback.

The owner explicitly declined VM installation and infrastructure acceptance
testing on this device. No guest image is supplied here; no VM was installed or
started. The guest needs separate static service identities, production
configuration, provisioned accounts/MFA, reviewed providers and sandbox images,
a named `org.aegis.api` virtio character device accessible to the restricted API
identity, and `python -m aegis.vm.guest` in the API network namespace. Provision
and independently review these inside the guest using SECURITY_IMPLEMENTATION.md.
There is no unattended guest-image builder or accepted production bundle.
Source-only provisioning examples now live in [deploy/vm/README.md](deploy/vm/README.md):
a restricted bridge service, narrowly scoped virtio ownership rule and a
schema-1 host policy with zero hashes that intentionally fail validation.
No example was installed, enabled or run on this device.

The current x86-64/q35 BIOS guest profile uses portable TCG by default; explicit
KVM/WHPX/HVF acceleration requires a matching x86-64 host. Apple Silicon uses
TCG, not an implemented ARM-native guest. GPU passthrough is not implemented.
The host administrator/hypervisor remain trusted; VM isolation is not hardware
confidential computing. Shutdown currently terminates the owned process rather
than performing an orderly guest shutdown; crash-safe storage/recovery needs
acceptance. HTTP messages are bounded, serialized, and do not support streaming,
WebSockets or chunked uploads. Native `users`/`backup` commands administer host
storage, not the guest: perform guest administration inside its reviewed console.

QEMU's [TLS guide](https://www.qemu.org/docs/master/system/tls.html) and
[invocation reference](https://www.qemu.org/docs/master/system/qemu-manpage.html)
describe the transport. Before release, qualify real host/guest isolation,
identity separation, certificates, recovery and model behavior on each intended
platform under DEPLOYMENT_ACCEPTANCE.md. Software tests are not that acceptance.
