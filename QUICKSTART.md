# Open and use Aegis

Aegis has one launcher for Windows, Linux and macOS. It runs on your computer;
no Microsoft, Google or other cloud account is needed. It does not download
Python, dependencies or models. Python 3.11+ and a reviewed offline dependency
bundle are needed once before first use.

## 1. One-time setup

Open a terminal in the Aegis folder. Use the command for your system:

| System | Setup command |
| --- | --- |
| Windows | `.\Aegis.bat setup` |
| Linux | `sh ./Aegis.command setup` |
| macOS | `sh ./Aegis.command setup` |

Setup asks for two local paths: your reviewed wheelhouse folder and its trusted
SHA-256 manifest. It creates `.venv` and installs from those files only. You do
not need to activate the environment. Existing `.venv` directories are never
overwritten; inspect a failed setup before attempting replacement.

Choose a dependency profile when preparing the bundle:

| Profile | Setup option | Requirements supplied by the wheelhouse |
| --- | --- | --- |
| Core (default) | none | `requirements.txt` and all dependencies |
| Core and images | `--profile media` | Core plus `requirements-media.txt` and all dependencies |
| Core, images, tokenizer and embeddings | `--profile full` | `requirements-local-full.txt` and all dependencies |

For example, `.\Aegis.bat setup --profile media` on Windows, or
`sh ./Aegis.command setup --profile media` on Linux/macOS. A complete image
workflow also needs separately installed model servers and weights.

The wheelhouse must match the destination OS, CPU architecture (including
Apple silicon versus Intel), and Python version. Do not reuse Windows binary
wheels on Linux or macOS. Include every dependency as a wheel. The manifest
format is `<sha256><two spaces><wheel filename>`; it must be checked against a
trusted acquisition record. A freshly computed checksum does not establish
trust. There must be no extra files or subdirectories inside the wheelhouse.

For unattended setup, provide both paths as arguments, quoting paths with spaces:

```text
Aegis.bat setup "D:\Offline bundle\wheels" "D:\Offline bundle\wheels.sha256"
sh ./Aegis.command setup "/local/offline bundle/wheels" "/local/offline bundle/wheels.sha256"
```

Windows prefers this checkout's existing `.runtime/python/python.exe`, then a
locally installed `python.exe` outside Windows Store aliases. It does not invoke
the `py` install manager. Linux/macOS use an installed `python3`; the macOS
`/usr/bin/python3` developer-tools bootstrap is intentionally not invoked.
These interpreters bootstrap setup only; application startup requires `.venv`.
For an explicit interpreter, run its full local path followed by
`aegis.py setup`. If Python's offline `venv`/`ensurepip` support is missing,
obtain it through your reviewed OS/Python installation process and retry.

## 2. Create local accounts

Account creation happens locally and prompts for passwords without showing
them. For the complete coding approval workflow, provision the fixed roles
`operator`, `data-owner`, `model-custodian` and `security-officer` with independent
credentials. Provisioning an existing account resets its password and revokes
its sessions, so this is not a daily startup step.

```text
Aegis.bat cli users set operator
sh ./Aegis.command cli users set operator
```

Use the line for your OS; repeat with the other required account IDs. No server
needs to be running for this local provisioning command. `cli users roles`
lists the supported roles. Do not put passwords in command arguments or chat.

## 3. Daily launch

| System | Open Aegis |
| --- | --- |
| Windows | Double-click `Aegis.bat`, or run `.\Aegis.bat` |
| Linux | `sh ./Aegis.command` |
| macOS | `sh ./Aegis.command`; optionally run `chmod +x Aegis.command` once, then open it in Finder |

This starts the local server and opens the operator terminal. `/exit` closes
that CLI and stops the server it started. You do not need Node.js, npm, a second
terminal, or manual virtual-environment activation. Older `run_all.bat` and
`run_all.sh` commands forward to this same launcher.

Inside Aegis:

```text
/login operator
/doctor
/help coding
```

Use `/help images` for images, `/help security` for lockdown and receipts, and
`/help recovery` for encrypted backups. Follow the guided role/approval steps
before selecting a lease and submitting work. `/compose` provides multiline
input with `/preview`, `/send` and `/cancel`. Ordinary text outside `/compose`
is submitted immediately under the selected lease.

The launcher prints the local dashboard URL. Opening it is optional; the CLI
operates Aegis and the dashboard displays telemetry/audit information. No
browser is opened automatically. A typical daily session binds only to
`127.0.0.1:8000`.

## If something needs attention

- **Environment missing:** run the setup command above; startup never switches
  to a shared Python environment.
- **Port busy:** close the previous Aegis session, or launch with
  `start --port 8001`. Both the server and CLI use the selected port; the
  launcher refuses to attach silently to an existing service.
- **Image or embedding feature unavailable:** core operation still works.
  Prepare the required profile in a fresh checkout/environment using a reviewed
  complete wheelhouse. Do not delete live `data/` to change dependencies.
- **Signed out or lease invalid:** use `/login`, `/context`, then the relevant
  workflow guide. Lockdown changes require fresh leases/tasks.
- **Plain terminal preferred:** launch with `start --plain`.
- **Window closes with an error:** run the same launcher from a terminal so the
  error remains visible. Startup errors do not trigger automatic installation.

For scripted or advanced use, `cli <arguments>` runs the dedicated CLI without
starting another server. Example: `Aegis.bat cli --json doctor`. Point a separate
CLI at a custom-port running server with `cli --url http://127.0.0.1:8001/api ...`.

## Platform security boundaries

| Capability | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Local API, CLI, approvals, text/image provider protocols | Implemented | Portable code path | Portable code path |
| Private session files | Owner-only ACL | Owner-only permissions | Owner-only permissions |
| New control key at rest | Current-user DPAPI | Local file, mode 0600 | Local file, mode 0600 |
| Managed data directories | Existing Windows controls | Owner-only, mode 0700 | Owner-only, mode 0700 |
| Encrypted passphrase backup | Supported code path | Supported code path | Supported code path |
| Fixed gVisor test sandbox | Unavailable natively | Optional local setup | Unavailable natively |
| Included firewall inspection/application scripts | Windows only | Host-specific deployment work | Host-specific deployment work |

Linux/macOS permission-protected keys are not equivalent to DPAPI, a hardware
keystore or disk encryption. A compromised owner account or administrator can
access them. Use only local storage: Windows network paths/drives are rejected;
Unix network mounts require deployment-level checking. Symlinked data inputs
are rejected; on macOS use canonical local paths rather than `/var` or `/tmp`
aliases if a path check refuses them.

To migrate Windows data to another OS, create an encrypted Aegis backup and
restore it on the destination. Do not copy a Windows DPAPI-bound live directory
and expect its key to open on Linux/macOS. Restore requires new sessions and
execution approvals. Check the restored lockdown state and keep an independent
offline recovery copy.

Application-local operation does not silence the operating system, a model
server, its extensions or unrelated software. Host egress isolation and actual
model behavior must be verified separately. CPU operation is supported by the
application; GPU/Metal/CUDA compatibility depends on the chosen local server
and is not inferred by this launcher.

Validation for this change runs on Windows, including portable-path logic and
launcher contracts. The suite includes native POSIX permission checks for
Linux/macOS. Native Linux/macOS installation, shutdown, model inference and
firewall validation still need to be run on those systems before certifying a
release. See [security operations](SECURITY_AND_RECOVERY.md) for the wider scope.

Latest verification: the complete Windows suite passed **440 tests, 3 skipped**.
A final launcher rerun passed **20 tests, 1 skipped**, including four additional
tests for forwarded CLI options and guided-setup cancellation. Together these
cover **444 distinct passing tests with no unresolved failures**. The skips are
two optional Pillow-dependent image modules and the native POSIX permissions
test. Windows wrapper execution, POSIX shell syntax, Python compilation and
changed tracked-file whitespace checks passed. These checks did not install a
wheelhouse or alter live accounts, keys, model files or backups.
