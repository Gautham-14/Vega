# Deployment acceptance gates

Current status (10 October 2026): **NOT ACCEPTED on production infrastructure**.
Local work uses Windows/Python 3.14.7. Linux separate-UID custody, actual sandbox
isolation, independent provider attestation, intended CPU/GPU behavior and
domain model quality have not been verified on the deployment hardware.
Separate synthetic PUBLIC inference was explicitly authorized and performed with
the owner's local models; no additional weights were downloaded. The 12-case
probe selected the expected model in every case but passed only 7 narrow answer
checks. This is not domain/hardware/provider qualification and does not fill the
production acceptance gaps; see LOCAL_MODELS.md.
The owner selected an isolated VM backend on Windows, macOS and Linux hosts but
explicitly declined VM installation/acceptance tests on this device. Before
later authorized acceptance, the owner must supply the intended host and
reviewed hypervisor/firmware/provisioned Linux guest inventory,
reviewed provider/model inventories, deployment-specific quality targets,
independent reviewer identities and permission to run the explicit acceptance
commands below. A passing source release gate does not complete point 22.

Use this record when the intended local models and deployment hardware are
available. Nothing here authorizes automatic model downloads or starts inference.
Configuration-only `provider-preflight` remains safe to run without models.

Record the deployment ID, reviewer identities, software revision, dependency
lock hashes, immutable provider IDs/configuration hashes, model inventory hashes,
Capsule IDs, hardware/OS/serving versions, report hashes and review date. Keep
evaluation evidence content-free or within its approved classification boundary.
Changing an accepted model, profile or implementation requires renewed review.

| Gate | Required evidence | Acceptance condition |
| --- | --- | --- |
| Independent accounts | Named account inventory, separate authenticator enrollment and review assignments | Enabled accounts have the correct immutable roles; independent approval decisions come from separate reviewers |
| Software baseline | Hash-pinned dependency checks, regression report, installation inventory | Required tests pass; platform-specific checks run on the target OS; skips have a documented deployment disposition |
| Model identity and compatibility | Verified offline bundle, pinned provider profile, explicit native serving configuration | Actual weight inventory and serving identity match their pins; tokenizer/chat template, modality, context window and structured-output mode are compatible |
| Candidate text/advisory quality | Explicit PUBLIC candidate qualification plus domain-owner-reviewed document cases | Predetermined accuracy/abstention targets pass; every accepted quote matches its cited source revision/field; unsupported evidence is rejected |
| Other enabled modalities | Vision/OCR/diffusion or embedding candidate suite as applicable | Each enabled modality meets its independently reviewed quality targets; unused capabilities remain disabled |
| Retrieval | Exact identifier, multilingual, stale-revision, compartment and relevance cases; optional embedding/MRL qualification | Current authorized evidence is retrieved; unauthorized evidence never enters a query; any MRL widths are supported by the selected trained model |
| Sensitive provider release | Independent signed attestation, exact-bound release approvals and current runtime evidence | INTERNAL data is blocked until the measured provider release is independently approved; refresh/expiry/replacement behaves correctly |
| Host containment | Hardened Linux services, separate custody/witness identities, attestor policy and negative containment report | Model identity cannot read application keys/state or the Docker socket; unwanted DNS, IPv4 and IPv6 egress is blocked; evidence matches the actual process |
| CPU/GPU confidentiality | Platform-supported attestation covering every processor/device receiving sensitive data | Reviewers verify the claimed coverage; lack of supported hardware evidence cannot be replaced by Docker or a software test |
| Cache and retention | Serving-engine configuration and independent negative cache/retention checks | Cross-task/user content cannot be recovered; expiry/revocation blocks output retention/release; requested unload/cache settings are independently observed |
| Authorization races | Revocation, source replacement, account reset, incident lockdown and provider-release replacement during actual requests | No newly unauthorized request is dispatched; in-flight output cannot be retained/read/exported after authorization changes; previously transmitted input is recorded as unretractable |
| Reviewed export and OT boundary | Exact-bound dual-review export; industrial boundary checks if a separate connector is introduced | Export needs the approved exact binding; advisory remains read-only; any future physical write connector has its own independently reviewed authorization |
| Capacity and latency | Representative load, measured latency, context limits and resource/timeout behavior | Deployment-specific targets agreed before testing pass; saturation and malformed/incomplete responses fail safely without weaker fallback |
| Operational recovery | Encrypted backup on separate media, separate passphrase custody, actual restored login/content checks and witness reconciliation | Restore preserves integrity and revokes sessions/execution approvals; fresh authorization is required; loss of the host has a tested recovery path |

Available entry points:

- `provider-qualify <id> evaluations/security-text.json` — explicit candidate
  text inference.
- `provider-qualify-advisory <id> evaluations/advisory-public.json` — explicit
  synthetic advisory inference. Add reviewed domain cases for the intended use.
- `provider-qualify-media` and `embedding-qualify` — explicit optional modality
  qualification; see `help models` for arguments.
- `python -m scripts.check_deployment --policy <policy-file> --provider <id>` —
  Linux administrator containment check against an already deployed process;
  does not launch a model or change policy.
- `backup create`, `backup verify`, `backup drill` — local encrypted recovery
  commands with hidden passphrase prompts; use `help recovery`.

Candidate tests alone do not grant production approval. BLT, stateful-token
architectures and a ColBERT encoder are not active backends in this installation;
accepting the working core does not implicitly qualify these optional concepts.
