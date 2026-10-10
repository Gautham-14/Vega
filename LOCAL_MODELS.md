# Dynamic local model routing

The current workstation uses the owner's GGUF files in
`C:\Users\Prem\OneDrive\Documents\Desktop\AI MODEL`. Originals were not moved
or modified. An explicit setup created the ignored local configuration
`.runtime/local-models.json`, including SHA-256 pins for weights, projector,
server executable and its DLLs. These workstation files are not included in a
fresh checkout or wheel, and local hashing is not publisher verification.

The explicitly authorized runtime acquisition used the official llama.cpp
Windows CPU build [b11540](https://github.com/ggml-org/llama.cpp/releases/tag/b11540).
Its archive SHA-256 matched the official release asset digest:
`85cae1b982145d1b315e56e7343524b301a11f0fdf2c7c9dd973c26daba4b3b5`.
It resides in the checkout's ignored `.runtime/llama-b11540` directory.
The initial AppData location was virtualized into Codex's Windows package
storage and therefore invisible to an ordinary command prompt. The runtime was
copied into the checkout, retaining every existing SHA-256 pin. Use an ordinary
local directory visible outside the installer app when setting up another host.
No VM/hypervisor was installed. No additional model weights were downloaded.
Third-party runtime/model licenses remain their own; Aegis's proprietary license
does not replace them.

| Role | Local alias | Artifact |
| --- | --- | --- |
| General language | `llama-general` | Llama-3.2-1B-Instruct-Q4_K_M.gguf |
| Programming | `qwen-coder` | qwen2.5-coder-0.5b-instruct-q4_k_m.gguf |
| Image understanding | `smol-vision` | SmolVLM-500M-Instruct-Q8_0.gguf plus matching mmproj |

The mmproj file is a vision projector, not an independent model. These small
models are connected candidates, not qualified domain experts. Responses can
be incorrect, incomplete or repetitive; deployment-specific quality review is
still required. An incomplete or malformed response is rejected, not silently
replaced by mock output, a different provider, or a cloud model.

## Daily use

Start `Aegis.bat` normally and sign in. Then, in the CLI:

```text
/local-models
/auto on --public
Explain how a heat exchanger works.
Write a Python function that squares a number.
/chat --public --image "C:\absolute\public-image.png" Describe the image.
/route --public Write a Python function.
/auto off
```

`auto on --public` explicitly acknowledges PUBLIC-only information and makes
ordinary shell prompts select a model dynamically. It is off until enabled and
cleared on a newly selected coding lease. `/chat --public ...` works without
changing the ordinary-prompt mode. `/route` is a deterministic, zero-inference
preview; a live semantic classifier can refine the selection during `/chat`.
One-shot equivalent: `python aegis.py cli chat --public "Your prompt"`.

Image attachments require the vision model regardless of prompt wording. Clear
code intent/syntax selects the coder; other text first uses a bounded local
semantic classifier to choose text or code. Its output can choose only that
specialization, never permissions, tools or classification. RAM headroom and a
conservative UTF-8 context estimate filter candidates. One model is loaded on
demand; idle model processes may be reclaimed before switching. This is not a
native-token count or measured VRAM estimate. Large requests fail without silent
truncation. Images are sanitized PNG/JPEG/WebP bytes, one file of at most 2 MB;
remote URLs and host-path fetching by the model are not supported.

The [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
describes the on-demand preset/router mechanism. Aegis pins the local inventory,
uses numeric loopback, a generated per-launch API key, offline mode, no Web UI,
no slot API, no disk prompt cache and no request logging. Startup checks pins
and exposes model aliases; it does not perform inference. Shutdown terminates
only the owned model process tree. Model switching is serialized; concurrent
requests fail busy rather than cancelling someone else's active inference.

This PUBLIC chat has no tools, source access, code execution or OT authority.
It does not retain answers/prompts in Aegis storage; content-free routing
receipts contain the model, routing policy and prompt hash. This is not a claim
of physical memory zeroization or independently verified process isolation.
Sessions and incident state are rechecked before dispatch and before output
release. INTERNAL/sensitive repository/advisory/media work remains in the
existing purpose-bound workflows with exact provider Capsules, leases and
independently approved releases. No provider is swapped within an existing
lease. Native local chat is not hardened-production acceptance.

## Explicit setup on another host

Acquire a compatible, independently reviewed local llama.cpp runtime for that
OS/architecture; retain its provenance and applicable licenses. No automatic
runtime acquisition is part of application startup. Supply the same named GGUF
files, then explicitly generate a new configuration:

```text
python -m scripts.configure_local_models <local-model-folder> <local-llama-server-executable>
```

The script never downloads, probes or runs a model and never overwrites an
existing configuration. Archive the old configuration before a reviewed update;
do not mutate pinned model files while the server runs. Restart after changes.
Installed packages need an explicit `AEGIS_LOCAL_MODELS_CONFIG` path to their
reviewed configuration. Set it to an empty string to disable the managed runtime.
Managed models require a stable server process; `--reload` is refused.

Synthetic inference is a separate explicit action:

```text
python -m scripts.check_local_models --live --output .audit-tmp/local-model-smoke.json
```

This checks temporary accounts/storage, synthetic PUBLIC text/code/image
requests, non-simulated responses and routing. It is not a model-quality or
production-isolation certification. Ordinary pytest disables real model startup
and uses fixed model/resource fixtures.

For the broader, labelled synthetic regression probe:

```text
python -m scripts.check_local_models --live --suite evaluations/local-routing-public.json --output .audit-tmp/local-model-evaluation.json
```

This checks 12 general-language, explicit-code, semantic-code and image cases.
Fact checks require small whole-word groups; Python checks inspect a narrow pure
function AST shape without executing generated code. These heuristics can miss
errors or reject alternative correct answers; they are not an accuracy benchmark
or an independently reviewed domain qualification. Reports contain case IDs,
selected aliases, scores, inventory/suite hashes and request latency, not prompts,
answers or account credentials. `--diagnostic` prints bounded synthetic responses
only; do not reuse it for operator/private data. Failed checks produce
`NEEDS_REVIEW` and a nonzero exit status, never fabricated passing output.

On 10 October 2026, two identical probes routed **12/12** cases correctly but
passed only **7/12** narrow answer checks. Diagnostics showed Llama reversing
heat-flow direction, Qwen returning JavaScript when Python was requested, and
SmolVLM omitting the requested blue/green color. They remain unqualified local
candidates. No weights were modified or additional models acquired to hide
these failures. Use a reviewed larger evaluation set and agreed quality targets
before relying on these models for correctness-sensitive work.

If another Aegis session owns port 8089, do not stop it for evaluation. Explicitly
generate a separate ignored configuration with `configure_local_models --port
<unused-port> --output <temporary-config>`, verify its pins match the reviewed
inventory, and set `AEGIS_LOCAL_MODELS_CONFIG` in the evaluation process only.
Application `latency_ms` includes classification/model selection and generation;
the evaluation also measures the whole API request as `request_latency_ms`.
