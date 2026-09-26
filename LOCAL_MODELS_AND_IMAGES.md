# Local models and images

Aegis governs inference requests; the separately installed local inference server loads the model weights, tokenizer, chat template, vision encoder and projector. Retrieval embeddings help find text in authorized snapshots. They do not compress LLM weights or make a trillion-parameter checkpoint fit on a small machine.

## Capacity and model identity

Use total parameters, including inactive MoE experts, to estimate weight storage:

```powershell
.\.venv\Scripts\python.exe aegis_cli.py capacity 1000 --bits 4
```

This reports 500 GB / 465.661 GiB for raw weights alone. Quantization metadata, KV cache, activations, vision processing, runtime buffers and operating-system memory are additional. An estimate is not a successful load or throughput measurement. Smaller model variants in the same family have different requirements.

| Example checkpoint | Total / active parameters | Raw 4-bit weight lower bound | Input capability |
| --- | --- | --- | --- |
| [Kimi K2.5](https://huggingface.co/moonshotai/Kimi-K2.5) | 1T / 32B | 500 GB | Text and vision |
| [DeepSeek V3](https://arxiv.org/abs/2412.19437) | 671B / 37B | 335.5 GB | Text; select a separate vision-capable checkpoint for images |
| [Qwen3.5-397B-A17B](https://huggingface.co/Qwen/Qwen3.5-397B-A17B) | 397B / 17B | 198.5 GB | Text and vision |

These are named examples, not a claim that every Kimi, DeepSeek or Qwen variant has the same size or capabilities. Weight arithmetic here is calculated from the published parameter counts. Runtime architecture support, quantization support and required GPU instructions must be checked against the exact installed server release.

This audit measured 63.87 GiB host RAM and an NVIDIA GeForce GT 710 with 2 GiB VRAM. It found no Ollama, llama-server or vLLM executable in PATH and no listeners at the standard local ports checked (11434, 8080, 1234, 7860). Alternate installations and ports were not exhaustively searched. Full-size models in the table do not fit in this host's RAM/VRAM. SSD offloading is not a verified performance solution here.

## Text inference and tokenization

Configure a reviewed, already installed model through `/provider-add profile.json`. Profiles accept Ollama, llama.cpp, LM Studio, vLLM and other compatible local servers. Use a separate port from Aegis, which defaults to 8000. Numeric loopback only; external-provider environment overrides, redirects, proxies, automatic downloads and cloud fallback are not supported.

The provider's `context_tokens` setting defaults to 16384 and is bounded to 1048576. It must reflect the server's actual configured context. Aegis reserves output tokens and framing space using a conservative UTF-8 byte estimate. This is not an exact model token count, particularly for images; native image preprocessing and vision token accounting remain server-managed. Oversized coding context is rejected rather than silently dropped.

The optional `LocalModelTokenizer` loads a SHA-256-pinned, existing `tokenizer.json` through Hugging Face Tokenizers. It preserves native vocabulary IDs and Unicode decoding, disables saved truncation/padding defaults, and never trains a replacement vocabulary or loads model code/weights. It is a text utility, not the inference engine. The server applies its native chat template and multimodal processor; do not feed locally invented image placeholder tokens to Kimi/Qwen models.

Install `tokenizers` separately if this utility is needed. Compatible-server digest pins are custodian assertions, because `/v1/models` exposes names without proving the loaded weight/tokenizer/projector hashes. Ollama exposes a server-reported digest, still not independent weight attestation.

## Retrieval embeddings

The optional `sentence-transformers` integration remains text-only. It accepts an existing absolute local model directory, safetensors weights, an approved standard Transformer/Pooling/Normalize module layout and the configured digest. The tree is bounded to 1 GiB; that limit applies to the retrieval model, not the separately served LLM.

`AEGIS_EMBEDDING_MODEL_DIR` and `AEGIS_EMBEDDING_DIGEST` enable the existing pinned retrieval path. It disables remote code/downloads, validates shape and finite nonzero vectors, and rechecks the pin. Full trained dimensions are retained by default. Truncation requires explicitly supplied reviewed dimensions for a model actually trained with Matryoshka representations; slicing an arbitrary embedding is not equivalent to that training.

This implementation rehashes model files and reloads the model for a search. It favors compartment separation over throughput and has no persistent vector index. Embedding inputs are capped at 512 model tokens; the current character chunks can be truncated internally by the embedding model, affecting retrieval quality. Native-token-aware chunking, quality evaluation and a carefully scoped model cache remain future work. Image embeddings and cross-modal retrieval are not implemented.

## Image understanding

Install the small local image decoder dependency as part of the [offline wheelhouse setup](OFFLINE_WINDOWS_SETUP.md):

```powershell
.\.runtime\python\python.exe scripts\setup_offline.py D:\path\to\wheelhouse D:\path\to\wheelhouse.sha256
```

Run and configure an already installed local vision model separately. Set `vision: true` explicitly in its provider profile. Example profile shape (replace the model identity and digest with reviewed values):

```json
{
  "name": "Local vision model",
  "protocol": "openai-compatible",
  "engine": "vllm",
  "endpoint": "http://127.0.0.1:8001/v1",
  "model": "reviewed-local-vision-model",
  "digest": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256",
  "local_only": true,
  "vision": true,
  "context_tokens": 16384,
  "max_tokens": 2048
}
```

For Ollama use `protocol: "ollama"`, `engine: "ollama"`, port 11434, and an explicit non-`latest` model tag. Aegis passes actual image bytes in the native `images` field, as described in the [Ollama vision API](https://docs.ollama.com/capabilities/vision). Compatible servers receive inline PNG data URLs in chat content; Aegis never asks a server to fetch an external image URL.

## Image generation and editing

Image understanding models are not automatically image generators. Generation and img2img editing use a separately configured local AUTOMATIC1111 server with its API enabled. The adapter follows its [API](https://github.com/AUTOMATIC1111/stable-diffusion-webui/wiki/API) and [request schemas](https://github.com/AUTOMATIC1111/stable-diffusion-webui/blob/master/modules/api/models.py).

Profile shape:

```json
{
  "name": "Local diffusion",
  "protocol": "sd-webui",
  "engine": "automatic1111",
  "endpoint": "http://127.0.0.1:7860",
  "model": "reviewed_checkpoint_name",
  "digest": "REPLACE_WITH_64_LOWERCASE_HEX_SHA256",
  "local_only": true,
  "max_response_bytes": 12000000,
  "timeout_seconds": 120
}
```

Use the exact `model_name` and full `sha256` reported by the already installed checkpoint listing. The same full checkpoint hash must be loaded before the request and remain loaded afterward. Generated output must carry the matching short checkpoint hash. These are server reports, not independent attestation. The adapter does not switch or download models, invoke arbitrary scripts, enable face restoration or run upscalers.

Generation is one image, 64–1024 pixels per side in multiples of 64, 1–50 steps, Euler sampler and an explicit nonnegative seed (default 0). Editing takes exactly one source image and a denoising `strength` between 0 and 1. This is whole-image img2img; masks/inpainting, arbitrary ComfyUI workflows, image training and image similarity search are not implemented. Backend plugins and retention must be independently reviewed: `save_images: false` is a request, not proof of server behavior.

## Governed CLI workflow

The same account roles and approval command used by coding apply here. Each step runs as the named account, with separate credentials; there are no default passwords.

1. **Model Custodian:** `/provider-add profile.json`, then `/provider-probe PROVIDER-ID`.
2. **Operator:** `/media-register PROVIDER-ID`. This returns a Capsule and its approval request.
3. **Model Custodian and Security Officer:** each `/approve CAPSULE-APPROVAL-ID approve`. The Model Custodian then `/activate CAPSULE-ID CAPSULE-APPROVAL-ID`.
4. **Operator:** create request JSON such as the following, then `/media-prepare request.json --image C:\Images\diagram.png`.

```json
{
  "capsule_id": "REPLACE_WITH_APPROVED_CAPSULE_ID",
  "operation": "understand",
  "prompt": "Describe the components and connections visible in this diagram. Flag unreadable labels.",
  "compartment": "Engineering",
  "classification": "INTERNAL",
  "minutes": 15
}
```

5. **Data Owner and Security Officer:** `/media-review MEDIA-ID` displays the exact request, hashes and authenticated preview URLs. Sign in to the local dashboard in the browser to open previews. Each reviewer then `/approve MEDIA-APPROVAL-ID approve`.
6. **Operator:** `/media-run MEDIA-ID`. A task can run once; a new run needs a new approved request. `/media-review MEDIA-ID` shows the result and image preview URLs.
7. **Operator:** `/media-export-request MEDIA-ID`. The Data Owner and Security Officer inspect the result with `/media-review`, then approve this separate export request. `/media-export MEDIA-ID EXPORT-APPROVAL-ID output.png` saves a generated/edited image; use `.txt` for a vision answer. Existing files are never overwritten.
8. `/media-revoke MEDIA-ID` removes retained request/result keys and blocks further content access or export. The owner or authorized Data Owner can revoke. All retained content expires within 15 minutes; the server sweeps expired records regularly and checks expiry on reads and after model calls.

For generation use `operation: "generate"`, omit `--image`, and optionally specify `width`, `height`, `steps`, `seed`, and `negative_prompt`. For editing use `operation: "edit"` with one `--image` and optional `strength`. `/media-capabilities` reports implementation limits; `/endpoints` includes all media routes. The website remains a read-only telemetry/preview surface.

Images must be PNG, JPEG or WebP, single-frame, at most 2 MB each and 4,194,304 pixels. Inputs are decoded and converted to metadata-free PNG before hashing and review; transparency is composited on white. Maximum four inputs for understanding; generated output is validated through the same decoder. URLs, paths in image payloads, animated files and malformed bytes are rejected. Payloads, prompts and answers are encrypted in application retention and excluded from telemetry/receipts; hashes, labels and operation metadata remain auditable. Authorization is rechecked immediately before sending image data and after inference; an already running server computation cannot be remotely erased by revocation. This does not prove physical RAM zeroization, server cache deletion, pixel-level secret detection or OS isolation.

## Setup requirements and deployment acceptance

No models are installed yet, as confirmed by the operator. Complete these steps when selecting the deployment; none require enabling a cloud fallback.

| Component | Required setup | Evidence needed before claiming it works |
| --- | --- | --- |
| Aegis account | Reset the existing `operator` password with `.\.venv\Scripts\python.exe aegis_cli.py users set operator`; provision separate reviewer credentials. Restart the backend after source changes. | New login succeeds, old sessions are revoked, and identity-header spoofing remains denied. |
| Backend | Python 3.11+, `requirements.txt`, and one server worker on numeric loopback. Install `requirements-media.txt` for images. | Authenticated capabilities and API requests succeed; no remote bind or proxy is silently enabled. |
| Text or vision model | An explicit local checkpoint supported by the chosen Ollama/llama.cpp/LM Studio/vLLM release, with enough memory, supported quantization and its matching tokenizer/chat template. Vision additionally needs the matching vision encoder/projector or native processor. | Record exact runtime version, model revision, quantization, model digest and context configuration. Load it without downloads; probe the registered profile and run a reviewed representative task. |
| Full-size MoE deployment | RAM/VRAM and storage sized for all weights plus working memory; compatible accelerators and adequate memory/interconnect bandwidth. Aegis does not provide expert sharding, offload scheduling or distributed serving itself. | Measure actual loaded memory, prompt processing, generation rate and latency at the selected context/concurrency. The raw-weight estimate alone cannot establish feasibility. |
| Retrieval embeddings | Optional `sentence-transformers` installed locally; approved standard local safetensors tree and digest. This is a separate, smaller model. | Measure retrieval relevance on the user's documents/code, including long chunks and Unicode; ensure the intended evidence is not lost to the 512-token input cap. |
| Image generation/editing | Local AUTOMATIC1111 API, reviewed installed checkpoint already loaded, image decoder, and approved media profile/Capsule. Review enabled server extensions and logging. | One approved generation and one img2img edit complete, return the right dimensions/model hash, appear in authenticated previews, and export only after result approval. |
| Confidentiality and recovery | Server-side egress/logging/cache controls, one Aegis worker, restricted local model files and protected data directory. | Test no external traffic, rejected unapproved/expired/revoked calls, failure without output release, and restart/recovery behavior. Application tests alone do not prove OS or GPU isolation. |

For a representative quality evaluation, use code tasks with known tests; screenshots with known UI labels; scanned text with a checked transcription; diagrams with a known component/connection list; and generation/editing prompts with explicit visual requirements. Record errors and uncertainty as well as successes. Keep fixture-server results separate from live-model results. Do not qualify a model family using only one small checkpoint or infer image-generation ability from vision-understanding support.

If a separate workstation hosts the model, the current provider transport still requires a numeric-loopback endpoint on the Aegis host. Deploy Aegis with the serving runtime on that workstation, or design and review a separate connection mechanism; arbitrary LAN/cloud endpoints are deliberately rejected. Backend support for a model architecture does not imply this workstation has the memory to run its largest checkpoint.

## Validation boundary

Tests exercise real tokenization/image decoding and test-double provider responses. They verify approval and confidentiality gates, protocol encoding, output/hash checks, expiry and revocation. No live LLM, embedding checkpoint or diffusion model was loaded in this audit. OCR accuracy, diagram reasoning, coding quality, generation/editing quality and throughput remain unmeasured until the chosen local model is installed and evaluated on representative inputs.
