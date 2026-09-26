# Local performance plan

Aegis is a policy/control layer. Its Python code is not the matrix-multiplication engine for an LLM or diffusion model. Rewriting the main application in Rust or C++ will not make a 1T-parameter checkpoint fit in 63.87 GiB RAM or 2 GiB VRAM. Use a compiled local inference runtime and an exactly compatible, reviewed model checkpoint. Keep model files and inference services local; measure their actual throughput before selecting hardware.

## Measured Aegis overhead

On this Windows host, a synthetic 64-file, roughly 445 KiB lexical search took a median **0.40 s** over five runs. Profiling showed repeated tokenization of lines after an exact match had already been found. Removing that redundant work and skipping unnecessary identifier splitting reduced the median to **0.05 s** over seven runs for the same synthetic input, about **8× faster**. This is a retrieval-only fixture, not a live-model benchmark. Existing coding/retrieval/model tests passed after the change. One hundred synthetic signed receipts took about 11–12 ms per append at this small chain length, and verifying the 100-receipt chain took 2.6 ms. Larger chains still need measurement; receipt validation should not be weakened solely for speed.

## Priorities

1. **Get a feasible local checkpoint running.** This PC has 8 physical / 16 logical CPU cores, 63.87 GiB RAM and a 2 GiB GT 710. The full-size Kimi/DeepSeek/Qwen checkpoints exceed host RAM even at a raw 4-bit lower bound. Start with a smaller family variant or distillation served by an offline, reviewed C/C++ runtime such as [llama.cpp](https://github.com/ggml-org/llama.cpp) where the exact model architecture is supported. Do not infer support from a family name alone.
2. **Measure the actual bottleneck.** Record cold load time, prompt-processing tokens/s, generated tokens/s, end-to-end latency, peak RAM/VRAM, and image-generation seconds at fixed image size/steps. Use the local runtime's own benchmark and then an approved Aegis task. Keep input/output sizes and model hashes constant. Fixture API timings are not model throughput.
3. **Tune the runtime, not the control language.** Compare quantizations, CPU thread counts, context size, batch sizes and supported GPU offload on the same model. Keep a result only if quality and resource use remain acceptable. With this GPU, CPU-only may be the honest baseline; verify rather than assuming offload helps. A larger modern local GPU or multi-device workstation is needed for materially faster large-model and image generation throughput.
4. **Review warm-model behavior.** Aegis currently sends `keep_alive: 0` to Ollama for coding and vision. Ollama documents that this unloads the model after a response; repeated agent turns may pay the load cost each time. This is a deliberate conservative memory-retention choice. A future task-scoped warm mode would need explicit authorization, bounded lifetime, reliable unload on success/failure/revocation, concurrent-task rules, and tests for prompt/cache retention before enabling it. Do not globally keep sensitive models resident merely for speed.
5. **Optimize Aegis only where measured.** The lexical search improvement is complete. The embedding path currently rehashes a pinned model and reloads it for each search; a cache could help but must be scoped to the approved model, compartment and task and invalidated on file changes or revocation. No live embedding model is installed to benchmark or validate such a cache yet. Do not port the policy/authentication layer to Rust without evidence that it dominates latency.

## First trials on this PC

| Use | Candidate to obtain and evaluate offline | Why this order |
| --- | --- | --- |
| Responsive text/coding baseline | [Qwen3-4B official GGUF](https://huggingface.co/Qwen/Qwen3-4B-GGUF), locally reviewed Q4_K_M file | Small dense model and an official GGUF release; test coding quality, tool-format compliance and tokens/s before moving larger. |
| Image understanding | [Qwen3-VL-4B-Instruct official GGUF](https://huggingface.co/Qwen/Qwen3-VL-4B-Instruct-GGUF) with its [vision projector](https://huggingface.co/Qwen/Qwen3-VL-4B-Instruct-GGUF/blob/main/mmproj-Qwen3VL-4B-Instruct-F16.gguf) | A smaller vision-capable candidate compatible with a local GGUF workflow; actual Aegis payload, OCR quality and CPU speed still require live validation. |
| Alternate reasoning/coding quality | [DeepSeek-R1-Distill-Qwen-7B](https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-7B) with a reviewed compatible quantization | Larger than the 4B baseline, so compare its quality gain against CPU latency. It is a distillation, not the full DeepSeek model. |
| Kimi-family vision | [Kimi-VL-A3B-Instruct](https://huggingface.co/moonshotai/Kimi-VL-A3B-Instruct), 16B total / 3B active | Possible later evaluation, but total stored weights and exact local-runtime compatibility matter; it is not the first speed target. |

These are **candidates, not installed models or proven performance rankings**. The official model cards sometimes show commands that fetch files online; the Aegis deployment must instead use separately reviewed local files and hashes. The vision model does not generate images. For generation/editing, the current AUTOMATIC1111 adapter still needs a separate local diffusion checkpoint; its [low-VRAM guidance](https://github.com/AUTOMATIC1111/stable-diffusion-webui/wiki/Troubleshooting) notes that memory-saving modes sacrifice speed. A 2 GiB GPU may be insufficient for the desired image model/resolution, and no generation-time estimate is honest without a live test.

Once a reviewed `llama-bench.exe` and local GGUF file are present, begin with CPU-only prompt-processing and generation trials at 4, 8 and 12 threads, for example:

```powershell
.\llama-bench.exe -m .\models\reviewed-q4.gguf -p 512 -n 128 -t 4,8,12 -ngl 0 -r 3
```

The [llama.cpp benchmark](https://github.com/ggml-org/llama.cpp/blob/master/tools/llama-bench/README.md) reports prompt processing and generation separately and does not include tokenization or sampling time. Measure an end-to-end Aegis task as well. Record model/runtime hashes and memory use; select the fastest setting that passes the same quality and confidentiality checks.

Image understanding requires a vision-capable LLM and its projector; generation/editing requires a diffusion model and compatible local runtime. Lower resolution, fewer sampling steps and smaller checkpoints may improve generation time but can change quality. Use the same prompt and image fixtures when comparing. The current 2 GiB GPU and absent checkpoints prevent a useful live image-speed claim.
