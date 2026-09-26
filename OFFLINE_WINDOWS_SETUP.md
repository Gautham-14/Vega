# Offline Windows environment

For the simplest setup and daily launch on **Windows, Linux or macOS**, start
with [QUICKSTART.md](QUICKSTART.md). This page retains Windows-specific deployment
notes. `Aegis.bat` is the preferred Windows entry point; `run_all.bat` is an alias.

Windows is the host OS. Aegis's supported operation uses local files and numeric-loopback connections only; it does not require Microsoft or Google accounts, APIs, model hosting, telemetry, package registries, or cloud services. The old `gemini-cli/` tree is reference material and is excluded from the supported startup path. Do not run `npm install` or `start:legacy` for Aegis.

This checkout now has an ignored `.runtime/python/` copy of locally installed CPython 3.11.15. It was copied from the existing local Python distribution without a network request. The Windows launcher requires `.venv/Scripts/python.exe`; it cannot silently fall back to Codex's Python. The separate virtual environment and model weights are **not installed yet**. The copied interpreter alone is not a working Aegis environment.

## Inputs to complete setup

1. A reviewed local wheelhouse matching the selected profile: `requirements.txt` for core (default), core plus `requirements-media.txt` for `--profile media`, or `requirements-local-full.txt` for `--profile full`. Include every dependency as Windows wheels for the selected Python/CPU architecture. Keep every wheel in one directory, without subdirectories or extra files. Record the trusted SHA-256 of each wheel in a manifest with lines of the form `<64 lowercase hex characters><two spaces><wheel filename>`. The manifest must be checked against a trusted acquisition record; calculating a new hash after an untrusted download does not establish provenance. `scripts/setup_offline.py` verifies the complete wheelhouse before creating `.venv` and installs with `pip --no-index --only-binary=:all:`. It never accesses a package index.
2. Reviewed model-server executables and model files, including tokenizer/chat template and any vision projector, placed on local storage. Choose checkpoints that fit this host's 63.87 GiB RAM and 2 GiB VRAM. The named full-size Kimi, DeepSeek and Qwen checkpoints in `LOCAL_MODELS_AND_IMAGES.md` do not fit. A separate local vision checkpoint and diffusion checkpoint/runtime are needed for image understanding and generation/editing unless one installed runtime explicitly supports both.
3. A separate protected copy of the existing encrypted Aegis backup. The current archive is on the same drive as the live database and does not cover drive loss.

Run setup only after the reviewed wheelhouse and manifest are present:

```powershell
.\Aegis.bat setup D:\path\to\wheelhouse D:\path\to\wheelhouse.sha256 --profile full
.\Aegis.bat
```

`run_all.bat` starts the Aegis API on `127.0.0.1:8000`, opens the operator CLI, and stops that server when the CLI exits. It refuses an occupied port so it cannot silently attach to another local service.

`setup_offline.py` refuses an existing `.venv`, missing/unlisted wheels and changed hashes. Each local wheel is hash-pinned again at pip's consumption boundary, with `--require-hashes --no-deps --no-index`, isolated configuration and no cache. The wheelhouse must contain one compatible, reviewed version of each package and its complete dependency closure; `pip check` rejects missing/incompatible dependencies without resolving URLs. Inspect a failed `.venv` before any fresh attempt; do not silently reuse it. Keep the Python runtime, wheelhouse, checkpoints and `.venv` out of Git. For a new Windows installation, use a reviewed locally installed Python 3.11+ or place a reviewed distribution in `.runtime/python/`; validate its origin and license separately. Startup still requires the resulting dedicated `.venv`.

## Network assurance

The app binds to numeric loopback and rejects nonlocal peers. Its provider transport accepts numeric loopback only and has no proxy, redirect or model-pull path. The launchers set offline flags for common Python model libraries. These application checks and flags do **not** prove zero outbound traffic from third-party packages, a model server, child processes, Windows or other applications.

When the exact Python and model-server binaries exist, use `scripts/Protect-LocalModelServer.ps1` to preview and apply outbound-deny rules for each executable that handles prompts or images, including `.venv/Scripts/python.exe` and any child/base Python process actually observed at runtime. Verify the resulting rules, process paths, loopback listeners and traffic during representative tasks. For host-wide assurance that Windows itself uses no vendor network service, disconnect network access or use a separately governed Windows network policy; Aegis application rules cannot establish that property. Do not apply an outbound block to the shared Codex Python installation.

The current setup has no live model or model process to evaluate. The security and media tests cover the Aegis boundary with fixtures, not live model quality, server retention or host-wide egress.
