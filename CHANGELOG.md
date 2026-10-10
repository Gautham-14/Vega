# Changelog

## Unreleased

- Add source-level isolated production guest hosting on Windows/macOS/Linux; infrastructure acceptance remains deferred.
- Connect pinned local GGUF text/code/vision models with on-demand loading, semantic prompt routing and explicit PUBLIC-only auto-chat.
- Repair Windows packaged-app AppData redirection by placing the pinned local runtime in the checkout's ignored runtime directory.
- Add a repeatable 12-case synthetic routing/answer probe; report model quality failures separately from connectivity.
- Include semantic routing in request latency and isolate wheel smoke checks from operator model settings.
- Add source-only VM guest bridge, device ownership and placeholder policy examples; no infrastructure was installed.

- Plain and redirected CLI input use basic input; demo tests use fixed hardware.
- Preserve the ASCII illustration's spacing and purple color.
- Central application version, import-safe configuration and transactional SQLite upgrades.
- Split CLI parsing, transport, display, shell, administration and file handling.
- Fix malformed UTF-8 text; add encoding, lint, formatting and incremental strict typing checks.
- Add critical branch coverage gates and a Python 3.11–3.14 CI matrix.
- Package console commands, bundled skills and an owner-selected proprietary license.
- Pin the optional CLI and quality-tool profiles; verify fresh wheel installation.
- Add reproducible release checks and distinguish historical operations from current evidence.

The current application version is 1.0.0. This section describes uncommitted,
unreleased changes, not a published release.
