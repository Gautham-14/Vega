# Contributing

This is proprietary software. Access to source is not permission to redistribute
it; obtain the owner's permission before contributing or publishing changes.

Use Python 3.11–3.14 and an isolated environment. Install development dependencies
with `python -m pip install --require-hashes -r requirements-dev.lock`, and quality
tools with `python -m pip install --require-hashes -r requirements-quality.lock`.
Git must be on PATH for repository tests.

Run the checks in [RELEASE.md](RELEASE.md) before proposing a change. Ruff checks
and formats all Python code. Strict mypy currently covers schema migrations and
production prerequisites; expand that scope module by module rather than ignoring
new errors. Coverage gates include branches for authentication, authorization,
recovery and coding/advisory/media provider dispatch.

Tests must use temporary private storage and explicit simulated hardware.
Do not depend on local accounts, model weights, live RAM, network endpoints or
operator credentials. Never bypass authorization to make a test pass. For schema
changes, append a migration and test legacy upgrades, row preservation, rollback,
idempotence and newer-version rejection.

Source and documentation are UTF-8. Never commit accounts, keys, backups, runtime
databases, model weights or private reports. Update the changelog, configuration
reference and verification record when behavior changes. Windows regression tests
do not establish Linux deployment or real-model acceptance.
