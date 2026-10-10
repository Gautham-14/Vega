# Release gate

Supported development Python versions: 3.11, 3.12, 3.13 and 3.14. Native operators
target Windows, macOS and Linux; hardened services use the isolated Linux guest
on those hosts or native Linux deployment. CI schedules every version on all
three platforms. VM installation/acceptance was explicitly not performed. A configured
matrix is not evidence those remote jobs have run: local evidence currently
comes from Windows Python 3.14.7.

The [last remote baseline run](https://github.com/Gautham-14/Aegis/actions/runs/37967909295)
passed Windows/Linux Python 3.11/3.12, custody and dependency jobs for commit
`7a5b874430602be28dd05cb7f83f9276dd33e76c`. It did not test the current
uncommitted changes, macOS, or Python 3.13/3.14. Running the expanded matrix
requires a commit/push. The owner has now authorized a new branch for that run;
its results are separate from the local record in WORKFLOW_VERIFICATION.md.

Install the hash-pinned development and quality profiles in an isolated environment.
Run from the repository root with Git on PATH:

```text
python -m scripts.project_checks snapshot --output .audit-tmp/source-snapshot.json
python -m coverage run -m pytest -q -ra -p no:cacheprovider --junitxml=.audit-tmp/results.xml
python -m coverage json -o .audit-tmp/coverage.json
python -m coverage xml -o .audit-tmp/coverage.xml
python -m build --wheel --no-isolation --outdir .audit-tmp/wheel
python -m scripts.check_package .audit-tmp/wheel/aegis_runtime-1.0.0-py3-none-any.whl --output .audit-tmp/package.json
python -m compileall -q aegis scripts tests aegis.py run_aegis.py demo_pipeline.py
python -m scripts.project_checks release --snapshot .audit-tmp/source-snapshot.json --junit .audit-tmp/results.xml --coverage .audit-tmp/coverage.json --package .audit-tmp/package.json --output .audit-tmp/verification.json
```

Adjust the wheel filename to the authoritative version. If quality tools are
installed separately, pass `--quality-python <that-environment-python>` to the
final check. The release check requires no failed tests, fresh reports, unchanged
source and lock hashes, consistent versions, successful wheel installation,
valid UTF-8, passing Ruff lint/format and incremental strict typing.
Critical authentication, authorization, recovery and coding/advisory/media
dispatch modules each require at least 80% combined statement/branch coverage.
Coverage is a regression floor, not proof that security is complete.

Review every skip on the target OS. Linux separate-UID custody tests run under
their dedicated CI job; production release additionally requires completed
DEPLOYMENT_ACCEPTANCE.md gates on intended infrastructure and selected models.
Do not call a source-only gate production acceptance.
The local synthetic LLM probe is separate: correct routing does not imply
correct answers. A `NEEDS_REVIEW` quality report cannot qualify those models
for correctness-sensitive or hardened-production deployment, even if the
software source gate passes.

Archive source snapshot, verification JSON, JUnit, coverage, package report,
wheel, SBOM and dependency lockfiles per release. Regenerate evidence after
implementation or lock changes. Only then create the separately signed offline
release using `scripts.release_security`; its monotonic release counter is not
the application version. The owner must configure branch protection to require
all CI jobs before merge/release; local files cannot enable repository protection.
