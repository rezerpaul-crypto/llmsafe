# Development workflow

LLMSafe has one contributor command for environment setup and every required quality check:

```bash
python3 scripts/dev.py
```

The command creates `.venv` when needed, updates an outdated `pip` inside that isolated environment,
installs LLMSafe with its development tools, and then runs:

1. Ruff linting.
2. The complete test suite with the coverage gate.
3. The curated vulnerable/safe benchmark.
4. An installed-command smoke test.
5. LLMSafe's self-scan with the repository policy.

No shell activation is required. The first run needs network access to install development
dependencies; later checks can skip installation:

```bash
python3 scripts/dev.py --check-only
```

## Choose a Python version

Run the script with the Python interpreter you want the environment to use:

```bash
python3.12 scripts/dev.py --venv .venv-3.12
```

On Windows, the equivalent command can use the Python launcher:

```powershell
py -3.12 scripts/dev.py --venv .venv-3.12
```

LLMSafe supports Python 3.9 through 3.14. CI runs this same workflow independently on every
supported version. A local contributor normally needs only one supported version; compatibility
failures on another version are visible in the pull request checks.

## CI mode

The `--current` option installs into the current environment instead of creating `.venv`. It is
intended for a disposable virtual environment or CI job:

```bash
python scripts/dev.py --current
```

Do not use `--current` with a system Python where you do not want packages installed.

On Windows, the contributor workflow runs the platform-neutral test suite, benchmark, CLI smoke test,
and self-scan. The direct `scripts/run-action.sh` test harness is Unix-only and is skipped on
Windows because invoking bare `bash` there can resolve to the Windows/WSL shim instead of the
GitHub runner's Git Bash. The composite action itself explicitly declares `shell: bash`, and its
shell harness remains covered by the Ubuntu action-contract job.

## Individual commands

The workflow deliberately keeps the project commands visible. When diagnosing one failed stage,
activate the environment or prefix the command with its Python executable and run:

```bash
python -m ruff check .
python -m pytest --cov=llmsafe --cov-report=term-missing
python -m benchmarks.run
python -m llmsafe --version
python -m llmsafe . --format json
```

The pull-request quality gate is the complete workflow, not a successful individual stage.
