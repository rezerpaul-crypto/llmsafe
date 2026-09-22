# Releasing LLMSafe

Releases are built by GitHub Actions and published to PyPI with Trusted Publishing. Maintainers do
not store a long-lived PyPI token in GitHub.

## One-time setup

1. Create a protected GitHub environment named `pypi` and require maintainer approval.
2. On PyPI, add a pending Trusted Publisher with:
   - PyPI project name: `llmsafe`
   - GitHub owner: `rezerpaul-crypto`
   - Repository: `llmsafe`
   - Workflow: `release.yml`
   - Environment: `pypi`

The pending publisher creates the PyPI project during the first successful publication.

## Release checklist

1. Update the version in `pyproject.toml` and `llmsafe/__init__.py`.
2. Move relevant entries from `Unreleased` to the dated release section in `CHANGELOG.md`.
3. Update versioned examples in `README.md` and run:

   ```bash
   ruff check .
   pytest --cov=llmsafe --cov-report=term-missing
   python -m benchmarks.run
   python -m build
   python -m twine check dist/*
   ```

4. Merge the focused release pull request after CI passes.
5. Create a GitHub release whose tag is exactly `v<package-version>`.
6. Approve the `pypi` deployment after the build job succeeds.
7. Verify the PyPI page, provenance, and a clean-environment installation.

The release workflow rejects a tag that does not match the version in `pyproject.toml`.

## Release build dependency policy

GitHub's Ubuntu 24.04/Python 3.12 package and release jobs install
`requirements/release-linux-py312.txt` with pip hash enforcement. The lock includes exact direct and
transitive versions, permits wheels only, and contains the build backend used by
`python -m build --no-isolation`. This prevents the release job from resolving a new backend or
packaging-tool graph after a tag is published.

When a direct tool changes, edit `requirements/release.in`, regenerate the lock exactly as described
in `docs/supply-chain.md`, review the full diff, and merge only after the target package job passes.
