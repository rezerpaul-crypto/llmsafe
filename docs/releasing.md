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
