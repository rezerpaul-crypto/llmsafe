# Configuration

LLMSafe discovers policy by walking from the current directory toward the filesystem root. The
closest `.llmsafe.toml` wins. If none exists, LLMSafe looks for `[tool.llmsafe]` in the closest
`pyproject.toml`.

## Dedicated policy

```toml
[llmsafe]
exclude = ["generated/**", "vendor/**"]
fail_on = "high"
max_file_size = 1000000
disabled_rules = ["PY004"]
baseline = ".llmsafe-baseline.json"
```

## `pyproject.toml`

```toml
[tool.llmsafe]
exclude = ["tests/fixtures/**"]
fail_on = "medium"
max_file_size = 2000000
disabled_rules = []
baseline = ".llmsafe-baseline.json"
```

## Settings

| Setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `exclude` | array of strings | `[]` | File-name or path globs skipped during traversal |
| `fail_on` | string | `"high"` | `low`, `medium`, `high`, or `critical` exit threshold |
| `max_file_size` | positive integer | `1000000` | Maximum bytes read from one file |
| `disabled_rules` | array of strings | `[]` | Stable rule IDs excluded from results |
| `baseline` | string | unset | Reviewed baseline path, relative to the policy file |

Unknown settings and invalid types fail with exit code 2. This catches policy typos rather than
silently weakening a scan.

## CLI precedence

- `--config PATH` replaces automatic discovery.
- `--exclude GLOB` extends configured excludes and may be repeated.
- `--disable-rule ID` extends configured disabled rules and may be repeated.
- `--fail-on SEVERITY` overrides the configured threshold.
- `--baseline PATH` overrides the configured baseline.
- `--write-baseline PATH` ignores the configured baseline and records the current result instead.

## Inline suppressions

```python
# llmsafe: ignore[FLOW004] -- URL was validated against INTERNAL_SERVICE_HOSTS above
requests.get(validated_url)
```

Multiple IDs can be comma-separated. A bare `llmsafe: ignore` suppresses all findings at that
location and is intentionally more visible in review.

## Path matching

Excludes are matched against the rendered path, the base filename, and the pattern under any
parent path. Common dependency, build, cache, virtual-environment, and VCS directories are skipped
by default. Directory traversal does not follow symbolic links, and symbolic-link files are not
read, so a repository link cannot silently expand the scan outside the selected tree.
