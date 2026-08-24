# Organization-specific rule extensions

LLMSafe exposes a small Python API for trusted in-process rules. It supports internal policy checks
without turning the CLI into a dynamic plugin loader or importing configuration-selected code.

## Stable surface

Import extension types and entrypoints from `llmsafe.api`:

```python
from pathlib import Path
from typing import Iterable

from llmsafe.api import Finding, Severity, scan_paths


class InternalAdminRule:
    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        if "send_to_internal_admin(" not in content:
            return
        yield Finding(
            rule_id="ACME001",
            title="Internal admin boundary",
            severity=Severity.HIGH,
            path=path,
            line=1,
            column=1,
            message="An organization-specific admin operation requires review.",
            remediation="Apply the organization's authorization policy before this operation.",
        )


result = scan_paths([Path("src")], extra_rules=[InternalAdminRule()])
```

`scan_paths()` always retains LLMSafe's built-ins, then runs explicitly supplied extra rules. It
accepts the same low-level exclusion, size, and disabled-rule policy used by `Scanner`. It returns the
public `ScanResult` model and does not render output or choose an exit threshold.

## Rule contract

A file rule implements:

```python
def scan(path: Path, content: str) -> Iterable[Finding]: ...
```

- Treat source as untrusted data; never import or execute the target application.
- Use an organization-owned uppercase prefix and three digits, such as `ACME001`.
- Do not reuse a built-in ID or another extension's ID.
- Keep title, severity, meaning, and remediation stable once automation consumes the ID.
- Return no secret values in messages or evidence.
- Add vulnerable, safe, malformed, and boundary tests.
- Bound file size, parsing, recursion, and external resource use.

The scanner isolates a rule exception as a scan error. A failing extension therefore produces exit
code 2 through the CLI-style policy and must not be interpreted as a clean result.

## Trust boundary

An extension is arbitrary Python code with the permissions of its host process. Only load code already
trusted by the organization. LLMSafe intentionally does not discover entry points, import modules from
TOML, download rules, or expose a `--plugin` option. Those mechanisms would turn scanning an untrusted
repository into a code-execution and supply-chain boundary.

For CI, keep the extension in a reviewed package, pin its immutable version, instantiate it in a small
organization-owned runner, and call `scan_paths()`. The built-in CLI remains the safer choice when no
custom policy is required.

## Compatibility

`llmsafe.api` names documented here are the extension compatibility surface for `0.3.x`. Internal
modules remain implementation details. Custom findings use the scan JSON v1 shape and SARIF fallback
metadata from the finding itself; custom IDs do not appear in `--list-rules`, which lists built-ins.

See the [rule-authoring guide](rule-authoring.md) for test design and the
[integration contracts](integration-contracts.md) for output stability.
