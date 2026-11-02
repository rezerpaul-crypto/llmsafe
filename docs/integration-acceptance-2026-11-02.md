# Combined PR #55–#58 acceptance (November 2, 2026)

This is a non-release integration branch based on PR #56 head `96eec73c4e7a9913ce8fa13be72f4e33bacd80c9`. It integrates the patch changes from #55, #57, and #58 without merging any of those original PRs into main. Exact commit and CI run are authoritative, not this document.

## Gates
- Full Linux Python 3.9–3.14, Windows, packaging, composite action contract, Code Scanning, CI checks, baseline 21/21 cases and 37/37 expected signals.
- A dedicated GitHub-hosted `macos-15` Python 3.12 job runs the complete contributor workflow, executes **all 18** focused research cases, asserts only G01/G02/G04/G06/G07/C01/C02/C03, and measures the 500-module chain on its own machine.
- The remaining research G03/G05/G08/G09/G10 and other cases are reported; do not mistake passing targeted cases for full 18/18 acceptance.
- Failing jobs block this integration. Even green CI does not amount to an independent human security review or verification on the owner's personal Apple Silicon Mac.

## Review and release status
- PR #55: syntax failures should be visible in existing JSON v1 / SARIF error paths, exit 2; beware runtime-version and cost boundaries.
- PR #56: bounded nested dictionaries, aliases, `SimpleNamespace`, unknown keys and the fixed-key update semantics. Treat external mutation, dynamic unknown objects, interprocedural field-state, and deeper-than-three nested paths as unsupported.
- PR #57: officially recognized LangChain/PydanticAI decorators vs injected contexts. Dynamic registries remain unresolved.
- PR #58: narrow POSIX literal echo data argv exception; no generic `shell=False` sanitizer and no Windows batch-file guarantee.
- Must obtain an independent security reviewer and run local macOS acceptance when device-specific evidence is required.
- No merge of original PRs, no release, no external scans and no Paid GO are authorized by this integration review.

## Proposed next research fixes (stacked draft)

A follow-up branch based on this integration head tests the five previously missing
frozen cases G03/G05/G08/G09/G10. Its bounded local instance-method recognition
does not resolve dynamic factories, inheritance, decorators, cross-module receiver
identity, or arbitrary runtime rebinding. The harmless dispatch exception requires
one immutable, literal-key dictionary of direct local, zero-argument functions whose
bodies each consist of a single constant return. It does **not** imply arbitrary
dynamic dispatch is safe. The unrelated .execute exception applies only to a
statically proven direct local instance method; unknown database receivers remain
conservative.

MCP shell executable matching uses the final component of a POSIX/Windows path,
and VS Code MCP configs may use a top-level servers dictionary. Neither treats
generic settings.json servers values as MCP registration.

The 18-case research harness, normal benchmark, full CI and hosted macOS gates
remain requirements. A green result is not equivalent to independent security
review or Paid GO.
