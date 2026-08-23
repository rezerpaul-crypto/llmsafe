"""Command-line interface for LLMSafe."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from llmsafe import __version__
from llmsafe.models import ScanResult, Severity
from llmsafe.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llmsafe",
        description="Scan AI and agentic applications for common security risks.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        default=Severity.HIGH.value,
        help="Exit with status 1 at this severity or above (default: high)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a file or path glob; may be repeated",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def render_text(result: ScanResult) -> str:
    lines = []
    for finding in result.findings:
        lines.append(
            f"{finding.path}:{finding.line}:{finding.column}: "
            f"{finding.severity.value.upper()} {finding.rule_id} {finding.title}"
        )
        lines.append(f"  {finding.message}")
        lines.append(f"  Fix: {finding.remediation}")
    if result.errors:
        for error in result.errors:
            lines.append(f"ERROR {error.path}: {error.message}")
    lines.append(
        f"Scanned {result.scanned_files} file(s), skipped {result.skipped_files}; "
        f"found {len(result.findings)} issue(s)."
    )
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "version": __version__,
        "summary": {
            "scanned_files": result.scanned_files,
            "skipped_files": result.skipped_files,
            "findings": len(result.findings),
            "errors": len(result.errors),
        },
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": [error.to_dict() for error in result.errors],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    scanner = Scanner(excludes=args.exclude)
    result = scanner.scan(Path(value) for value in args.paths)
    output = render_json(result) if args.output_format == "json" else render_text(result)
    print(output)
    if result.errors:
        return 2
    minimum = Severity.parse(args.fail_on)
    return 1 if result.has_findings_at(minimum) else 0


if __name__ == "__main__":
    sys.exit(main())
