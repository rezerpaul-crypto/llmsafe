"""Command-line interface for LLMSafe."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from llmsafe import __version__
from llmsafe.baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from llmsafe.catalog import CATALOG_SCHEMA_VERSION, RULE_CATALOG
from llmsafe.config import ConfigError, load_config
from llmsafe.models import ScanResult, Severity
from llmsafe.sarif import to_sarif
from llmsafe.scanner import Scanner

SCAN_SCHEMA_VERSION = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llmsafe",
        description="Scan AI and agentic applications for common security risks.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        default=None,
        help="Exit with status 1 at this severity or above (default: high)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a file or path glob; may be repeated",
    )
    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Disable a rule ID; may be repeated",
    )
    parser.add_argument("--config", type=Path, help="Path to an LLMSafe TOML policy")
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List built-in rule metadata without scanning",
    )
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument(
        "--baseline",
        type=Path,
        help="Ignore findings recorded in this baseline JSON file",
    )
    baseline.add_argument(
        "--write-baseline",
        type=Path,
        help="Record current findings as a reviewed baseline",
    )
    parser.add_argument("--output", type=Path, help="Write output to a file instead of stdout")
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
        for evidence in finding.evidence:
            location = f"{evidence.line}:{evidence.column}"
            if evidence.path is not None:
                location = f"{evidence.path}:{location}"
            lines.append(f"  Trace {location}: {evidence.message}")
        lines.append(f"  Fix: {finding.remediation}")
    if result.errors:
        for error in result.errors:
            lines.append(f"ERROR {error.path}: {error.message}")
    summary = (
        f"Scanned {result.scanned_files} file(s), skipped {result.skipped_files}; "
        f"found {len(result.findings)} issue(s)."
    )
    if result.baseline_findings:
        summary += f" Ignored {result.baseline_findings} baseline finding(s)."
    lines.append(summary)
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "schema_version": SCAN_SCHEMA_VERSION,
        "version": __version__,
        "summary": {
            "scanned_files": result.scanned_files,
            "skipped_files": result.skipped_files,
            "findings": len(result.findings),
            "baseline_findings": result.baseline_findings,
            "errors": len(result.errors),
        },
        "findings": [finding.to_dict() for finding in result.findings],
        "errors": [error.to_dict() for error in result.errors],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2, sort_keys=True)


def render_rule_catalog(output_format: str) -> str:
    rules = sorted(RULE_CATALOG, key=lambda rule: rule.rule_id)
    if output_format == "json":
        return json.dumps(
            {
                "schema_version": CATALOG_SCHEMA_VERSION,
                "version": __version__,
                "rules": [rule.to_dict() for rule in rules],
            },
            indent=2,
            sort_keys=True,
        )
    lines = [
        f"{rule.rule_id:<9} {rule.severity.value.upper():<8} {rule.family:<8} {rule.title}"
        for rule in rules
    ]
    lines.append(f"{len(rules)} built-in rule(s).")
    return "\n".join(lines)


def write_output(output: str, destination: Optional[Path]) -> bool:
    """Write output and return whether the operation succeeded."""

    if destination is None:
        print(output)
        return True
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"llmsafe: cannot write {destination}: {exc}", file=sys.stderr)
        return False
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        if args.output_format == "sarif":
            print("llmsafe: --list-rules supports text or json output", file=sys.stderr)
            return 2
        return 0 if write_output(render_rule_catalog(args.output_format), args.output) else 2
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"llmsafe: configuration error: {exc}", file=sys.stderr)
        return 2
    baseline_path = args.baseline or (config.baseline if not args.write_baseline else None)
    selected_baseline = None
    if baseline_path:
        try:
            selected_baseline = load_baseline(baseline_path)
        except BaselineError as exc:
            print(f"llmsafe: baseline error: {exc}", file=sys.stderr)
            return 2
    if args.output and args.write_baseline:
        try:
            same_destination = args.output.resolve() == args.write_baseline.resolve()
        except OSError:
            same_destination = args.output.absolute() == args.write_baseline.absolute()
        if same_destination:
            print("llmsafe: output and baseline paths must differ", file=sys.stderr)
            return 2
    scan_baseline_path = baseline_path or args.write_baseline
    baseline_excludes = ()
    if scan_baseline_path:
        baseline_excludes = (scan_baseline_path.as_posix(), scan_baseline_path.name)
    scanner = Scanner(
        excludes=(*config.excludes, *args.exclude, *baseline_excludes),
        max_file_size=config.max_file_size,
        disabled_rules=(*config.disabled_rules, *args.disable_rule),
    )
    result = scanner.scan(Path(value) for value in args.paths)
    if selected_baseline is not None:
        result = apply_baseline(result, selected_baseline, baseline_path.parent.resolve())
    if args.write_baseline and not result.errors:
        try:
            count = write_baseline(
                args.write_baseline,
                result.findings,
                args.write_baseline.parent.resolve(),
            )
        except BaselineError as exc:
            print(f"llmsafe: baseline error: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {count} finding(s) to baseline {args.write_baseline}", file=sys.stderr)
    renderers = {"text": render_text, "json": render_json, "sarif": render_sarif}
    output = renderers[args.output_format](result)
    if not write_output(output, args.output):
        return 2
    if result.errors:
        return 2
    if args.write_baseline:
        return 0
    minimum = Severity.parse(args.fail_on) if args.fail_on else config.fail_on
    return 1 if result.has_findings_at(minimum) else 0


if __name__ == "__main__":
    sys.exit(main())
