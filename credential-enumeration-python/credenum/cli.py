"""
cli.py  --  Command-line entry point and argument parser.

Python port of the Nim `harvester.nim`. Parses the command-line flags into a
HarvestConfig, then either previews the scan (--dry-run) or runs every enabled
module via run_collectors, stamps the report with a UTC timestamp, and routes
output to the terminal renderer, the JSON serializer, or both.

Exit code convention (unchanged from the Nim tool, so it drops into CI the
same way): exit 1 if any CRITICAL or HIGH finding exists, else 0.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import List

from . import config as C
from .output.json_report import render_json
from .output.terminal import render_terminal
from .runner import run_collectors
from .types import Category, HarvestConfig, OutputFormat, Severity


def print_help() -> None:
    b = C.BINARY_NAME
    names = ",".join(C.MODULE_NAMES[c] for c in C.ALL_MODULES)
    lines = [
        f"{C.COLOR_BOLD}{b}{C.COLOR_RESET} v{C.APP_VERSION}",
        "",
        "  Post-access credential exposure detection for Linux systems",
        "",
        f"{C.COLOR_BOLD}USAGE:{C.COLOR_RESET}",
        f"  {b} [flags]",
        "",
        f"{C.COLOR_BOLD}FLAGS:{C.COLOR_RESET}",
        "  --target <path>       Target home directory (default: current user)",
        f"  --modules <list>      Comma-separated modules: {names}",
        "  --exclude <patterns>  Comma-separated path patterns to skip",
        "  --format <fmt>        Output format: terminal, json, both (default: terminal)",
        "  --output <path>       Write JSON output to file",
        "  --dry-run             List scan targets without reading files",
        "  --quiet               Suppress banner, show findings only",
        "  --verbose             Show all scanned paths including empty modules",
        "  --help                Show this help",
        "  --version             Show version",
        "",
        f"{C.COLOR_BOLD}EXAMPLES:{C.COLOR_RESET}",
        f"  {b}                           Scan current user",
        f"  {b} --format json             JSON output",
        f"  {b} --modules ssh,git,cloud   Scan specific modules",
        f"  {b} --target /home/victim     Scan another user",
        f"  {b} --dry-run                 Preview scan paths",
        "",
    ]
    print("\n".join(lines))


def parse_modules(value: str) -> List[Category]:
    """Map a comma-separated module list to Category values; ignore unknowns."""
    result = []
    name_to_cat = {name: cat for cat, name in C.MODULE_NAMES.items()}
    for part in value.split(","):
        name = part.strip().lower()
        if name in name_to_cat:
            result.append(name_to_cat[name])
    return result


def parse_cli(argv: List[str]) -> HarvestConfig:
    config = C.default_config()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", "-t")
    parser.add_argument("--modules", "-m")
    parser.add_argument("--exclude", "-e")
    parser.add_argument("--format", "-f", dest="fmt")
    parser.add_argument("--output", "-o")
    parser.add_argument("--dry-run", "-d", dest="dry_run", action="store_true")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--help", "-h", dest="help", action="store_true")
    parser.add_argument("--version", action="store_true")

    args, _unknown = parser.parse_known_args(argv)

    if args.help:
        print_help()
        raise SystemExit(0)
    if args.version:
        print(f"{C.BINARY_NAME} {C.APP_VERSION}")
        raise SystemExit(0)

    if args.target is not None:
        config.target_dir = args.target
    if args.modules is not None:
        config.enabled_modules = parse_modules(args.modules)
    if args.exclude is not None:
        config.exclude_patterns = args.exclude.split(",")
    if args.fmt is not None:
        f = args.fmt.lower()
        if f == "json":
            config.output_format = OutputFormat.JSON
        elif f == "both":
            config.output_format = OutputFormat.BOTH
        else:
            config.output_format = OutputFormat.TERMINAL
    if args.output is not None:
        config.output_path = args.output
    config.dry_run = args.dry_run
    config.quiet = args.quiet
    config.verbose = args.verbose

    return config


def render_dry_run(conf: HarvestConfig) -> None:
    print(f"{C.COLOR_BOLD}Dry run — scan targets:{C.COLOR_RESET}")
    print()
    for cat in conf.enabled_modules:
        print(f"  {C.COLOR_CYAN}{C.MODULE_NAMES[cat]}{C.COLOR_RESET}: {C.MODULE_DESCRIPTIONS[cat]}")
    print()
    print(f"{C.COLOR_DIM}  Target: {conf.target_dir}{C.COLOR_RESET}")
    print()


def main(argv: List[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    conf = parse_cli(argv)

    if conf.dry_run:
        render_dry_run(conf)
        return 0

    report = run_collectors(conf)
    report.metadata.timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if conf.output_format == OutputFormat.TERMINAL:
        render_terminal(report, conf.quiet, conf.verbose)
    elif conf.output_format == OutputFormat.JSON:
        render_json(report, conf.output_path)
    elif conf.output_format == OutputFormat.BOTH:
        render_terminal(report, conf.quiet, conf.verbose)
        render_json(report, conf.output_path)

    has_high_severity = report.summary[Severity.CRITICAL] > 0 or report.summary[Severity.HIGH] > 0
    return 1 if has_high_severity else 0
