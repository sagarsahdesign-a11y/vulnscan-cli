"""
CLI entry point for cvemap.

Commands
--------
  cvemap scan     — Scan a target and look up CVEs
  cvemap version  — Print version information

Examples
--------
  cvemap scan -t 192.168.1.0/24
  cvemap scan -t 192.168.1.1 -p 1-65535 --stealth
  cvemap scan -t scanme.nmap.org -p 22,80,443 -o report --format html json
  cvemap scan -t 10.0.0.1 --no-cve --timing 4
"""

from __future__ import annotations

import sys
import argparse
import textwrap
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from cvemap import __version__, __description__
from cvemap.utils import (
    console,
    err_console,
    load_config,
    print_banner,
    sanitize_filename,
    utc_now_iso,
    get_logger,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cvemap",
        description=textwrap.dedent(
            f"""
            cvemap v{__version__} — {__description__}

            Scan networks, enumerate services, and cross-reference
            discovered software versions against the NIST NVD CVE database.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              cvemap scan -t 192.168.1.1
              cvemap scan -t 192.168.1.0/24 -p 1-65535 --stealth
              cvemap scan -t scanme.nmap.org -o /tmp/report --format html json
              cvemap scan -t 10.0.0.5 --timing 5 --scripts vuln,auth
            """
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    # ── scan ────────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a target and look up CVEs for discovered services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    scan_p.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)",
    )
    scan_p.add_argument(
        "-p", "--ports",
        default="1-1000",
        metavar="PORTS",
        help='Port range or list (default: 1-1000). Examples: "22,80,443", "1-65535", "-"',
    )
    scan_p.add_argument(
        "-o", "--output",
        default=None,
        metavar="PATH",
        help="Output file stem (without extension). Default: cvemap_<target>_<timestamp>",
    )
    scan_p.add_argument(
        "--format",
        nargs="+",
        choices=["json", "html"],
        default=["html", "json"],
        metavar="FMT",
        help="Output format(s): json, html (default: html json)",
    )
    scan_p.add_argument(
        "--output-dir",
        default=None,
        metavar="DIR",
        help="Directory to write reports (default: current directory)",
    )
    scan_p.add_argument(
        "--timing",
        type=int,
        choices=range(0, 6),
        default=None,
        metavar="0-5",
        help="Nmap timing template 0=paranoid … 5=insane (default: 3)",
    )
    scan_p.add_argument(
        "--stealth",
        action="store_true",
        help="Use SYN scan (-sS). Requires root / Administrator privileges.",
    )
    scan_p.add_argument(
        "--no-os",
        action="store_true",
        help="Disable OS fingerprinting (speeds up scan, may not need root)",
    )
    scan_p.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE lookup (scan only, faster)",
    )
    scan_p.add_argument(
        "--max-cves",
        type=int,
        default=None,
        metavar="N",
        help="Max CVEs to retrieve per service (default: 10)",
    )
    scan_p.add_argument(
        "--scripts",
        default=None,
        metavar="SCRIPTS",
        help="Nmap NSE script categories/names (e.g., vuln,auth,safe)",
    )
    scan_p.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="NIST NVD API key for higher rate limits (or set NVD_API_KEY env var)",
    )
    scan_p.add_argument(
        "--env-file",
        default=None,
        metavar="FILE",
        help="Path to .env file (default: ./.env or ~/.cvemap/.env)",
    )
    scan_p.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SECS",
        help="Per-host scan timeout in seconds (default: 300)",
    )
    scan_p.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII art banner",
    )
    scan_p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show per-port CVE query details)",
    )
    scan_p.add_argument(
        "--no-report",
        action="store_true",
        help="Do not write report files; print CVE details to terminal only",
    )

    # ── version ─────────────────────────────────────────────────────────────
    subparsers.add_parser(
        "version",
        help="Print cvemap version and exit",
    )

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_version() -> None:
    from cvemap.utils import BANNER
    console.print(f"[banner]{BANNER}[/banner]")
    console.print(f"  cvemap [bold cyan]v{__version__}[/bold cyan]\n")
    console.print(f"  [dim]{__description__}[/dim]")
    console.print(f"  [dim]https://github.com/sagarsahdesign-a11y/vulnscan-cli[/dim]\n")


def cmd_scan(args: argparse.Namespace, config: dict) -> int:
    """Execute scan + CVE lookup + reporting. Returns exit code."""
    from cvemap.scanner import NetworkScanner
    from cvemap.cve_lookup import CVELookup
    from cvemap.reporter import Reporter, build_report_data

    # ── Banner ───────────────────────────────────────────────────────────────
    if not args.no_banner:
        print_banner(__version__)

    # ── Resolve config ───────────────────────────────────────────────────────
    timing = args.timing if args.timing is not None else config["timing"]
    api_key = args.api_key or config["nvd_api_key"]
    max_cves = args.max_cves or config["max_cves_per_port"]
    output_dir = args.output_dir or config["output_dir"]

    if api_key:
        console.print("[dim]>> NVD API key detected -- using elevated rate limits[/dim]")
    else:
        console.print(
            "[dim]>> No NVD API key -- free tier (4 req/30s). "
            "Set NVD_API_KEY in .env for faster lookups.[/dim]"
        )

    # ── Scan ─────────────────────────────────────────────────────────────────
    scanner = NetworkScanner(
        timing=timing,
        timeout=args.timeout,
        stealth=args.stealth,
    )

    try:
        scan_results = scanner.scan(
            target=args.target,
            ports=args.ports,
            os_detection=not args.no_os,
            service_detection=True,
            scripts=args.scripts,
        )
    except ValueError as exc:
        err_console.print(f"\n[error]✖  {exc}[/error]")
        return 1
    except RuntimeError as exc:
        err_console.print(f"\n[error]✖  Scan error: {exc}[/error]")
        return 1
    except PermissionError:
        err_console.print(
            "\n[error]✖  Permission denied — SYN scan and OS detection require "
            "root (Linux/macOS) or Administrator (Windows).[/error]"
        )
        return 1

    if not scan_results:
        console.print("[yellow]No live hosts found. Exiting.[/yellow]")
        return 0

    scanner.display_results(scan_results)

    # ── CVE Enrichment ───────────────────────────────────────────────────────
    if not args.no_cve:
        lookup = CVELookup(
            api_key=api_key,
            max_results=max_cves,
            request_timeout=config["request_timeout"],
        )
        lookup.enrich_scan_results(scan_results, verbose=args.verbose)

    # ── Build report data ────────────────────────────────────────────────────
    cli_args_str = " ".join(sys.argv)
    report_data = build_report_data(
        scan_results=scan_results,
        target=args.target,
        ports=args.ports,
        args_used=cli_args_str,
        tool_version=__version__,
    )

    # ── Terminal output ──────────────────────────────────────────────────────
    reporter = Reporter(output_dir=output_dir)
    reporter.print_summary(report_data)

    if not args.no_cve:
        reporter.print_cve_details(scan_results)

    # ── File reports ─────────────────────────────────────────────────────────
    if not args.no_report:
        # Build output file stem
        if args.output:
            stem = args.output
        else:
            safe_target = sanitize_filename(args.target)
            timestamp = utc_now_iso().replace(":", "").replace("-", "").replace("Z", "")[:15]
            stem = f"cvemap_{safe_target}_{timestamp}"

        formats = [f.lower() for f in args.format]

        if "json" in formats:
            try:
                reporter.save_json(report_data, stem)
            except Exception as exc:
                err_console.print(f"[error]✖  JSON export failed: {exc}[/error]")

        if "html" in formats:
            try:
                reporter.save_html(report_data, stem)
            except FileNotFoundError as exc:
                err_console.print(f"[error]✖  {exc}[/error]")
            except Exception as exc:
                err_console.print(f"[error]✖  HTML export failed: {exc}[/error]")

    # Exit with non-zero code if CRITICAL or HIGH CVEs were found
    sev_counts = report_data["summary"]["severity_counts"]
    if sev_counts.get("CRITICAL", 0) > 0:
        return 2  # Critical findings
    if sev_counts.get("HIGH", 0) > 0:
        return 3  # High findings
    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Console script entry point installed by pip."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "version":
        cmd_version()
        sys.exit(0)

    # Load config from .env / env vars
    env_file = getattr(args, "env_file", None)
    config = load_config(env_file)

    exit_code = cmd_scan(args, config)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
