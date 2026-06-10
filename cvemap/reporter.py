"""
Reporter module — generates JSON and HTML vulnerability reports.

HTML report is generated from a Jinja2 template and includes:
  - Executive summary with severity breakdown
  - Per-host, per-port CVE tables
  - CVSS score badges
  - Dark-mode cybersecurity aesthetic
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from rich.table import Table
from rich import box

from .utils import console, cvss_to_severity, severity_badge, utc_now_iso, get_logger

logger = get_logger(__name__)

# Jinja2 import — optional at module level, raised only if HTML export attempted
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape, Template
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False


# ---------------------------------------------------------------------------
# Report data builder
# ---------------------------------------------------------------------------

def build_report_data(
    scan_results: list,
    target: str,
    ports: str,
    args_used: Optional[str] = None,
    tool_version: str = "1.0.0",
) -> dict:
    """
    Aggregate all scan results into a single serialisable report dict.

    Args:
        scan_results: List of ScanResult objects.
        target:       Original scan target string.
        ports:        Port range used.
        args_used:    Full CLI invocation (for audit trail).
        tool_version: cvemap version string.

    Returns:
        dict ready for JSON serialisation or Jinja2 rendering.
    """
    hosts_data = [r.to_dict() for r in scan_results]

    # Aggregate severity counts across ALL CVEs
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    all_cves = []
    for result in scan_results:
        for port in result.ports:
            for cve in port.cves:
                sev = cvss_to_severity(cve.cvss_score)
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                all_cves.append(cve.to_dict())

    total_hosts = len(scan_results)
    total_open_ports = sum(r.open_port_count for r in scan_results)
    total_cves = len(all_cves)

    return {
        "meta": {
            "tool": "cvemap",
            "version": tool_version,
            "generated_at": utc_now_iso(),
            "target": target,
            "ports": ports,
            "args_used": args_used or "",
        },
        "summary": {
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "total_cves": total_cves,
            "severity_counts": severity_counts,
            "risk_score": _calculate_risk_score(severity_counts),
        },
        "hosts": hosts_data,
    }


def _calculate_risk_score(severity_counts: dict) -> float:
    """Weighted risk score 0–10 based on severity distribution."""
    weights = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "NONE": 0.0}
    total = sum(severity_counts.values())
    if not total:
        return 0.0
    weighted = sum(weights.get(k, 0) * v for k, v in severity_counts.items())
    return round(min(weighted / max(total, 1), 10.0), 2)


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------

class Reporter:
    """
    Generates JSON and HTML reports from enriched scan results.

    Usage::

        reporter = Reporter(output_dir="./reports")
        reporter.save_json(report_data, "scan_192.168.1.0")
        reporter.save_html(report_data, "scan_192.168.1.0")
    """

    def __init__(
        self,
        output_dir: str = ".",
        template_dir: Optional[str] = None,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Locate templates directory
        if template_dir:
            self.template_dir = Path(template_dir)
        else:
            # Default: <project-root>/templates  or  next to this file/../templates
            candidates = [
                Path(__file__).parent.parent / "templates",
                Path("templates"),
            ]
            self.template_dir = next((p for p in candidates if p.exists()), candidates[0])

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def save_json(self, report_data: dict, stem: str = "cvemap_report") -> Path:
        """
        Write the report as a pretty-printed JSON file.

        Returns:
            Path to the saved file.
        """
        out_path = self.output_dir / f"{stem}.json"
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, ensure_ascii=False)

        console.print(f"[success]✔  JSON report saved:[/success] [link]{out_path}[/link]")
        return out_path

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def save_html(self, report_data: dict, stem: str = "cvemap_report") -> Path:
        """
        Render an HTML report using the Jinja2 template.

        Returns:
            Path to the saved file.
        """
        if not _JINJA2_AVAILABLE:
            raise ImportError(
                "Jinja2 is required for HTML reports. "
                "Run: pip install jinja2"
            )

        template_path = self.template_dir / "report.html"
        if not template_path.exists():
            raise FileNotFoundError(
                f"HTML template not found: {template_path}\n"
                "Ensure the templates/ directory exists in the project root."
            )

        env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html"]),
        )

        # Custom Jinja2 filters
        env.filters["cvss_severity"] = cvss_to_severity
        env.filters["severity_class"] = lambda s: s.lower()
        env.filters["format_date"] = lambda d: d[:10] if d else "—"

        template = env.get_template("report.html")
        rendered = template.render(
            report=report_data,
            generated_at_human=datetime.now(timezone.utc).strftime("%B %d, %Y — %H:%M UTC"),
        )

        out_path = self.output_dir / f"{stem}.html"
        out_path.write_text(rendered, encoding="utf-8")

        console.print(f"[success]✔  HTML report saved:[/success] [link]{out_path}[/link]")
        return out_path

    # ------------------------------------------------------------------
    # Terminal summary
    # ------------------------------------------------------------------

    def print_summary(self, report_data: dict) -> None:
        """Print a concise executive summary table to stdout."""
        summary = report_data["summary"]
        meta = report_data["meta"]

        console.print(f"\n[bold]╔══ SCAN SUMMARY ════════════════════════════╗[/bold]")
        console.print(f"  Target      : [cyan]{meta['target']}[/cyan]")
        console.print(f"  Hosts found : [cyan]{summary['total_hosts']}[/cyan]")
        console.print(f"  Open ports  : [cyan]{summary['total_open_ports']}[/cyan]")
        console.print(f"  CVEs found  : [cyan]{summary['total_cves']}[/cyan]")
        console.print(f"  Risk score  : [cyan]{summary['risk_score']} / 10[/cyan]")
        console.print(f"[bold]╚════════════════════════════════════════════╝[/bold]\n")

        counts = summary["severity_counts"]
        sev_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold magenta",
        )
        sev_table.add_column("Severity", width=10)
        sev_table.add_column("Count", justify="right", width=8)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
            count = counts.get(sev, 0)
            if count > 0:
                badge = severity_badge(sev)
                sev_table.add_row(badge, str(count))

        console.print(sev_table)

    # ------------------------------------------------------------------
    # CVE detail display
    # ------------------------------------------------------------------

    def print_cve_details(self, scan_results: list) -> None:
        """Print detailed CVE findings per host/port to the terminal."""
        for result in scan_results:
            ports_with_cves = [p for p in result.ports if p.cves]
            if not ports_with_cves:
                continue

            console.rule(
                f"[bold]CVE Details — {result.display_name}[/bold]",
                style="red",
            )

            for port in ports_with_cves:
                console.print(
                    f"\n  [cyan]Port {port.port}/{port.protocol}[/cyan] — "
                    f"[bold]{port.version_string or port.service}[/bold]"
                )

                cve_table = Table(
                    box=box.MINIMAL,
                    show_header=True,
                    header_style="bold",
                    border_style="dim",
                    expand=True,
                )
                cve_table.add_column("CVE ID", style="cve", width=18)
                cve_table.add_column("CVSS", justify="center", width=6)
                cve_table.add_column("Severity", width=10)
                cve_table.add_column("Published", width=12)
                cve_table.add_column("Description", overflow="fold")

                for cve in port.cves:
                    sev_str = severity_badge(cve.severity)
                    desc = cve.description[:120] + "…" if len(cve.description) > 120 else cve.description
                    cve_table.add_row(
                        cve.cve_id,
                        f"{cve.cvss_score:.1f}",
                        sev_str,
                        cve.published,
                        desc,
                    )

                console.print(cve_table)

        console.print()
