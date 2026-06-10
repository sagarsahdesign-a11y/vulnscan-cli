"""
Network scanner module — wraps python-nmap for port scanning,
service enumeration, and OS fingerprinting.
"""

from __future__ import annotations

import socket
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    import nmap
except ImportError as exc:
    raise ImportError(
        "python-nmap is required. Run: pip install python-nmap\n"
        "Also ensure nmap is installed on your system: https://nmap.org/download.html"
    ) from exc

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich import box

from .utils import console, get_logger, utc_now_iso

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    """Represents a single open port discovered during scanning."""

    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    script_output: dict = field(default_factory=dict)
    cpe: list[str] = field(default_factory=list)
    cves: list = field(default_factory=list)  # populated by cve_lookup

    @property
    def version_string(self) -> str:
        """Human-readable product + version."""
        parts = [self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p).strip()

    @property
    def search_query(self) -> str:
        """Best search string for NVD CVE lookup."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        if self.product:
            return self.product
        if self.service:
            return self.service
        return ""

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "cves": [c.to_dict() for c in self.cves],
        }


@dataclass
class ScanResult:
    """Represents all scan data collected for a single host."""

    host: str
    hostname: str = ""
    state: str = "unknown"
    os_match: str = "Unknown"
    os_accuracy: int = 0
    ports: list[PortInfo] = field(default_factory=list)
    scan_start: str = ""
    scan_end: str = ""

    @property
    def open_port_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "open")

    @property
    def cve_count(self) -> int:
        return sum(len(p.cves) for p in self.ports)

    @property
    def critical_cves(self) -> list:
        from .utils import cvss_to_severity
        return [
            cve
            for p in self.ports
            for cve in p.cves
            if cvss_to_severity(cve.cvss_score) == "CRITICAL"
        ]

    @property
    def display_name(self) -> str:
        if self.hostname:
            return f"{self.host} ({self.hostname})"
        return self.host

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "state": self.state,
            "os_match": self.os_match,
            "os_accuracy": self.os_accuracy,
            "open_ports": self.open_port_count,
            "cve_count": self.cve_count,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "ports": [p.to_dict() for p in self.ports],
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    Production-ready network scanner built on python-nmap.

    Supports:
      - TCP connect scan  (-sT)  — no root required
      - SYN stealth scan  (-sS)  — requires root/administrator
      - Service version detection (-sV)
      - OS fingerprinting         (-O)   — requires root/administrator
      - NSE script execution      (--script)
      - Configurable timing templates (T0–T5)
    """

    def __init__(
        self,
        timing: int = 3,
        timeout: int = 300,
        stealth: bool = False,
    ):
        """
        Args:
            timing:  Nmap timing template 0 (paranoid) – 5 (insane). Default 3 (normal).
            timeout: Per-host timeout in seconds.
            stealth: Use SYN scan (-sS). Requires root/Administrator.
        """
        if not 0 <= timing <= 5:
            raise ValueError("timing must be between 0 and 5")

        self.timing = timing
        self.timeout = timeout
        self.stealth = stealth

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise RuntimeError(
                "nmap binary not found. Please install nmap:\n"
                "  Linux : sudo apt install nmap\n"
                "  macOS : brew install nmap\n"
                "  Windows: https://nmap.org/download.html"
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        ports: str = "1-1000",
        os_detection: bool = True,
        service_detection: bool = True,
        scripts: Optional[str] = None,
    ) -> list[ScanResult]:
        """
        Execute a full Nmap scan and return structured results.

        Args:
            target:            IP, hostname, or CIDR notation (e.g., 192.168.1.0/24).
            ports:             Port specification (e.g., "1-1000", "22,80,443", "-").
            os_detection:      Enable OS fingerprinting. Requires root.
            service_detection: Enable service/version detection.
            scripts:           NSE scripts to run (e.g., "vuln,auth").

        Returns:
            List of :class:`ScanResult` objects, one per discovered live host.

        Raises:
            ValueError: If the target string is invalid.
            RuntimeError: If nmap fails or is not installed.
        """
        self._validate_target(target)
        args = self._build_args(
            os_detection=os_detection,
            service_detection=service_detection,
            scripts=scripts,
        )

        console.print(
            f"\n[bold cyan]▶  Target  :[/bold cyan] {target}\n"
            f"[bold cyan]   Ports   :[/bold cyan] {ports}\n"
            f"[bold cyan]   Args    :[/bold cyan] nmap {args} -p {ports} {target}\n"
        )

        with Progress(
            SpinnerColumn(spinner_name="dots2", style="cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"Scanning {target} …", total=None)
            scan_start = utc_now_iso()

            try:
                self.nm.scan(hosts=target, ports=ports, arguments=args)
            except nmap.PortScannerError as exc:
                raise RuntimeError(f"Nmap scan failed: {exc}") from exc
            except Exception as exc:
                raise RuntimeError(f"Unexpected error during scan: {exc}") from exc
            finally:
                progress.update(task_id, completed=100, total=100)

        scan_end = utc_now_iso()
        results = []

        for host in self.nm.all_hosts():
            result = self._parse_host(host)
            result.scan_start = scan_start
            result.scan_end = scan_end
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_target(self, target: str) -> None:
        """Raise ValueError if target is not a valid IP, CIDR, or hostname."""
        # CIDR range
        try:
            ipaddress.ip_network(target, strict=False)
            return
        except ValueError:
            pass
        # Hostname / bare IP
        try:
            socket.getaddrinfo(target, None)
            return
        except socket.gaierror:
            pass
        raise ValueError(
            f"Invalid target: '{target}'. "
            "Provide an IP address, hostname, or CIDR range (e.g., 192.168.1.0/24)."
        )

    def _build_args(
        self,
        os_detection: bool,
        service_detection: bool,
        scripts: Optional[str],
    ) -> str:
        """Compose the nmap argument string."""
        parts = [f"-T{self.timing}"]

        # Scan type
        parts.append("-sS" if self.stealth else "-sT")

        if service_detection:
            parts.append("-sV --version-intensity 7")

        if os_detection:
            parts.append("-O --osscan-guess")

        if scripts:
            parts.append(f"--script={scripts}")

        parts.append(f"--host-timeout {self.timeout}s")
        parts.append("--open")  # Only show open ports

        return " ".join(parts)

    def _parse_host(self, host: str) -> ScanResult:
        """Build a ScanResult from raw nmap data for one host."""
        host_data = self.nm[host]

        # Hostname
        hostnames = host_data.get("hostnames", [])
        hostname = next(
            (h.get("name", "") for h in hostnames if h.get("name")),
            "",
        )

        # OS detection
        os_match, os_accuracy = "Unknown", 0
        for entry in host_data.get("osmatch", []):
            name = entry.get("name", "")
            accuracy = int(entry.get("accuracy", 0))
            if accuracy > os_accuracy:
                os_match, os_accuracy = name, accuracy

        result = ScanResult(
            host=host,
            hostname=hostname,
            state=host_data.state(),
            os_match=os_match,
            os_accuracy=os_accuracy,
        )

        # Ports
        for proto in host_data.all_protocols():
            port_dict = host_data[proto]
            for port in sorted(port_dict.keys()):
                pd = port_dict[port]
                if pd.get("state") != "open":
                    continue

                # Extract CPE entries
                cpe_raw = pd.get("cpe", "")
                cpe_list = [c.strip() for c in cpe_raw.split("\n") if c.strip()]

                # NSE script output
                script_output = pd.get("script", {})

                port_info = PortInfo(
                    port=int(port),
                    protocol=proto,
                    state=pd.get("state", "open"),
                    service=pd.get("name", ""),
                    product=pd.get("product", ""),
                    version=pd.get("version", ""),
                    extra_info=pd.get("extrainfo", ""),
                    script_output=dict(script_output),
                    cpe=cpe_list,
                )
                result.ports.append(port_info)

        return result

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def display_results(self, results: list[ScanResult]) -> None:
        """Render scan results to the terminal using Rich tables."""
        if not results:
            console.print("\n[yellow]⚠  No live hosts found.[/yellow]\n")
            return

        console.print(
            f"\n[bold green]✔  Scan complete — {len(results)} host(s) found[/bold green]\n"
        )

        for result in results:
            self._display_host(result)

    def _display_host(self, result: ScanResult) -> None:
        """Render a single host block."""
        state_style = "green" if result.state == "up" else "red"
        console.rule(
            f"[bold]{result.display_name}[/bold]  "
            f"[{state_style}]{result.state.upper()}[/{state_style}]",
            style="cyan",
        )

        if result.os_match != "Unknown":
            console.print(
                f"  [bold]OS :[/bold] {result.os_match} "
                f"[dim]({result.os_accuracy}% confidence)[/dim]"
            )

        if not result.ports:
            console.print("  [dim]No open ports found.[/dim]\n")
            return

        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="dim cyan",
            row_styles=["", "dim"],
            expand=False,
        )
        table.add_column("Port", style="port", width=7, justify="right")
        table.add_column("Proto", width=6)
        table.add_column("State", width=8)
        table.add_column("Service", width=14)
        table.add_column("Version / Product", style="version", min_width=30)
        table.add_column("CPE", style="dim", min_width=20, overflow="fold")

        for p in result.ports:
            cpe_str = p.cpe[0] if p.cpe else ""
            table.add_row(
                str(p.port),
                p.protocol.upper(),
                f"[green]{p.state}[/green]",
                p.service or "[dim]unknown[/dim]",
                p.version_string or "[dim]—[/dim]",
                cpe_str or "[dim]—[/dim]",
            )

        console.print(table)
        console.print()
