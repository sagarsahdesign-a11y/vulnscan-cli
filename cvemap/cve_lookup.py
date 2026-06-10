"""
CVE lookup module — queries the NIST National Vulnerability Database (NVD) API v2.0.

Features:
  - NVD API v2.0 with automatic rate limiting
  - In-process LRU cache to avoid duplicate requests within a session
  - CVSS v3.1 / v3.0 / v2.0 score extraction with severity labelling
  - CPE-based precise lookup + keyword fallback
  - Graceful degradation on network failure
"""

from __future__ import annotations

import time
import logging
import functools
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .utils import (
    RateLimiter,
    console,
    cvss_to_severity,
    severity_badge,
    get_logger,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# NVD API constants
# ---------------------------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_USER_AGENT = "cvemap/1.0.0 (github.com/sagarsahdesign-a11y/vulnscan-cli)"

# Without API key: 5 req / 30s  → we use 4 / 30s to be safe
# With API key:   50 req / 30s  → we use 40 / 30s to be safe
_RATE_NO_KEY = RateLimiter(calls=4, period=30.0)
_RATE_WITH_KEY = RateLimiter(calls=40, period=30.0)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    """Structured representation of a single CVE entry from NVD."""

    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    cvss_version: str
    severity: str
    published: str
    last_modified: str
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cvss_version": self.cvss_version,
            "severity": self.severity,
            "published": self.published,
            "last_modified": self.last_modified,
            "nvd_url": self.nvd_url,
            "references": self.references,
            "cwe": self.cwe,
        }


# ---------------------------------------------------------------------------
# Lookup engine
# ---------------------------------------------------------------------------

class CVELookup:
    """
    Queries the NIST NVD API v2.0 for CVEs matching a software product/version.

    Usage::

        lookup = CVELookup(api_key="your_key")
        cves = lookup.search("Apache httpd", "2.4.49", max_results=10)
    """

    def __init__(
        self,
        api_key: str = "",
        max_results: int = 10,
        request_timeout: int = 30,
    ):
        self.api_key = api_key.strip()
        self.max_results = max_results
        self.request_timeout = request_timeout
        self._rate = _RATE_WITH_KEY if self.api_key else _RATE_NO_KEY

        # Build a session with retry logic
        self._session = self._build_session()

        # Simple in-process cache: (query_key) → list[CVEResult]
        self._cache: dict[str, list[CVEResult]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search(
        self,
        product: str,
        version: str = "",
        cpe: str = "",
        max_results: Optional[int] = None,
    ) -> list[CVEResult]:
        """
        Look up CVEs for a given product and optional version.

        Strategy:
          1. If a CPE string is provided, use it for a precise query.
          2. Otherwise fall back to keyword search.

        Args:
            product:    Product name (e.g., "OpenSSH", "Apache httpd").
            version:    Version string (e.g., "7.4", "2.4.49").
            cpe:        CPE 2.3 URI if available (more precise).
            max_results: Override instance-level max_results.

        Returns:
            Sorted list of :class:`CVEResult` by CVSS score (highest first).
        """
        if not product and not cpe:
            return []

        limit = max_results or self.max_results
        cache_key = f"{cpe or product}::{version}::{limit}"

        if cache_key in self._cache:
            logger.debug(f"Cache hit: {cache_key}")
            return self._cache[cache_key]

        results: list[CVEResult] = []

        try:
            if cpe:
                results = self._query_by_cpe(cpe, limit)

            if not results and product:
                query = f"{product} {version}".strip()
                results = self._query_by_keyword(query, limit)

        except requests.exceptions.Timeout:
            console.print(
                f"[warn]⚠  NVD API timeout for '{product} {version}'. "
                "Skipping CVE lookup.[/warn]"
            )
        except requests.exceptions.ConnectionError:
            console.print(
                "[warn]⚠  Cannot reach NVD API. Check your internet connection.[/warn]"
            )
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response else "?"
            if status == 403:
                console.print(
                    "[error]✖  NVD API returned 403 Forbidden. "
                    "Your API key may be invalid.[/error]"
                )
            elif status == 429:
                console.print(
                    "[warn]⚠  NVD API rate limit hit (429). Waiting 35s …[/warn]"
                )
                time.sleep(35)
            else:
                console.print(f"[warn]⚠  NVD API HTTP error {status} for '{product}'[/warn]")
        except Exception as exc:
            logger.warning(f"Unexpected CVE lookup error for '{product}': {exc}")

        self._cache[cache_key] = results
        return results

    def enrich_scan_results(self, scan_results: list, verbose: bool = False) -> None:
        """
        In-place enrichment: attach CVEs to each PortInfo in every ScanResult.

        Args:
            scan_results: List of :class:`~cvemap.scanner.ScanResult` objects.
            verbose:      Print per-port lookup status.
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn, MofNCompleteColumn

        # Collect all ports that have something to search for
        all_ports = [
            (result, port)
            for result in scan_results
            for port in result.ports
            if port.search_query
        ]

        if not all_ports:
            console.print("[dim]No services to enrich.[/dim]")
            return

        with Progress(
            SpinnerColumn(spinner_name="dots2", style="yellow"),
            TextColumn("[bold yellow]{task.description}"),
            MofNCompleteColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Looking up CVEs …",
                total=len(all_ports),
            )

            for result, port in all_ports:
                label = f"{result.host}:{port.port}/{port.service}"
                if verbose:
                    progress.update(task, description=f"CVE → {label}")

                cpe_str = port.cpe[0] if port.cpe else ""
                cves = self.search(
                    product=port.product or port.service,
                    version=port.version,
                    cpe=cpe_str,
                )
                port.cves = cves
                progress.advance(task)

        total_cves = sum(len(p.cves) for r in scan_results for p in r.ports)
        console.print(
            f"[bold green]✔  CVE enrichment complete — "
            f"{total_cves} CVE(s) found across "
            f"{len(all_ports)} service(s)[/bold green]\n"
        )

    # ------------------------------------------------------------------
    # Private NVD API helpers
    # ------------------------------------------------------------------

    def _query_by_cpe(self, cpe: str, limit: int) -> list[CVEResult]:
        """Query NVD using a CPE 2.3 string."""
        params = {"cpeName": cpe, "resultsPerPage": min(limit, 2000)}
        return self._fetch_and_parse(params, limit)

    def _query_by_keyword(self, keyword: str, limit: int) -> list[CVEResult]:
        """Query NVD using a free-text keyword search."""
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 2000)}
        return self._fetch_and_parse(params, limit)

    def _fetch_and_parse(self, params: dict, limit: int) -> list[CVEResult]:
        """Execute one NVD API request and parse the response."""
        self._rate.acquire()

        headers = {"User-Agent": NVD_USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key

        response = self._session.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=self.request_timeout,
        )
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        results = []
        for item in vulnerabilities[:limit]:
            cve = self._parse_cve_item(item.get("cve", {}))
            if cve:
                results.append(cve)

        # Sort by CVSS score descending
        results.sort(key=lambda c: c.cvss_score, reverse=True)
        return results

    def _parse_cve_item(self, cve_data: dict) -> Optional[CVEResult]:
        """Extract structured fields from a single CVE dict returned by NVD."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            next((d.get("value", "") for d in descriptions), "No description available."),
        )

        # CVSS metrics — try v3.1, then v3.0, then v2.0
        cvss_score = 0.0
        cvss_vector = ""
        cvss_version = "N/A"
        metrics = cve_data.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                primary = next(
                    (m for m in metric_list if m.get("type") == "Primary"),
                    metric_list[0],
                )
                cvss_data = primary.get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_version = cvss_data.get("version", "")
                break

        severity = cvss_to_severity(cvss_score)

        # Published / modified dates
        published = cve_data.get("published", "")
        last_modified = cve_data.get("lastModified", "")

        # References
        references = [
            r.get("url", "")
            for r in cve_data.get("references", [])
            if r.get("url")
        ]

        # CWE
        cwe_list = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val and val != "NVD-CWE-Other" and val not in cwe_list:
                    cwe_list.append(val)

        return CVEResult(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            severity=severity,
            published=published[:10] if published else "",
            last_modified=last_modified[:10] if last_modified else "",
            references=references[:5],  # cap to avoid huge output
            cwe=cwe_list,
        )

    # ------------------------------------------------------------------
    # Session factory
    # ------------------------------------------------------------------

    @staticmethod
    def _build_session() -> requests.Session:
        """Build a requests Session with exponential-backoff retry."""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2,            # waits 2, 4, 8 seconds
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session
