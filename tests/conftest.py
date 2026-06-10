"""
Shared pytest fixtures for cvemap test suite.
"""

import pytest
from cvemap.scanner import ScanResult, PortInfo
from cvemap.cve_lookup import CVEResult


# ---------------------------------------------------------------------------
# Fixture: a minimal PortInfo with no CVEs
# ---------------------------------------------------------------------------
@pytest.fixture
def port_ssh() -> PortInfo:
    return PortInfo(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product="OpenSSH",
        version="7.4",
        extra_info="protocol 2.0",
        cpe=["cpe:/a:openbsd:openssh:7.4"],
    )


@pytest.fixture
def port_http() -> PortInfo:
    return PortInfo(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        product="Apache httpd",
        version="2.4.49",
        extra_info="",
        cpe=["cpe:/a:apache:http_server:2.4.49"],
    )


@pytest.fixture
def port_unknown() -> PortInfo:
    """Port with no product info — should gracefully skip CVE lookup."""
    return PortInfo(
        port=12345,
        protocol="tcp",
        state="open",
        service="",
        product="",
        version="",
        extra_info="",
        cpe=[],
    )


# ---------------------------------------------------------------------------
# Fixture: CVEResult samples
# ---------------------------------------------------------------------------
@pytest.fixture
def cve_critical() -> CVEResult:
    return CVEResult(
        cve_id="CVE-2021-41773",
        description=(
            "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. "
            "An attacker could use a path traversal attack to map URLs to files outside the "
            "directories configured by Alias-like directives."
        ),
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_version="3.1",
        severity="CRITICAL",
        published="2021-10-05",
        last_modified="2022-10-07",
        references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
        cwe=["CWE-22"],
    )


@pytest.fixture
def cve_medium() -> CVEResult:
    return CVEResult(
        cve_id="CVE-2016-20012",
        description="OpenSSH through 8.7 allows remote attackers to enumerate valid usernames.",
        cvss_score=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_version="3.1",
        severity="MEDIUM",
        published="2021-09-15",
        last_modified="2021-12-03",
        references=["https://www.openssh.com/txt/release-8.7"],
        cwe=["CWE-203"],
    )


# ---------------------------------------------------------------------------
# Fixture: full ScanResult
# ---------------------------------------------------------------------------
@pytest.fixture
def scan_result(port_ssh, port_http, cve_critical, cve_medium) -> ScanResult:
    port_ssh.cves = [cve_medium]
    port_http.cves = [cve_critical]
    return ScanResult(
        host="192.168.1.5",
        hostname="metasploitable.local",
        state="up",
        os_match="Linux 2.6.X",
        os_accuracy=95,
        ports=[port_ssh, port_http],
        scan_start="2024-01-01T00:00:00Z",
        scan_end="2024-01-01T00:02:00Z",
    )


@pytest.fixture
def empty_scan_result() -> ScanResult:
    return ScanResult(host="10.0.0.1", state="up")
