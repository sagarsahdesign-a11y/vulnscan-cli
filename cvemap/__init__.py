"""
cvemap — CVE-powered Network Vulnerability Scanner
===================================================
Author : sagarsahdesign-a11y
License: MIT
GitHub : https://github.com/sagarsahdesign-a11y/vulnscan-cli
"""

__version__ = "1.0.0"
__author__ = "sagarsahdesign-a11y"
__license__ = "MIT"
__description__ = "CVE-powered network vulnerability scanner using Nmap + NIST NVD API"
__url__ = "https://github.com/sagarsahdesign-a11y/vulnscan-cli"

from cvemap.scanner import NetworkScanner, ScanResult, PortInfo
from cvemap.cve_lookup import CVELookup, CVEResult
from cvemap.reporter import Reporter

__all__ = [
    "NetworkScanner",
    "ScanResult",
    "PortInfo",
    "CVELookup",
    "CVEResult",
    "Reporter",
    "__version__",
]
