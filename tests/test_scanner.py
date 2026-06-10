"""
Unit tests for cvemap.scanner

These tests mock nmap so they can run without nmap installed
and without root privileges.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from cvemap.scanner import NetworkScanner, ScanResult, PortInfo


# ---------------------------------------------------------------------------
# NetworkScanner.__init__
# ---------------------------------------------------------------------------

class TestNetworkScannerInit:
    def test_valid_timing(self):
        with patch("nmap.PortScanner"):
            scanner = NetworkScanner(timing=3)
            assert scanner.timing == 3

    def test_invalid_timing_raises(self):
        with pytest.raises(ValueError, match="timing must be between 0 and 5"):
            NetworkScanner(timing=6)

    def test_nmap_not_found_raises(self):
        import nmap
        with patch("nmap.PortScanner", side_effect=nmap.PortScannerError("nmap not found")):
            with pytest.raises(RuntimeError, match="nmap binary not found"):
                NetworkScanner()


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

class TestValidateTarget:
    @pytest.fixture
    def scanner(self):
        with patch("nmap.PortScanner"):
            return NetworkScanner()

    def test_valid_ip(self, scanner):
        # Should not raise
        scanner._validate_target("192.168.1.1")

    def test_valid_cidr(self, scanner):
        scanner._validate_target("10.0.0.0/24")

    def test_valid_hostname(self, scanner):
        # Patch DNS resolution
        with patch("socket.getaddrinfo", return_value=[("AF_INET", None, None, None, ("1.2.3.4", 0))]):
            scanner._validate_target("example.com")

    def test_invalid_target_raises(self, scanner):
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS fail")):
            with pytest.raises(ValueError, match="Invalid target"):
                scanner._validate_target("not_a_valid_target!!")


# ---------------------------------------------------------------------------
# Argument builder
# ---------------------------------------------------------------------------

class TestBuildArgs:
    @pytest.fixture
    def scanner(self):
        with patch("nmap.PortScanner"):
            return NetworkScanner(timing=3)

    def test_default_args_contain_timing(self, scanner):
        args = scanner._build_args(os_detection=False, service_detection=False, scripts=None)
        assert "-T3" in args
        assert "-sT" in args

    def test_stealth_uses_ss(self):
        with patch("nmap.PortScanner"):
            scanner = NetworkScanner(stealth=True)
        args = scanner._build_args(os_detection=False, service_detection=False, scripts=None)
        assert "-sS" in args
        assert "-sT" not in args

    def test_service_detection_flag(self, scanner):
        args = scanner._build_args(os_detection=False, service_detection=True, scripts=None)
        assert "-sV" in args

    def test_os_detection_flag(self, scanner):
        args = scanner._build_args(os_detection=True, service_detection=False, scripts=None)
        assert "-O" in args

    def test_scripts_appended(self, scanner):
        args = scanner._build_args(os_detection=False, service_detection=False, scripts="vuln,auth")
        assert "--script=vuln,auth" in args

    def test_no_scripts(self, scanner):
        args = scanner._build_args(os_detection=False, service_detection=False, scripts=None)
        assert "--script" not in args


# ---------------------------------------------------------------------------
# _parse_host
# ---------------------------------------------------------------------------

class TestParseHost:
    @pytest.fixture
    def scanner(self):
        with patch("nmap.PortScanner"):
            s = NetworkScanner()
        return s

    def _make_nm_mock(self, host_ip: str):
        """Return a mock nmap.PortScanner that mimics one open SSH port."""
        nm = MagicMock()
        host_data = MagicMock()
        host_data.state.return_value = "up"
        host_data.get.side_effect = lambda key, default=None: {
            "hostnames": [{"name": "test.local", "type": "PTR"}],
            "osmatch": [{"name": "Linux 2.6.32", "accuracy": "96"}],
        }.get(key, default)
        host_data.all_protocols.return_value = ["tcp"]
        host_data.__getitem__ = lambda self_inner, proto: {
            "tcp": {
                22: {
                    "state": "open",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.4",
                    "extrainfo": "protocol 2.0",
                    "cpe": "cpe:/a:openbsd:openssh:7.4",
                    "script": {},
                }
            }
        }[proto]

        nm.__getitem__ = lambda self_inner, h: host_data
        return nm

    def test_parse_host_extracts_ssh_port(self, scanner):
        scanner.nm = self._make_nm_mock("192.168.1.1")
        result = scanner._parse_host("192.168.1.1")

        assert result.host == "192.168.1.1"
        assert result.hostname == "test.local"
        assert result.state == "up"
        assert result.os_match == "Linux 2.6.32"
        assert result.os_accuracy == 96
        assert len(result.ports) == 1

        port = result.ports[0]
        assert port.port == 22
        assert port.protocol == "tcp"
        assert port.service == "ssh"
        assert port.product == "OpenSSH"
        assert port.version == "7.4"

    def test_parse_host_cpe_extraction(self, scanner):
        scanner.nm = self._make_nm_mock("192.168.1.1")
        result = scanner._parse_host("192.168.1.1")
        port = result.ports[0]
        assert "cpe:/a:openbsd:openssh:7.4" in port.cpe


# ---------------------------------------------------------------------------
# ScanResult properties
# ---------------------------------------------------------------------------

class TestScanResultProperties:
    def test_open_port_count(self, scan_result):
        assert scan_result.open_port_count == 2

    def test_cve_count(self, scan_result):
        assert scan_result.cve_count == 2

    def test_critical_cves(self, scan_result):
        crits = scan_result.critical_cves
        assert len(crits) == 1
        assert crits[0].cve_id == "CVE-2021-41773"

    def test_display_name_with_hostname(self, scan_result):
        assert "metasploitable.local" in scan_result.display_name

    def test_display_name_without_hostname(self, empty_scan_result):
        assert empty_scan_result.display_name == "10.0.0.1"

    def test_to_dict_structure(self, scan_result):
        d = scan_result.to_dict()
        assert "host" in d
        assert "ports" in d
        assert "cve_count" in d
        assert d["host"] == "192.168.1.5"


# ---------------------------------------------------------------------------
# PortInfo properties
# ---------------------------------------------------------------------------

class TestPortInfoProperties:
    def test_version_string_with_product_and_version(self, port_http):
        assert "Apache httpd" in port_http.version_string
        assert "2.4.49" in port_http.version_string

    def test_version_string_empty_when_no_product(self, port_unknown):
        assert port_unknown.version_string == ""

    def test_search_query_product_version(self, port_ssh):
        assert "OpenSSH" in port_ssh.search_query
        assert "7.4" in port_ssh.search_query

    def test_search_query_falls_back_to_service(self):
        p = PortInfo(
            port=80, protocol="tcp", state="open",
            service="http", product="", version="", extra_info="",
        )
        assert p.search_query == "http"

    def test_search_query_empty_when_nothing(self, port_unknown):
        assert port_unknown.search_query == ""

    def test_to_dict(self, port_ssh):
        d = port_ssh.to_dict()
        assert d["port"] == 22
        assert d["service"] == "ssh"
        assert d["cves"] == []
