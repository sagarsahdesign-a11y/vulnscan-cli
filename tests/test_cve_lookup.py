"""
Unit tests for cvemap.cve_lookup

All NVD API calls are mocked — no network access required.
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

import requests

from cvemap.cve_lookup import CVELookup, CVEResult
from cvemap.utils import cvss_to_severity


# ---------------------------------------------------------------------------
# Helpers: fake NVD API responses
# ---------------------------------------------------------------------------

def _make_nvd_response(cve_id: str, score: float, version: str = "3.1") -> dict:
    """Return a minimal NVD API v2.0 response dict for one CVE."""
    metric_key = f"cvssMetricV{version.replace('.', '')}"
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {"lang": "en", "value": f"Test description for {cve_id}."}
                    ],
                    "metrics": {
                        metric_key: [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": version,
                                    "baseScore": score,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "published": "2023-01-15T00:00:00.000",
                    "lastModified": "2023-06-01T00:00:00.000",
                    "references": [
                        {"url": "https://example.com/advisory"}
                    ],
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-79"}]}
                    ],
                }
            }
        ],
        "totalResults": 1,
    }


def _make_empty_response() -> dict:
    return {"vulnerabilities": [], "totalResults": 0}


# ---------------------------------------------------------------------------
# CVSSseverity helper
# ---------------------------------------------------------------------------

class TestCvssToSeverity:
    @pytest.mark.parametrize("score,expected", [
        (9.8, "CRITICAL"),
        (9.0, "CRITICAL"),
        (8.9, "HIGH"),
        (7.0, "HIGH"),
        (6.9, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.9, "LOW"),
        (0.1, "LOW"),
        (0.0, "NONE"),
    ])
    def test_score_to_severity(self, score, expected):
        assert cvss_to_severity(score) == expected


# ---------------------------------------------------------------------------
# CVELookup.search — happy path
# ---------------------------------------------------------------------------

class TestCVELookupSearch:
    @pytest.fixture
    def lookup(self):
        return CVELookup(api_key="", max_results=10)

    def _mock_get(self, response_body: dict, status_code: int = 200):
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.json.return_value = response_body
        mock_resp.raise_for_status.return_value = None
        return mock_resp

    # ── keyword search returns CVE ──────────────────────────────────────────
    def test_search_returns_cve_result(self, lookup):
        body = _make_nvd_response("CVE-2021-41773", 9.8)
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)):
            results = lookup.search("Apache httpd", "2.4.49")

        assert len(results) == 1
        cve = results[0]
        assert cve.cve_id == "CVE-2021-41773"
        assert cve.cvss_score == 9.8
        assert cve.severity == "CRITICAL"

    # ── empty response ──────────────────────────────────────────────────────
    def test_search_empty_response(self, lookup):
        body = _make_empty_response()
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)):
            results = lookup.search("SomeProduct", "1.0")
        assert results == []

    # ── CPE path is preferred when available ───────────────────────────────
    def test_cpe_query_used_when_provided(self, lookup):
        body = _make_nvd_response("CVE-2023-0001", 7.5)
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)) as mock_get:
            lookup.search(product="", cpe="cpe:/a:openbsd:openssh:7.4")
            call_kwargs = mock_get.call_args
            params = call_kwargs[1].get("params", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {})
            assert "cpeName" in params

    # ── cache prevents second API call ─────────────────────────────────────
    def test_results_are_cached(self, lookup):
        body = _make_nvd_response("CVE-2023-0001", 5.0)
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)) as mock_get:
            lookup.search("nginx", "1.18")
            lookup.search("nginx", "1.18")   # second call — should hit cache
            assert mock_get.call_count == 1

    # ── empty product returns immediately ──────────────────────────────────
    def test_empty_product_and_cpe_returns_empty(self, lookup):
        with patch.object(lookup._session, "get") as mock_get:
            results = lookup.search("", "")
        mock_get.assert_not_called()
        assert results == []

    # ── sorted by CVSS descending ──────────────────────────────────────────
    def test_results_sorted_by_score_desc(self, lookup):
        body = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-LOW",
                        "descriptions": [{"lang": "en", "value": "Low CVE"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "type": "Primary",
                                "cvssData": {"version": "3.1", "baseScore": 3.1, "vectorString": ""},
                            }]
                        },
                        "published": "2023-01-01T00:00:00.000",
                        "lastModified": "2023-01-01T00:00:00.000",
                        "references": [],
                        "weaknesses": [],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2023-CRIT",
                        "descriptions": [{"lang": "en", "value": "Critical CVE"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "type": "Primary",
                                "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": ""},
                            }]
                        },
                        "published": "2023-06-01T00:00:00.000",
                        "lastModified": "2023-06-01T00:00:00.000",
                        "references": [],
                        "weaknesses": [],
                    }
                },
            ]
        }
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)):
            results = lookup.search("openssl", "1.0.1")
        assert results[0].cve_id == "CVE-2023-CRIT"
        assert results[1].cve_id == "CVE-2023-LOW"

    # ── CVSS v2 fallback ───────────────────────────────────────────────────
    def test_cvss_v2_fallback(self, lookup):
        body = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2010-0001",
                        "descriptions": [{"lang": "en", "value": "Old CVE"}],
                        "metrics": {
                            "cvssMetricV2": [{
                                "type": "Primary",
                                "cvssData": {"version": "2.0", "baseScore": 6.8, "vectorString": "AV:N/AC:M/Au:N/C:P/I:P/A:P"},
                            }]
                        },
                        "published": "2010-01-01T00:00:00.000",
                        "lastModified": "2010-01-01T00:00:00.000",
                        "references": [],
                        "weaknesses": [],
                    }
                }
            ]
        }
        with patch.object(lookup._session, "get", return_value=self._mock_get(body)):
            results = lookup.search("oldsoft", "1.0")
        assert len(results) == 1
        assert results[0].cvss_version == "2.0"
        assert results[0].cvss_score == 6.8


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestCVELookupErrors:
    @pytest.fixture
    def lookup(self):
        return CVELookup()

    def test_timeout_returns_empty(self, lookup):
        with patch.object(lookup._session, "get", side_effect=requests.exceptions.Timeout):
            results = lookup.search("product", "1.0")
        assert results == []

    def test_connection_error_returns_empty(self, lookup):
        with patch.object(lookup._session, "get", side_effect=requests.exceptions.ConnectionError):
            results = lookup.search("product", "1.0")
        assert results == []

    def test_http_429_rate_limit_handled(self, lookup):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        http_error = requests.exceptions.HTTPError(response=mock_resp)
        with patch.object(lookup._session, "get", side_effect=http_error):
            # Patch time.sleep inside the cve_lookup module's namespace
            with patch("cvemap.cve_lookup.time.sleep") as mock_sleep:
                results = lookup.search("product", "1.0")
        assert results == []
        # sleep is called at least once (RateLimiter + 429 handler both sleep)
        assert mock_sleep.called

    def test_generic_exception_returns_empty(self, lookup):
        with patch.object(lookup._session, "get", side_effect=Exception("unexpected")):
            results = lookup.search("product", "1.0")
        assert results == []


# ---------------------------------------------------------------------------
# CVEResult model
# ---------------------------------------------------------------------------

class TestCVEResult:
    def test_nvd_url(self, cve_critical):
        assert "CVE-2021-41773" in cve_critical.nvd_url
        assert "nvd.nist.gov" in cve_critical.nvd_url

    def test_to_dict_keys(self, cve_critical):
        d = cve_critical.to_dict()
        for key in ("cve_id", "description", "cvss_score", "cvss_vector",
                    "cvss_version", "severity", "published", "nvd_url"):
            assert key in d

    def test_severity_label_critical(self, cve_critical):
        assert cve_critical.severity == "CRITICAL"

    def test_severity_label_medium(self, cve_medium):
        assert cve_medium.severity == "MEDIUM"
