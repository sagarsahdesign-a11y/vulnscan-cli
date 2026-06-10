"""
Unit tests for cvemap.reporter

Tests JSON/HTML generation and the report data builder without
requiring nmap or network access.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path

from cvemap.reporter import Reporter, build_report_data, _calculate_risk_score


# ---------------------------------------------------------------------------
# _calculate_risk_score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_all_critical_is_max(self):
        score = _calculate_risk_score({"CRITICAL": 10, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0})
        assert score == 10.0

    def test_zero_cves_is_zero(self):
        score = _calculate_risk_score({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0})
        assert score == 0.0

    def test_mixed_severity(self):
        score = _calculate_risk_score({"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "NONE": 0})
        assert 0 < score <= 10

    def test_score_does_not_exceed_ten(self):
        score = _calculate_risk_score({"CRITICAL": 999, "HIGH": 999, "MEDIUM": 0, "LOW": 0, "NONE": 0})
        assert score <= 10.0


# ---------------------------------------------------------------------------
# build_report_data
# ---------------------------------------------------------------------------

class TestBuildReportData:
    def test_meta_fields_populated(self, scan_result):
        data = build_report_data(
            scan_results=[scan_result],
            target="192.168.1.0/24",
            ports="1-1000",
            args_used="cvemap scan -t 192.168.1.0/24",
            tool_version="1.0.0",
        )
        assert data["meta"]["target"] == "192.168.1.0/24"
        assert data["meta"]["version"] == "1.0.0"
        assert "generated_at" in data["meta"]

    def test_summary_counts(self, scan_result):
        data = build_report_data([scan_result], "host", "1-1000")
        assert data["summary"]["total_hosts"] == 1
        assert data["summary"]["total_open_ports"] == 2
        assert data["summary"]["total_cves"] == 2

    def test_severity_counts_critical(self, scan_result):
        data = build_report_data([scan_result], "host", "1-1000")
        counts = data["summary"]["severity_counts"]
        assert counts["CRITICAL"] == 1

    def test_empty_scan_results(self):
        data = build_report_data([], "192.168.1.1", "1-1000")
        assert data["summary"]["total_hosts"] == 0
        assert data["summary"]["total_cves"] == 0
        assert data["summary"]["risk_score"] == 0.0

    def test_hosts_list_in_output(self, scan_result):
        data = build_report_data([scan_result], "host", "1-1000")
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["host"] == "192.168.1.5"


# ---------------------------------------------------------------------------
# Reporter.save_json
# ---------------------------------------------------------------------------

class TestReporterJSON:
    def test_json_file_created(self, tmp_path, scan_result):
        reporter = Reporter(output_dir=str(tmp_path))
        data = build_report_data([scan_result], "192.168.1.5", "1-1000")
        out = reporter.save_json(data, stem="test_report")

        assert out.exists()
        assert out.suffix == ".json"

    def test_json_content_valid(self, tmp_path, scan_result):
        reporter = Reporter(output_dir=str(tmp_path))
        data = build_report_data([scan_result], "192.168.1.5", "1-1000")
        out = reporter.save_json(data, stem="test_report")

        with out.open() as f:
            loaded = json.load(f)

        assert loaded["meta"]["target"] == "192.168.1.5"
        assert "hosts" in loaded

    def test_json_pretty_printed(self, tmp_path, scan_result):
        reporter = Reporter(output_dir=str(tmp_path))
        data = build_report_data([scan_result], "host", "1-1000")
        out = reporter.save_json(data, "pretty_test")
        content = out.read_text()
        # Pretty-printed JSON has newlines
        assert "\n" in content

    def test_output_dir_created_if_missing(self, tmp_path):
        new_dir = tmp_path / "nested" / "reports"
        reporter = Reporter(output_dir=str(new_dir))
        assert new_dir.exists()

    def test_stem_used_as_filename(self, tmp_path, scan_result):
        reporter = Reporter(output_dir=str(tmp_path))
        data = build_report_data([scan_result], "host", "1-1000")
        out = reporter.save_json(data, "my_custom_stem")
        assert "my_custom_stem" in out.name


# ---------------------------------------------------------------------------
# Reporter.save_html
# ---------------------------------------------------------------------------

class TestReporterHTML:
    @pytest.fixture
    def template_dir(self):
        """Return the real templates/ directory relative to the project root."""
        return Path(__file__).parent.parent / "templates"

    def test_html_file_created(self, tmp_path, scan_result, template_dir):
        if not template_dir.exists():
            pytest.skip("templates/ dir not found — skipping HTML test")
        reporter = Reporter(output_dir=str(tmp_path), template_dir=str(template_dir))
        data = build_report_data([scan_result], "192.168.1.5", "1-1000")
        out = reporter.save_html(data, stem="test_html")

        assert out.exists()
        assert out.suffix == ".html"

    def test_html_contains_target(self, tmp_path, scan_result, template_dir):
        if not template_dir.exists():
            pytest.skip("templates/ dir not found")
        reporter = Reporter(output_dir=str(tmp_path), template_dir=str(template_dir))
        data = build_report_data([scan_result], "192.168.1.5", "1-1000")
        reporter.save_html(data, stem="html_test")
        content = (tmp_path / "html_test.html").read_text(encoding="utf-8")
        assert "192.168.1.5" in content

    def test_html_contains_cve_id(self, tmp_path, scan_result, template_dir):
        if not template_dir.exists():
            pytest.skip("templates/ dir not found")
        reporter = Reporter(output_dir=str(tmp_path), template_dir=str(template_dir))
        data = build_report_data([scan_result], "192.168.1.5", "1-1000")
        reporter.save_html(data, stem="html_cve_test")
        content = (tmp_path / "html_cve_test.html").read_text(encoding="utf-8")
        assert "CVE-2021-41773" in content

    def test_missing_template_raises(self, tmp_path, scan_result):
        reporter = Reporter(output_dir=str(tmp_path), template_dir=str(tmp_path / "no_templates"))
        data = build_report_data([scan_result], "host", "1-1000")
        with pytest.raises(FileNotFoundError):
            reporter.save_html(data, "stem")
