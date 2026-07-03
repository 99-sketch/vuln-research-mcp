"""Tests for PentestReportGenerator — Professional Report Generation."""

import pytest
from src.reporting.pentest_report import (
    PentestReportGenerator, ReportConfig, MARKDOWN_TEMPLATE,
    SEVERITY_ORDER, SEVERITY_EMOJI,
)
from src.db.models import Finding


@pytest.fixture
def gen():
    return PentestReportGenerator()


@pytest.fixture
def sample_findings():
    return [
        Finding(project_id=1, asset_id=1, title="SQL Injection",
                description="Blind SQLi in login", severity="critical",
                cvss_score=9.8, cve_ids="CVE-2021-44228",
                cwe_ids="CWE-89", risk_score=19.5,
                remediation="Use parameterized queries"),
        Finding(project_id=1, asset_id=1, title="XSS in search",
                description="Reflected XSS", severity="high",
                cvss_score=7.5, cve_ids="CVE-2022-12345",
                cwe_ids="CWE-79", risk_score=8.0,
                remediation="Sanitize input"),
        Finding(project_id=1, asset_id=1, title="Info disclosure",
                description="Server version exposed", severity="medium",
                cvss_score=4.0, risk_score=4.0,
                remediation="Suppress version headers"),
        Finding(project_id=1, asset_id=1, title="Cookie no HttpOnly",
                description="Missing HttpOnly flag", severity="low",
                cvss_score=2.0, risk_score=2.0,
                remediation="Set HttpOnly flag"),
    ]


class TestMarkdownGeneration:
    def test_generate_markdown_basic(self, gen, sample_findings):
        config = ReportConfig(project_name="Test Project", version="1.0")
        md = gen.generate_markdown(sample_findings, config)

        assert "Penetration Test Report" in md
        assert "Test Project" in md
        assert "Confidential" in md

    def test_generate_markdown_has_all_sections(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        required_sections = [
            "Executive Summary",
            "Risk Overview",
            "Key Findings Summary",
            "Methodology",
            "Findings Details",
            "Remediation Roadmap",
            "Appendices",
            "CVE Cross-Reference",
            "ATT&CK Technique Mapping",
        ]
        for section in required_sections:
            assert section in md, f"Missing section: {section}"

    def test_generate_markdown_severity_counts(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        assert "| Critical | 1" in md
        assert "| High     | 1" in md
        assert "| Medium   | 1" in md
        assert "| Low      | 1" in md

    def test_generate_markdown_empty_findings(self, gen):
        md = gen.generate_markdown([])
        assert "Penetration Test Report" in md
        assert "| Critical | 0" in md
        assert "No findings were identified" in md

    def test_generate_markdown_default_config(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        assert "vuln-research-mcp v4.0" in md

    def test_generate_markdown_cve_reference(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        assert "CVE-2021-44228" in md
        assert "CVE-2022-12345" in md

    def test_generate_markdown_risk_visualization(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        assert "critical" in md.lower()  # risk viz bar

    def test_generate_markdown_remediation_roadmap(self, gen, sample_findings):
        md = gen.generate_markdown(sample_findings)
        assert "Immediate (0-7 days)" in md
        assert "Short-term (7-30 days)" in md
        assert "Long-term (30-90 days)" in md

    def test_generate_markdown_with_timeline(self, gen, sample_findings):
        config = ReportConfig(
            project_name="Timeline Test",
            timeline_events=["2024-01-01: Scan started", "2024-01-02: Scan completed"],
        )
        md = gen.generate_markdown(sample_findings, config)
        assert "2024-01-01: Scan started" in md
        assert "2024-01-02: Scan completed" in md

    def test_generate_markdown_with_tools(self, gen, sample_findings):
        config = ReportConfig(
            project_name="Tools Test",
            tools_used=["Nmap 7.94", "Nuclei 3.0", "Burp Suite Pro"],
        )
        md = gen.generate_markdown(sample_findings, config)
        assert "Nmap 7.94" in md
        assert "Nuclei 3.0" in md


class TestJSONGeneration:
    def test_generate_json_basic(self, gen, sample_findings):
        config = ReportConfig(project_name="JSON Test")
        data = gen.generate_json(sample_findings, config)

        assert data["meta"]["project"] == "JSON Test"
        assert data["meta"]["generator"] == "vuln-research-mcp v4.0"
        assert data["summary"]["total_findings"] == 4
        assert data["summary"]["severity_counts"]["critical"] == 1
        assert data["summary"]["severity_counts"]["high"] == 1
        assert len(data["findings"]) == 4

    def test_generate_json_remediation(self, gen, sample_findings):
        data = gen.generate_json(sample_findings)
        assert "critical" in data["remediation"]
        assert "high" in data["remediation"]
        assert "medium" in data["remediation"]

    def test_generate_json_cve_index(self, gen, sample_findings):
        data = gen.generate_json(sample_findings)
        cves = [item["cve"] for item in data.get("cve_index", [])]
        assert "CVE-2021-44228" in cves
        assert "CVE-2022-12345" in cves

    def test_generate_json_risk_profile(self, gen, sample_findings):
        # Add a KEV finding
        findings = sample_findings + [
            Finding(project_id=1, title="KEV Vuln", severity="critical",
                    cvss_score=9.8, is_kev=True, risk_score=20.0)
        ]
        data = gen.generate_json(findings)
        assert data["summary"]["risk_profile"]["kev_present"] is True
        assert data["summary"]["risk_profile"]["risk_level"] == "critical"


class TestExecutiveSummary:
    def test_generate_executive_summary(self, gen, sample_findings):
        stats = {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0}
        summary = gen.generate_executive_summary(stats, sample_findings)
        assert "CRITICAL" in summary
        assert "4 findings" in summary

    def test_generate_executive_summary_low_risk(self, gen):
        stats = {"critical": 0, "high": 0, "medium": 1, "low": 2, "info": 0}
        summary = gen.generate_executive_summary(stats)
        assert "LOW" in summary


class TestToReportModel:
    def test_to_report_model(self, gen, sample_findings):
        config = ReportConfig(project_name="Model Test", version="2.0")
        md = gen.generate_markdown(sample_findings, config)
        report = gen.to_report_model(1, md, "markdown", sample_findings, config)

        assert report.project_id == 1
        assert report.format == "markdown"
        assert report.content == md
        assert "Model Test" in report.title
        assert report.finding_count == 4
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1
