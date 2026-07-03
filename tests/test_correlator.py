"""Tests for Correlator — Asset-Vulnerability Correlation Engine."""

import pytest
from src.correlator.engine import Correlator, CorrelationResult, BANNER_PATTERNS, KNOWN_VERSION_VULNS
from src.db.models import Asset


class TestBannerPatterns:
    def test_patterns_exist(self):
        assert len(BANNER_PATTERNS) >= 20

    def test_known_products(self):
        assert "apache" in BANNER_PATTERNS.values()
        assert "nginx" in BANNER_PATTERNS.values()
        assert "openssh" in BANNER_PATTERNS.values()
        assert "spring" in BANNER_PATTERNS.values()
        assert "tomcat" in BANNER_PATTERNS.values()


class TestKnownVulns:
    def test_known_vulns_exist(self):
        assert len(KNOWN_VERSION_VULNS) >= 15

    def test_apache_2_4_49_has_vulns(self):
        assert "apache:2.4.49" in KNOWN_VERSION_VULNS
        v = KNOWN_VERSION_VULNS["apache:2.4.49"][0]
        assert v["cve"] == "CVE-2021-41773"
        assert v["kev"] == True

    def test_spring5shell_present(self):
        assert "spring:5.2" in KNOWN_VERSION_VULNS
        v = KNOWN_VERSION_VULNS["spring:5.2"][0]
        assert v["cve"] == "CVE-2022-22965"


class TestCorrelateByBanner:
    @pytest.mark.asyncio
    async def test_correlate_apache_vulnerable_version(self):
        c = Correlator()
        asset = Asset(project_id=1, value="192.168.1.1",
                      banner="Apache/2.4.49 (Unix)", service="http", port=80)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) >= 1
        cve_ids = [v.get("cve") for v in r.matched_vulns]
        assert "CVE-2021-41773" in cve_ids

    @pytest.mark.asyncio
    async def test_correlate_nginx_banner(self):
        c = Correlator()
        asset = Asset(project_id=1, value="10.0.0.2",
                      banner="nginx/1.20.1", service="https", port=443)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) >= 1
        assert any("CVE-2021-3618" == v.get("cve") for v in r.matched_vulns)

    @pytest.mark.asyncio
    async def test_correlate_openssh_banner(self):
        c = Correlator()
        asset = Asset(project_id=1, value="172.16.0.1",
                      banner="OpenSSH_7.4p1 Debian-10+deb9u7", service="ssh", port=22)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) >= 1
        # OpenSSH 7.4 -> CVE-2018-15473
        cves = [v.get("cve") for v in r.matched_vulns]
        assert "CVE-2018-15473" in cves

    @pytest.mark.asyncio
    async def test_correlate_tomcat_banner(self):
        c = Correlator()
        asset = Asset(project_id=1, value="10.0.0.3",
                      banner="Apache Tomcat/9.0.31", service="http", port=8080)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) >= 1

    @pytest.mark.asyncio
    async def test_correlate_without_banner_no_match(self):
        c = Correlator()
        asset = Asset(project_id=1, value="192.168.1.1",
                      banner="", service="unknown-svc", port=65535)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) == 0

    @pytest.mark.asyncio
    async def test_correlate_severity_detection(self):
        """Critical vulns (CVSS >= 9) should produce critical severity."""
        c = Correlator()
        # spring:5.2 -> CVE-2022-22965 (CVSS 9.8, KEV)
        asset = Asset(project_id=1, value="10.0.0.4",
                      banner="Spring Boot/5.2.0", service="http", port=8080)
        r = await c.correlate_asset(asset)
        assert r.top_severity == "critical"
        assert r.total_risk > 0


class TestCorrelateByService:
    @pytest.mark.asyncio
    async def test_correlate_with_service_version(self):
        c = Correlator()
        asset = Asset(project_id=1, value="10.0.0.5",
                      service="apache", version="2.4.50", port=80)
        r = await c.correlate_asset(asset)
        assert len(r.matched_vulns) >= 1
        cves = [v.get("cve") for v in r.matched_vulns]
        assert "CVE-2021-42013" in cves


class TestCorrelateBatch:
    def test_correlate_batch(self):
        c = Correlator()
        assets = [
            Asset(project_id=1, value="host1", service="apache", version="2.4.49"),
            Asset(project_id=1, value="host2", service="openssh", version="8.5"),
            Asset(project_id=1, value="host3", service="nonexistent", version="99.0"),
        ]
        results = c.correlate_batch(assets)
        assert len(results) == 3
        # host1 (apache 2.4.49) should have vulns
        assert len(results[0].matched_vulns) >= 1
        # host2 (openssh 8.5) should have vulns
        assert len(results[1].matched_vulns) >= 1
        # host3 should have 0 vulns
        assert len(results[2].matched_vulns) == 0
        # Results should be sorted by risk DESC
        assert results[0].total_risk >= results[1].total_risk
        assert results[1].total_risk >= results[2].total_risk


class TestFindingsFromResult:
    @pytest.mark.asyncio
    async def test_convert_to_findings(self):
        c = Correlator()
        asset = Asset(id=42, project_id=1, value="10.0.0.1",
                      banner="Apache/2.4.49 (Unix)", service="http", port=80)
        r = await c.correlate_asset(asset)
        findings = c.findings_from_result(1, r)
        assert len(findings) == len(r.matched_vulns)
        for f in findings:
            assert f.project_id == 1
            assert f.asset_id == 42
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.cve_ids
            assert f.risk_score > 0


class TestCorrelationResult:
    def test_default_result(self):
        asset = Asset(project_id=1, value="test")
        r = CorrelationResult(asset=asset)
        assert r.total_risk == 0.0
        assert r.top_severity == "info"
        assert r.matched_vulns == []
