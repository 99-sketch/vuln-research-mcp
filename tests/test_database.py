"""Tests for Database — SQLite persistence layer."""

import pytest
from src.db.database import Database
from src.db.models import (
    Asset, Evidence, Finding, PentestReport,
    Project, Scan, TimelineEvent,
)


@pytest.fixture
def db():
    d = Database(":memory:")
    d.initialize()
    yield d
    d.close()


class TestDatabaseInit:
    def test_initialize_creates_tables(self):
        d = Database(":memory:")
        d.initialize()
        # Verify by creating a project
        p = Project(name="test")
        pid = d.create_project(p)
        assert pid > 0
        d.close()

    def test_close(self):
        d = Database(":memory:")
        d.initialize()
        d.close()  # should not raise


class TestProjectCRUD:
    def test_create_project(self, db):
        p = Project(name="External Penetration Test", description="Q3 engagement",
                    client="ACME Corp", status="active", tags="pentest,external")
        pid = db.create_project(p)
        assert pid > 0

    def test_get_project(self, db):
        p = Project(name="API Security Audit", description="REST API review")
        pid = db.create_project(p)
        result = db.get_project(pid)
        assert result is not None
        assert result.name == "API Security Audit"
        assert result.description == "REST API review"

    def test_get_nonexistent_project(self, db):
        assert db.get_project(99999) is None

    def test_list_projects(self, db):
        db.create_project(Project(name="Project A"))
        db.create_project(Project(name="Project B"))
        projects = db.list_projects()
        assert len(projects) == 2

    def test_list_projects_by_status(self, db):
        db.create_project(Project(name="Active1", status="active"))
        db.create_project(Project(name="Active2", status="active"))
        db.create_project(Project(name="Done", status="completed"))
        assert len(db.list_projects("active")) == 2
        assert len(db.list_projects("completed")) == 1
        assert len(db.list_projects("archived")) == 0

    def test_update_project(self, db):
        p = Project(name="Old Name", description="old desc")
        pid = db.create_project(p)

        updated = db.get_project(pid)
        updated.description = "new description"
        updated.status = "completed"
        db.update_project(updated)

        result = db.get_project(pid)
        assert result.description == "new description"
        assert result.status == "completed"

    def test_delete_project(self, db):
        p = Project(name="To Delete")
        pid = db.create_project(p)
        assert db.get_project(pid) is not None

        db.delete_project(pid)
        assert db.get_project(pid) is None

    def test_delete_project_cascades(self, db):
        p = Project(name="Cascade Test")
        pid = db.create_project(p)

        a = Asset(project_id=pid, value="10.0.0.1")
        aid = db.create_asset(a)
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="Test Vuln"))

        assert len(db.list_assets(pid)) == 1
        assert len(db.list_findings(pid)) == 1

        db.delete_project(pid)
        # CASCADE should remove assets and findings
        assert len(db.list_assets(pid)) == 0
        assert len(db.list_findings(pid)) == 0


class TestAssetCRUD:
    @pytest.fixture
    def pid(self, db):
        p = Project(name="Asset Test Project")
        return db.create_project(p)

    def test_create_asset(self, db, pid):
        a = Asset(project_id=pid, asset_type="domain", value="example.com",
                  port=443, protocol="tcp", service="https", banner="nginx/1.20.1")
        aid = db.create_asset(a)
        assert aid > 0

    def test_get_asset(self, db, pid):
        a = Asset(project_id=pid, value="192.168.1.1", service="ssh", port=22)
        aid = db.create_asset(a)
        result = db.get_asset(aid)
        assert result is not None
        assert result.value == "192.168.1.1"
        assert result.service == "ssh"

    def test_list_assets_by_project(self, db, pid):
        db.create_asset(Asset(project_id=pid, value="10.0.0.1", port=80))
        db.create_asset(Asset(project_id=pid, value="10.0.0.2", port=443))
        assert len(db.list_assets(pid)) == 2

    def test_list_assets_by_type(self, db, pid):
        db.create_asset(Asset(project_id=pid, value="10.0.0.1", asset_type="ip", port=80))
        db.create_asset(Asset(project_id=pid, value="example.com", asset_type="domain"))
        assert len(db.list_assets(pid, asset_type="ip")) == 1
        assert len(db.list_assets(pid, asset_type="domain")) == 1

    def test_update_asset(self, db, pid):
        a = Asset(project_id=pid, value="stale.example.com", service="http")
        aid = db.create_asset(a)

        updated = db.get_asset(aid)
        updated.banner = "Apache/2.4.49"
        updated.version = "2.4.49"
        updated.is_alive = False
        db.update_asset(updated)

        result = db.get_asset(aid)
        assert result.banner == "Apache/2.4.49"
        assert result.version == "2.4.49"
        assert result.is_alive == False

    def test_upsert_asset_insert(self, db, pid):
        aid = db.upsert_asset(pid, "ip", "172.16.0.1", port=3306)
        assert aid > 0
        assert len(db.list_assets(pid)) == 1

    def test_upsert_asset_update(self, db, pid):
        aid1 = db.upsert_asset(pid, "ip", "10.0.0.5", port=22)
        aid2 = db.upsert_asset(pid, "ip", "10.0.0.5", port=22)
        assert aid1 == aid2  # same ID
        assert len(db.list_assets(pid)) == 1  # still only one asset


class TestFindingCRUD:
    @pytest.fixture
    def pid(self, db):
        return db.create_project(Project(name="Findings Test"))

    @pytest.fixture
    def aid(self, db, pid):
        return db.create_asset(Asset(project_id=pid, value="target.com"))

    def test_create_finding_all_fields(self, db, pid, aid):
        f = Finding(
            project_id=pid, asset_id=aid, title="SQL Injection in login form",
            description="Blind SQL injection detected in username parameter",
            severity="critical", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/...",
            cve_ids="CVE-2021-44228", cwe_ids="CWE-89",
            epss_score=97.5, is_kev=True, has_exploit=True,
            impact="Full database exfiltration", remediation="Use parameterized queries",
            risk_score=19.5, tags="sql,injection,login",
        )
        fid = db.create_finding(f)
        assert fid > 0

    def test_list_findings(self, db, pid, aid):
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="F1", severity="critical"))
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="F2", severity="high"))
        assert len(db.list_findings(pid)) == 2

    def test_list_findings_by_severity(self, db, pid, aid):
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="Crit", severity="critical"))
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="High", severity="high"))
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="Mid", severity="medium"))
        assert len(db.list_findings(pid, severity="critical")) == 1
        assert len(db.list_findings(pid, severity="high")) == 1

    def test_list_findings_by_status(self, db, pid, aid):
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="Open Vuln", status="open"))
        db.create_finding(Finding(project_id=pid, asset_id=aid,
                                   title="Fixed Vuln", status="fixed"))
        assert len(db.list_findings(pid, status="open")) == 1
        assert len(db.list_findings(pid, status="fixed")) == 1

    def test_update_finding_status(self, db, pid, aid):
        f = Finding(project_id=pid, asset_id=aid, title="To Fix")
        fid = db.create_finding(f)

        db.update_finding_status(fid, "fixed", assigned_to="analyst1")

        # Re-query
        findings = db.list_findings(pid, status="fixed")
        assert len(findings) == 1
        assert findings[0].title == "To Fix"

    def test_finding_stats(self, db, pid, aid):
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="C1", severity="critical"))
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="C2", severity="critical"))
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="H1", severity="high"))

        stats = db.get_finding_stats(pid)
        assert stats["critical"] == 2
        assert stats["high"] == 1
        assert stats["medium"] == 0
        assert stats["low"] == 0
        assert stats["info"] == 0


class TestScanCRUD:
    @pytest.fixture
    def pid(self, db):
        return db.create_project(Project(name="Scans Test"))

    def test_create_scan(self, db, pid):
        s = Scan(project_id=pid, scan_type="port_scan", tool="nmap",
                 target="10.0.0.0/24", command="nmap -sV 10.0.0.0/24")
        sid = db.create_scan(s)
        assert sid > 0

    def test_update_scan_result(self, db, pid):
        s = Scan(project_id=pid, scan_type="vuln_scan", tool="nuclei",
                 target="https://example.com")
        sid = db.create_scan(s)

        db.update_scan_result(sid, "completed", output="Found 3 vulns",
                              result_count=3, duration_ms=45000)

    def test_list_scans(self, db, pid):
        db.create_scan(Scan(project_id=pid, scan_type="port_scan", tool="nmap",
                            target="range1"))
        db.create_scan(Scan(project_id=pid, scan_type="vuln_scan", tool="nuclei",
                            target="range2"))
        assert len(db.list_scans(pid)) == 2


class TestEvidenceCRUD:
    @pytest.fixture
    def fid(self, db):
        pid = db.create_project(Project(name="Evidence Test"))
        aid = db.create_asset(Asset(project_id=pid, value="target"))
        return db.create_finding(Finding(project_id=pid, asset_id=aid, title="Vuln"))

    def test_create_evidence(self, db, fid):
        e = Evidence(finding_id=fid, evidence_type="screenshot",
                     title="Login SQLi", content="base64...")
        eid = db.create_evidence(e)
        assert eid > 0

    def test_list_evidences(self, db, fid):
        db.create_evidence(Evidence(finding_id=fid, title="E1"))
        db.create_evidence(Evidence(finding_id=fid, title="E2"))
        assert len(db.list_evidences(fid)) == 2


class TestTimelineCRUD:
    @pytest.fixture
    def pid(self, db):
        return db.create_project(Project(name="Timeline Test"))

    def test_add_timeline_event(self, db, pid):
        e = TimelineEvent(project_id=pid, event_type="scan_started",
                          title="Nmap scan started", severity="info", source="nmap")
        eid = db.add_timeline_event(e)
        assert eid > 0

    def test_list_timeline(self, db, pid):
        db.add_timeline_event(TimelineEvent(project_id=pid, title="Event 1"))
        db.add_timeline_event(TimelineEvent(project_id=pid, title="Event 2"))
        db.add_timeline_event(TimelineEvent(project_id=pid, title="Event 3"))
        events = db.list_timeline(pid)
        assert len(events) == 3
        # Should be chronological order (oldest first)
        assert events[0].title == "Event 1"
        assert events[-1].title == "Event 3"

    def test_list_timeline_limit(self, db, pid):
        for i in range(10):
            db.add_timeline_event(TimelineEvent(project_id=pid, title=f"E{i}"))
        assert len(db.list_timeline(pid, limit=5)) == 5


class TestReportCRUD:
    @pytest.fixture
    def pid(self, db):
        return db.create_project(Project(name="Report Test"))

    def test_create_report(self, db, pid):
        r = PentestReport(project_id=pid, title="Final Report", format="markdown",
                          content="# Report\n...", summary="Test completed",
                          finding_count=3, critical_count=1, high_count=2)
        rid = db.create_report(r)
        assert rid > 0

    def test_get_report(self, db, pid):
        r = PentestReport(project_id=pid, title="My Report", format="json",
                          content='{"findings": []}')
        rid = db.create_report(r)
        result = db.get_report(rid)
        assert result is not None
        assert result.title == "My Report"

    def test_list_reports(self, db, pid):
        db.create_report(PentestReport(project_id=pid, title="R1"))
        db.create_report(PentestReport(project_id=pid, title="R2"))
        assert len(db.list_reports(pid)) == 2


class TestProjectSummary:
    @pytest.fixture
    def pid(self, db):
        return db.create_project(Project(name="Summary Test"))

    def test_empty_summary(self, db, pid):
        s = db.get_project_summary(pid)
        assert s["asset_count"] == 0
        assert s["scan_count"] == 0
        assert s["total_findings"] == 0
        assert s["timeline_events"] == 0

    def test_full_summary(self, db, pid):
        db.create_asset(Asset(project_id=pid, value="a.com"))
        db.create_asset(Asset(project_id=pid, value="b.com"))
        db.create_scan(Scan(project_id=pid, scan_type="port_scan", tool="nmap", target="*"))
        aid = db.create_asset(Asset(project_id=pid, value="target.com"))
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="Vuln1", severity="critical"))
        db.create_finding(Finding(project_id=pid, asset_id=aid, title="Vuln2", severity="high"))
        db.add_timeline_event(TimelineEvent(project_id=pid, title="E1"))

        s = db.get_project_summary(pid)
        assert s["asset_count"] == 3
        assert s["scan_count"] == 1
        assert s["total_findings"] == 2
        assert s["findings"]["critical"] == 1
        assert s["findings"]["high"] == 1
        assert s["timeline_events"] == 1
