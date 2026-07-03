"""Tests for ATT&CK Mapper — MITRE ATT&CK Framework Integration."""

import pytest
from src.intel.attck import ATTACKMapper, ATTCTechnique, ATTACK_TECHNIQUES, CWE_TO_ATTACK, TACTICS_ORDER


class TestTechniqueData:
    def test_techniques_exist(self):
        assert len(ATTACK_TECHNIQUES) == 10

    def test_technique_structure(self):
        t = ATTACK_TECHNIQUES["T1190"]
        assert t.name == "Exploit Public-Facing Application"
        assert t.tactic == "Initial Access"
        assert len(t.platforms) > 0
        assert len(t.detection) > 0
        assert len(t.mitigations) > 0

    def test_tactics_order(self):
        assert TACTICS_ORDER[0] == "Reconnaissance"
        assert TACTICS_ORDER[-1] == "Impact"
        assert "Initial Access" in TACTICS_ORDER
        assert "Execution" in TACTICS_ORDER
        assert "Exfiltration" in TACTICS_ORDER

    def test_cwe_mappings(self):
        assert len(CWE_TO_ATTACK) >= 10
        assert "T1190" in CWE_TO_ATTACK["CWE-89"]  # SQLi
        assert "T1059" in CWE_TO_ATTACK["CWE-78"]  # Command Injection


class TestGetTechnique:
    def test_get_valid_technique(self):
        m = ATTACKMapper()
        t = m.get_technique("T1190")
        assert t is not None
        assert t.name == "Exploit Public-Facing Application"

    def test_get_invalid_technique(self):
        m = ATTACKMapper()
        assert m.get_technique("T9999") is None

    def test_get_technique_case_insensitive(self):
        m = ATTACKMapper()
        t = m.get_technique("t1190")
        assert t is not None
        assert t.id == "T1190"


class TestMapCWE:
    def test_map_cwe_sqli(self):
        m = ATTACKMapper()
        results = m.map_cwe("CWE-89")
        assert len(results) == 1
        assert results[0].id == "T1190"

    def test_map_cwe_deserialization(self):
        m = ATTACKMapper()
        results = m.map_cwe("CWE-502")
        assert len(results) == 2
        ids = [t.id for t in results]
        assert "T1059" in ids
        assert "T1068" in ids

    def test_map_cwe_unknown(self):
        m = ATTACKMapper()
        results = m.map_cwe("CWE-99999")
        assert len(results) == 0

    def test_map_cwe_case_insensitive(self):
        m = ATTACKMapper()
        results = m.map_cwe("cwe-89")
        assert len(results) == 1
        assert results[0].id == "T1190"


class TestMapCVE:
    def test_map_cve_with_cwes(self):
        m = ATTACKMapper()
        results = m.map_cve("CVE-2021-44228", cwe_ids=["CWE-502", "CWE-20"])
        assert len(results) >= 2

    def test_map_cve_without_cwes(self):
        m = ATTACKMapper()
        results = m.map_cve("CVE-2021-44228")
        assert len(results) == 0


class TestMapFinding:
    def test_map_finding_with_cwe(self):
        m = ATTACKMapper()
        r = m.map_finding("SQL Injection in login", "Blind SQLi found",
                          "CWE-89", "critical")
        assert r["technique_count"] >= 1
        assert r["tactic_count"] >= 1
        assert "T1190" in [t["id"] for t in r["techniques"]]
        assert r["severity"] == "critical"
        assert "CWE-89" in r["cwe_mappings"]

    def test_map_finding_keyword_detection(self):
        """Keyword-based CWE detection from title/description."""
        m = ATTACKMapper()
        r = m.map_finding("Log4Shell RCE", "Remote code execution via JNDI",
                          "", "critical")
        # "rce" and "remote code execution" keywords -> CWE-78 -> T1059
        assert r["technique_count"] >= 1
        assert "CWE-78" in r["cwe_mappings"]

    def test_map_finding_keyword_sqli(self):
        m = ATTACKMapper()
        r = m.map_finding("SQL Injection found", "Blind SQL injection",
                          "", "high")
        assert "CWE-89" in r["cwe_mappings"]

    def test_map_finding_keyword_xss(self):
        m = ATTACKMapper()
        r = m.map_finding("XSS in search form", "Cross-site scripting",
                          "", "medium")
        assert "CWE-79" in r["cwe_mappings"]

    def test_map_finding_keyword_deserialization(self):
        m = ATTACKMapper()
        r = m.map_finding("Java Deserialization in API",
                          "Insecure deserialization of user input",
                          "", "critical")
        assert "CWE-502" in r["cwe_mappings"]

    def test_map_finding_keyword_ssrf(self):
        m = ATTACKMapper()
        r = m.map_finding("SSRF via import endpoint",
                          "Server-side request forgery allows internal network access",
                          "", "high")
        assert "CWE-918" in r["cwe_mappings"]

    def test_map_finding_tactics_matrix(self):
        m = ATTACKMapper()
        r = m.map_finding("Critical RCE", "Remote code execution",
                          "CWE-78,CWE-20", "critical")
        assert "tactics_matrix" in r
        assert isinstance(r["tactics_matrix"], dict)
        assert r["tactics_matrix"]["Execution"] is True  # T1059 tactic

    def test_map_finding_no_match(self):
        m = ATTACKMapper()
        r = m.map_finding("Unknown issue", "Nothing matches",
                          "", "low")
        assert r["technique_count"] == 0
        assert r["tactic_count"] == 0


class TestNavigatorLayer:
    def test_generate_navigator_layer(self):
        m = ATTACKMapper()
        findings = [
            {"title": "SQL Injection", "description": "", "cwe_ids": "CWE-89", "severity": "critical"},
            {"title": "XSS", "description": "", "cwe_ids": "CWE-79", "severity": "high"},
            {"title": "RCE", "description": "Remote code execution", "cwe_ids": "CWE-78", "severity": "critical"},
        ]
        layer = m.generate_attack_navigator_layer(findings, "Test Project")
        assert layer["name"] == "Test Project Findings - ATT&CK Mapping"
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["attack"] == "15"
        assert "techniques" in layer
        assert "gradient" in layer

    def test_generate_navigator_layer_empty(self):
        m = ATTACKMapper()
        layer = m.generate_attack_navigator_layer([], "")
        assert layer["techniques"] == []


class TestListTechniques:
    def test_list_all_techniques(self):
        m = ATTACKMapper()
        techniques = m.list_all_techniques()
        assert len(techniques) == 10
        for t in techniques:
            assert "id" in t
            assert "name" in t
            assert "tactic" in t
            assert "platforms" in t

    def test_techniques_by_tactic(self):
        m = ATTACKMapper()
        by_tactic = m.techniques_by_tactic()
        assert isinstance(by_tactic, dict)
        # "Initial Access" should have T1190 and T1199
        ia = by_tactic.get("Initial Access", [])
        ia_ids = [t["id"] for t in ia]
        assert "T1190" in ia_ids
        assert "T1199" in ia_ids
