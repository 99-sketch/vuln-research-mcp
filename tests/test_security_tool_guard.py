# tests/test_security_tool_guard.py
"""Tests for src/security/tool_guard.py"""

import pytest
from src.security.tool_guard import (
    ToolRiskLevel,
    ToolGuard,
    TOOL_RISK_MAP,
    create_tool_guard,
)


class TestToolRiskLevel:
    def test_known_tool_has_risk_level(self):
        assert TOOL_RISK_MAP["search_cve"] == ToolRiskLevel.READ_ONLY
        assert TOOL_RISK_MAP["scan_ports"] == ToolRiskLevel.ACTIVE_SCAN
        assert TOOL_RISK_MAP["search_metasploit"] == ToolRiskLevel.EXPLOIT
        assert TOOL_RISK_MAP["clone_poc_archive"] == ToolRiskLevel.SYSTEM

    def test_unknown_tool_defaults_to_read_only(self):
        guard = ToolGuard()
        assert guard.get_risk_level("nonexistent_tool") == ToolRiskLevel.READ_ONLY


class TestToolGuard:
    @pytest.fixture
    def guard(self):
        return ToolGuard()

    def test_read_only_allowed_at_all_levels(self, guard):
        allowed, _ = guard.is_allowed("search_cve")
        assert allowed

    def test_scan_blocked_at_lower_level(self):
        guard = ToolGuard(max_risk_level=ToolRiskLevel.READ_ONLY)
        allowed, reason = guard.is_allowed("scan_ports")
        assert not allowed
        assert "风险等级" in reason or "超出" in reason

    def test_exploit_blocked_at_network_level(self):
        guard = ToolGuard(max_risk_level=ToolRiskLevel.NETWORK_INFO)
        allowed, _ = guard.is_allowed("search_metasploit")
        assert not allowed

    def test_system_blocked_at_scan_level(self):
        guard = ToolGuard(max_risk_level=ToolRiskLevel.ACTIVE_SCAN)
        allowed, _ = guard.is_allowed("clone_poc_archive")
        assert not allowed

    def test_network_info_blocked_at_read_only(self):
        guard = ToolGuard(max_risk_level=ToolRiskLevel.READ_ONLY)
        allowed, _ = guard.is_allowed("query_dns")
        assert not allowed

    def test_set_max_risk_level(self, guard):
        guard.set_max_risk_level(ToolRiskLevel.READ_ONLY)
        assert guard._max_risk_level == ToolRiskLevel.READ_ONLY

    def test_tool_hash_verification(self, guard):
        schema = {"type": "object", "properties": {"param": {"type": "string"}}}
        h = guard.compute_tool_hash("test_tool", schema)
        assert len(h) == 64  # SHA256 hex length
        assert guard.verify_tool_hash("test_tool", schema)

    def test_tool_hash_tamper_detection(self, guard):
        original_schema = {"type": "object", "properties": {"param": {"type": "string"}}}
        guard.compute_tool_hash("test_tool", original_schema)

        tampered_schema = {"type": "object", "properties": {"param": {"type": "number"}}}
        assert not guard.verify_tool_hash("test_tool", tampered_schema)

    def test_unknown_tool_hash_verifies_true(self, guard):
        schema = {"type": "object"}
        assert guard.verify_tool_hash("unknown_tool", schema)

    def test_filter_tools_by_risk_level(self, guard):
        tools = [
            {"name": "search_cve"},
            {"name": "scan_ports"},
            {"name": "search_metasploit"},
            {"name": "clone_poc_archive"},
        ]
        filtered = guard.filter_tools(tools, max_level=ToolRiskLevel.NETWORK_INFO)
        names = [t["name"] for t in filtered]
        assert "search_cve" in names
        assert "scan_ports" not in names  # active_scan > network_info

    def test_get_all_valid_scanners(self, guard):
        scanners = guard.get_all_valid_scanners()
        assert "scan_ports" in scanners
        assert "search_metasploit" in scanners
        assert "search_cve" not in scanners  # read-only, not a scanner

    def test_create_tool_guard_global(self):
        guard = create_tool_guard()
        assert guard is not None
        assert guard._max_risk_level == ToolRiskLevel.SYSTEM


class TestRateLimit:
    def test_rate_limit_allows_initial_calls(self):
        guard = ToolGuard()
        for _ in range(5):
            allowed, _ = guard.is_allowed("search_cve")
            assert allowed
