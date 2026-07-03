# tests/test_security_target_policy.py
"""Tests for src/security/target_policy.py"""

import pytest
from src.security.target_policy import (
    TargetPolicy,
    ScanLimitPolicy,
    create_default_policy,
    create_enterprise_policy,
)


class TestTargetPolicy:
    @pytest.fixture
    def basic_policy(self):
        return TargetPolicy(whitelist_enabled=False)

    @pytest.fixture
    def strict_policy(self):
        return TargetPolicy(whitelist_enabled=True)

    @pytest.fixture
    def enterprise_policy(self):
        return create_enterprise_policy(["10.0.0.0/8", "192.168.1.0/24"])

    def test_public_target_allowed(self, basic_policy):
        allowed, _ = basic_policy.check_target("example.com")
        assert allowed

    def test_localhost_blocked_by_default(self, basic_policy):
        allowed, reason = basic_policy.check_target("localhost")
        assert not allowed
        assert "黑名单" in reason

    def test_127_0_0_1_blocked(self, basic_policy):
        allowed, _ = basic_policy.check_target("127.0.0.1")
        assert not allowed

    def test_multicast_blocked(self, basic_policy):
        allowed, _ = basic_policy.check_target("224.0.0.1")
        assert not allowed

    def test_private_ip_allowed_by_default(self, basic_policy):
        allowed, _ = basic_policy.check_target("10.0.0.1")
        assert allowed

    def test_private_ip_denied_when_disabled(self):
        policy = TargetPolicy(allow_private_ips=False)
        allowed, reason = policy.check_target("192.168.1.1")
        assert not allowed
        assert "内网" in reason

    def test_public_ip_denied_when_disabled(self):
        policy = TargetPolicy(allow_public_ips=False)
        allowed, reason = policy.check_target("8.8.8.8")
        assert not allowed
        assert "公网" in reason

    def test_whitelist_mode_denies_unknown(self, strict_policy):
        allowed, reason = strict_policy.check_target("example.com")
        assert not allowed
        assert "白名单" in reason

    def test_whitelist_mode_allows_known(self, strict_policy):
        strict_policy.add_to_whitelist("example.com")
        allowed, _ = strict_policy.check_target("example.com")
        assert allowed

    def test_whitelist_network(self, strict_policy):
        strict_policy.whitelist_networks = ["10.0.0.0/8"]
        allowed, _ = strict_policy.check_target("10.0.0.1")
        assert allowed

    def test_enterprise_allows_internal(self, enterprise_policy):
        allowed, _ = enterprise_policy.check_target("10.1.2.3")
        assert allowed

    def test_enterprise_denies_public(self, enterprise_policy):
        allowed, reason = enterprise_policy.check_target("8.8.8.8")
        assert not allowed

    def test_empty_target_denied(self, basic_policy):
        allowed, _ = basic_policy.check_target("")
        assert not allowed

    def test_blocked_domain_suffix(self, basic_policy):
        basic_policy.blacklist_domains = ["malicious.com"]
        allowed, _ = basic_policy.check_target("evil.malicious.com")
        assert not allowed

    def test_add_to_whitelist_no_duplicate(self):
        policy = TargetPolicy(whitelist_enabled=True)
        policy.add_to_whitelist("test.com")
        policy.add_to_whitelist("test.com")
        assert len(policy.whitelist_targets) == 1


class TestScanLimitPolicy:
    def test_can_scan_initially(self):
        policy = ScanLimitPolicy()
        allowed, _ = policy.can_scan()
        assert allowed

    def test_record_scan_updates_count(self):
        policy = ScanLimitPolicy()
        assert policy._scan_count_today == 0
        policy.record_scan()
        assert policy._scan_count_today == 1

    def test_cooldown_enforced(self):
        policy = ScanLimitPolicy(cooldown_seconds=60)
        policy.record_scan()
        allowed, reason = policy.can_scan()
        assert not allowed
        assert "冷却" in reason

    def test_daily_limit_reached(self):
        policy = ScanLimitPolicy(max_daily_scans=2)
        policy.record_scan()
        policy.record_scan()
        policy._scan_count_today = 2  # simulate
        allowed, reason = policy.can_scan()
        assert not allowed
        assert "上限" in reason


class TestDefaultPolicy:
    def test_default_allows_public(self):
        policy = create_default_policy()
        allowed, _ = policy.check_target("github.com")
        assert allowed

    def test_default_allows_private(self):
        policy = create_default_policy()
        allowed, _ = policy.check_target("192.168.1.1")
        assert allowed

    def test_default_blocks_localhost(self):
        policy = create_default_policy()
        allowed, _ = policy.check_target("localhost")
        assert not allowed
