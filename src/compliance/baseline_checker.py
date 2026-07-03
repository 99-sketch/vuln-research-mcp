"""
Security Baseline & Compliance Checker (v5.0)

Enterprise security baseline checking and compliance verification:
  - 等级保护 2.0 (等保2.0) basic checks
  - CIS benchmarks
  - Service hardening checks
  - Port exposure assessment
  - Weak cipher detection
  - Configuration compliance scoring

Usage:
    checker = BaselineChecker()
    rules = checker.load_rules("cis_linux_server")
    results = checker.run_checks(target="10.0.0.1", rules=rules)
    report = checker.generate_report(results)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Data Models ─────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class BaselineRule:
    """A single baseline check rule."""
    rule_id: str
    title: str
    description: str
    category: str                          # e.g. authentication, encryption, network, patching
    severity: Severity = Severity.MEDIUM
    check_type: str = "manual"            # manual, script, port_check, version_check
    expected_value: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class BaselineResult:
    """Result of a single baseline check."""
    rule: BaselineRule
    status: CheckStatus = CheckStatus.SKIP
    actual_value: str = ""
    evidence: str = ""
    score_impact: float = 0.0            # negative for failures
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.rule_id,
            "title": self.rule.title,
            "status": self.status.value,
            "severity": self.rule.severity.value,
            "actual_value": self.actual_value,
            "evidence": self.evidence,
            "score_impact": self.score_impact,
        }


@dataclass
class ComplianceReport:
    """Full compliance check report."""
    target: str
    profile: str                          # which baseline was used
    results: List[BaselineResult] = field(default_factory=list)
    total_rules: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    skipped: int = 0
    score: float = 0.0                   # 0-100
    grade: str = "F"
    generated_at: float = field(default_factory=time.time)

    def compute_grade(self):
        """Compute letter grade based on score."""
        if self.score >= 95:
            self.grade = "A+"
        elif self.score >= 90:
            self.grade = "A"
        elif self.score >= 85:
            self.grade = "B+"
        elif self.score >= 80:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "C"
        elif self.score >= 60:
            self.grade = "D"
        else:
            self.grade = "F"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "profile": self.profile,
            "total_rules": self.total_rules,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "skipped": self.skipped,
            "score": self.score,
            "grade": self.grade,
            "results": [r.to_dict() for r in self.results],
            "generated_at": self.generated_at,
        }

    def to_markdown(self) -> str:
        """Generate a markdown compliance report."""
        lines = [
            f"# Compliance Report",
            f"",
            f"**Target:** {self.target}  ",
            f"**Profile:** {self.profile}  ",
            f"**Score:** {self.score:.1f}/100 ({self.grade})  ",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.generated_at))}  ",
            f"",
            f"## Summary",
            f"",
            f"| Status | Count |",
            f"|--------|-------|",
            f"| ✅ Pass | {self.passed} |",
            f"| ❌ Fail | {self.failed} |",
            f"| ⚠️  Warn | {self.warnings} |",
            f"| ⏭️  Skip | {self.skipped} |",
            f"| **Total** | **{self.total_rules}** |",
            f"",
            f"## Failed Checks",
            f"",
        ]

        failed = [r for r in self.results if r.status == CheckStatus.FAIL]
        if failed:
            for r in failed:
                lines.append(f"### [{r.rule.severity.value}] {r.rule.title}")
                lines.append(f"")
                lines.append(f"- **Rule:** {r.rule.rule_id}")
                lines.append(f"- **Description:** {r.rule.description}")
                lines.append(f"- **Actual:** {r.actual_value}")
                lines.append(f"- **Remediation:** {r.rule.remediation}")
                lines.append(f"")
        else:
            lines.append("No failed checks! 🎉")
            lines.append("")

        # Warnings
        warned = [r for r in self.results if r.status == CheckStatus.WARN]
        if warned:
            lines.append("## Warnings")
            lines.append("")
            for r in warned:
                lines.append(f"- **{r.rule.title}**: {r.actual_value}")

        return "\n".join(lines)


# ── Built-in Baseline Profiles ──────────────────────────────────────

# 等保2.0 三级 — 主机安全基线
DENGBAO_L3_RULES = [
    BaselineRule(
        rule_id="DB-L3-001", title="操作系统最小化安装",
        description="仅安装必要的系统组件和应用，关闭不必要的服务",
        category="system_hardening", severity=Severity.CRITICAL,
        check_type="port_check", expected_value="no unnecessary services",
        remediation="关闭 telnet、ftp、rsh 等非必要服务",
        tags=["等保2.0", "三级", "最小化"],
    ),
    BaselineRule(
        rule_id="DB-L3-002", title="密码复杂度策略",
        description="密码长度≥8位，包含大小写字母、数字、特殊字符中至少3种",
        category="authentication", severity=Severity.HIGH,
        check_type="manual", expected_value="PASS",
        remediation="配置 /etc/pam.d/system-auth 密码复杂度策略",
        tags=["等保2.0", "三级", "身份鉴别"],
    ),
    BaselineRule(
        rule_id="DB-L3-003", title="登录失败锁定",
        description="连续登录失败5次锁定账户30分钟",
        category="authentication", severity=Severity.HIGH,
        check_type="manual", expected_value="enabled",
        remediation="配置 fail2ban 或 pam_tally2",
        tags=["等保2.0", "三级", "身份鉴别"],
    ),
    BaselineRule(
        rule_id="DB-L3-004", title="SSH 安全配置",
        description="禁止 root 远程登录、使用密钥认证、修改默认端口",
        category="network", severity=Severity.HIGH,
        check_type="port_check", expected_value="PermitRootLogin no, PasswordAuthentication no",
        remediation="修改 /etc/ssh/sshd_config: PermitRootLogin no, PasswordAuthentication no",
        tags=["等保2.0", "三级", "访问控制"],
    ),
    BaselineRule(
        rule_id="DB-L3-005", title="防火墙策略",
        description="启用主机防火墙，仅开放必要的服务端口",
        category="network", severity=Severity.CRITICAL,
        check_type="port_check", expected_value="only necessary ports open",
        remediation="配置 iptables/firewalld 仅开放 22, 443 等必要端口",
        tags=["等保2.0", "三级", "访问控制"],
    ),
    BaselineRule(
        rule_id="DB-L3-006", title="审计日志启用",
        description="开启系统审计日志，记录用户登录、操作、权限变更等事件",
        category="audit", severity=Severity.HIGH,
        check_type="manual", expected_value="auditd enabled",
        remediation="安装并启用 auditd: systemctl enable auditd && systemctl start auditd",
        tags=["等保2.0", "三级", "安全审计"],
    ),
    BaselineRule(
        rule_id="DB-L3-007", title="系统补丁管理",
        description="操作系统和关键应用应及时安装安全补丁",
        category="patching", severity=Severity.HIGH,
        check_type="manual", expected_value="all critical patches applied",
        remediation="定期执行系统更新并修复已知漏洞",
        tags=["等保2.0", "三级", "入侵防范"],
    ),
    BaselineRule(
        rule_id="DB-L3-008", title="恶意代码防护",
        description="安装防病毒软件并保持病毒库更新",
        category="malware_protection", severity=Severity.HIGH,
        check_type="manual", expected_value="antivirus installed and updated",
        remediation="安装 clamav 或其他防病毒软件",
        tags=["等保2.0", "三级", "恶意代码防范"],
    ),
    BaselineRule(
        rule_id="DB-L3-009", title="日志保存期限",
        description="审计日志至少保存6个月",
        category="audit", severity=Severity.MEDIUM,
        check_type="manual", expected_value="log retention ≥ 180 days",
        remediation="配置 logrotate 保留至少180天的日志",
        tags=["等保2.0", "三级", "安全审计"],
    ),
    BaselineRule(
        rule_id="DB-L3-010", title="数据加密传输",
        description="敏感数据传输使用TLS 1.2+协议",
        category="encryption", severity=Severity.HIGH,
        check_type="port_check", expected_value="TLS >= 1.2",
        remediation="禁用 TLS 1.0/1.1，启用 TLS 1.2/1.3",
        tags=["等保2.0", "三级", "数据安全"],
    ),
]

# CIS Benchmarks — Level 1 Server
CIS_SERVER_RULES = [
    BaselineRule(
        rule_id="CIS-1.1.1", title="禁用不使用的文件系统",
        description="确保 cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf 文件系统被禁用",
        category="system_hardening", severity=Severity.MEDIUM,
        check_type="manual", expected_value="disabled",
        remediation="在 /etc/modprobe.d/ 中配置禁用不必要文件系统模块",
        tags=["CIS", "Level1", "Filesystem"],
    ),
    BaselineRule(
        rule_id="CIS-1.1.18", title="/tmp 分区挂载选项",
        description="确保 /tmp 分区以 nosuid, nodev, noexec 选项挂载",
        category="system_hardening", severity=Severity.HIGH,
        check_type="manual", expected_value="nosuid,nodev,noexec",
        remediation="在 /etc/fstab 中为 /tmp 添加 nosuid,nodev,noexec 选项",
        tags=["CIS", "Level1", "Filesystem"],
    ),
    BaselineRule(
        rule_id="CIS-5.2.1", title="SSH PermitRootLogin",
        description="确保 SSH PermitRootLogin 设置为 no",
        category="network", severity=Severity.HIGH,
        check_type="port_check", expected_value="no",
        remediation="在 /etc/ssh/sshd_config 中设置 PermitRootLogin no",
        tags=["CIS", "Level1", "SSH"],
    ),
    BaselineRule(
        rule_id="CIS-5.2.2", title="SSH 协议版本",
        description="确保仅使用 SSH Protocol 2",
        category="network", severity=Severity.CRITICAL,
        check_type="port_check", expected_value="2",
        remediation="在 /etc/ssh/sshd_config 中设置 Protocol 2",
        tags=["CIS", "Level1", "SSH"],
    ),
    BaselineRule(
        rule_id="CIS-5.3.1", title="密码创建要求",
        description="确保使用 pwquality 模块配置密码复杂度",
        category="authentication", severity=Severity.MEDIUM,
        check_type="manual", expected_value="pwquality configured",
        remediation="安装 libpwquality 并配置 /etc/security/pwquality.conf",
        tags=["CIS", "Level1", "PAM"],
    ),
]


# ── Baseline Checker ───────────────────────────────────────────────

class BaselineChecker:
    """Security baseline and compliance verification engine."""

    PROFILES = {
        "dengbao_l3": ("等保2.0 三级 — 主机安全基线", DENGBAO_L3_RULES),
        "cis_server": ("CIS Benchmarks — Level 1 Server", CIS_SERVER_RULES),
        "all": ("全量安全检查", DENGBAO_L3_RULES + CIS_SERVER_RULES),
    }

    def __init__(self):
        self._custom_rules: Dict[str, List[BaselineRule]] = {}

    def list_profiles(self) -> List[str]:
        """List available baseline profiles."""
        profiles = list(self.PROFILES.keys())
        profiles.extend(self._custom_rules.keys())
        return profiles

    def get_profile(self, name: str) -> Optional[Tuple[str, List[BaselineRule]]]:
        """Get a baseline profile by name."""
        if name in self.PROFILES:
            return self.PROFILES[name]
        if name in self._custom_rules:
            return (name, self._custom_rules[name])
        return None

    def add_custom_rules(self, profile_name: str, rules: List[BaselineRule]):
        """Add custom baseline rules."""
        self._custom_rules[profile_name] = rules

    def load_rules_from_file(self, file_path: str) -> List[BaselineRule]:
        """Load baseline rules from a JSON file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        rules = []
        for item in data:
            rules.append(BaselineRule(
                rule_id=item["rule_id"],
                title=item["title"],
                description=item.get("description", ""),
                category=item.get("category", "general"),
                severity=Severity(item.get("severity", "MEDIUM")),
                check_type=item.get("check_type", "manual"),
                expected_value=item.get("expected_value", ""),
                remediation=item.get("remediation", ""),
                references=item.get("references", []),
                tags=item.get("tags", []),
            ))
        return rules

    def run_checks(
        self,
        target: str,
        profile_name: str = "dengbao_l3",
        check_data: Optional[Dict[str, Any]] = None,
    ) -> ComplianceReport:
        """Run all baseline checks against a target.

        Args:
            target: Target IP/hostname
            profile_name: Baseline profile to use
            check_data: Pre-collected data for checks (ports, services, configs)
        """
        profile = self.get_profile(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile: {profile_name}")

        profile_desc, rules = profile
        check_data = check_data or {}

        results: List[BaselineResult] = []
        total_weight = 0.0
        total_score = 0.0

        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0.5,
        }

        for rule in rules:
            if not rule.enabled:
                results.append(BaselineResult(rule=rule, status=CheckStatus.SKIP))
                continue

            result = self._check_single_rule(rule, check_data)
            results.append(result)

            weight = severity_weights.get(rule.severity, 1.0)
            total_weight += weight

            if result.status == CheckStatus.PASS:
                total_score += weight
            elif result.status == CheckStatus.WARN:
                total_score += weight * 0.5
            # FAIL: score += 0

        # Compute final score
        score = (total_score / total_weight * 100) if total_weight > 0 else 100.0

        report = ComplianceReport(
            target=target,
            profile=f"{profile_name} ({profile_desc})",
            results=results,
            total_rules=len(rules),
            passed=sum(1 for r in results if r.status == CheckStatus.PASS),
            failed=sum(1 for r in results if r.status == CheckStatus.FAIL),
            warnings=sum(1 for r in results if r.status == CheckStatus.WARN),
            skipped=sum(1 for r in results if r.status == CheckStatus.SKIP),
            score=round(score, 1),
        )
        report.compute_grade()
        return report

    def generate_report(self, report: ComplianceReport) -> str:
        """Generate a human-readable compliance report."""
        return report.to_markdown()

    # ── Private ──────────────────────────────────────────────────

    def _check_single_rule(self, rule: BaselineRule, data: dict) -> BaselineResult:
        """Check a single baseline rule against provided data."""
        result = BaselineResult(rule=rule)

        if rule.check_type == "port_check":
            return self._check_ports(rule, data)
        elif rule.check_type == "version_check":
            return self._check_version(rule, data)
        else:
            # Manual checks: mark as skip
            result.status = CheckStatus.SKIP
            result.actual_value = "manual verification required"
            result.evidence = f"Run check manually: {rule.remediation}"
            return result

    def _check_ports(self, rule: BaselineRule, data: dict) -> BaselineResult:
        """Check port-based rules."""
        result = BaselineResult(rule=rule)
        open_ports = data.get("open_ports", [])

        if rule.rule_id in ("DB-L3-001", "DB-L3-005"):
            # Check for dangerous ports
            dangerous_ports = {23, 21, 135, 139, 445, 3389, 3306, 5432, 6379, 27017}
            found = [p for p in open_ports if p in dangerous_ports]

            if found:
                result.status = CheckStatus.FAIL
                result.actual_value = f"Dangerous ports open: {found}"
                result.evidence = f"Ports {found} should be closed unless explicitly required"
                result.score_impact = -10
            else:
                result.status = CheckStatus.PASS
                result.actual_value = "No dangerous ports detected"

        elif rule.rule_id == "DB-L3-004":
            # SSH hardening check: port 22 should not allow root, should use key auth
            if 22 in open_ports:
                ssh_config = data.get("ssh_config", {})
                root_login = ssh_config.get("PermitRootLogin", "yes")
                pass_auth = ssh_config.get("PasswordAuthentication", "yes")

                if root_login.lower() == "no" and pass_auth.lower() == "no":
                    result.status = CheckStatus.PASS
                    result.actual_value = "SSH hardened: root login disabled, key auth required"
                elif root_login.lower() == "no":
                    result.status = CheckStatus.WARN
                    result.actual_value = "SSH: root login disabled but password auth still allowed"
                else:
                    result.status = CheckStatus.FAIL
                    result.actual_value = f"SSH: root login allowed ({root_login})"
                    result.evidence = "Root SSH login is a significant security risk"
            else:
                result.status = CheckStatus.PASS
                result.actual_value = "SSH port 22 not detected"

        return result

    def _check_version(self, rule: BaselineRule, data: dict) -> BaselineResult:
        """Check version-based rules."""
        result = BaselineResult(rule=rule)
        versions = data.get("versions", {})

        # Simple version comparison
        result.status = CheckStatus.SKIP
        result.actual_value = "version check not implemented for this rule"
        return result


# ── Global Singleton ────────────────────────────────────────────────

_baseline_checker: Optional[BaselineChecker] = None


def get_baseline_checker() -> BaselineChecker:
    global _baseline_checker
    if _baseline_checker is None:
        _baseline_checker = BaselineChecker()
    return _baseline_checker
