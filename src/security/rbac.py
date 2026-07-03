# src/security/rbac.py
"""RBAC 权限隔离 — 工具分级权限 + 4 角色控制 + 授权声明确认

v5.3: 完整的基于角色的访问控制 (Role-Based Access Control)

架构:
  Role (viewer/analyst/operator/admin) → Permission Level (0-4)
  每个工具标记 RiskLevel (0-4) → 角色只能调用 <= 自己等级的工具

风险等级:
  L0_INFO     — 只读情报查询 (CVE查询/CVSS/CWE/CPE映射/知识图谱)
  L1_NET      — 网络信息收集 (DNS/whois/IP地理位置/HTTP头)
  L2_SCAN     — 主动扫描 (端口扫描/服务探测/banner抓取)
  L3_EXPLOIT  — 漏洞测试 (Nuclei模板/Exploit搜索/Metasploit)
  L4_SYSTEM   — 系统级操作 (执行任意命令/修改配置/文件操作)

角色:
  viewer    [L0] — 只能做情报查询，零风险
  analyst   [L1] — 可做网络信息收集 + 情报
  operator  [L2-L3] — 可执行扫描和漏洞验证
  admin     [L4] — 完全控制，所有工具可用
"""

import json
import logging
import os
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vuln-research-mcp.security.rbac")


class RiskLevel(IntEnum):
    """工具风险等级 — 越高越危险"""
    L0_INFO = 0       # 只读情报
    L1_NET = 1        # 网络信息收集
    L2_SCAN = 2       # 主动扫描
    L3_EXPLOIT = 3    # 漏洞利用/测试
    L4_SYSTEM = 4     # 系统级操作


class Role(IntEnum):
    """用户角色 — 数字越大权限越高"""
    VIEWER = 0        # 只读
    ANALYST = 1       # 分析师
    OPERATOR = 2      # 操作员
    ADMIN = 3         # 管理员


# 角色 → 允许的最高风险等级
ROLE_MAX_LEVEL: dict[Role, RiskLevel] = {
    Role.VIEWER: RiskLevel.L0_INFO,
    Role.ANALYST: RiskLevel.L1_NET,
    Role.OPERATOR: RiskLevel.L3_EXPLOIT,
    Role.ADMIN: RiskLevel.L4_SYSTEM,
}

ROLE_LABELS: dict[Role, str] = {
    Role.VIEWER: "查看者 (仅情报查询)",
    Role.ANALYST: "分析师 (情报+网络信息)",
    Role.OPERATOR: "操作员 (扫描+漏洞验证)",
    Role.ADMIN: "管理员 (完全控制)",
}

# ============================================================
# 工具 → 风险等级映射 (覆盖全部 55+ 工具)
# ============================================================
TOOL_RISK_MAP: dict[str, RiskLevel] = {
    # ── L0: 只读情报查询 ──
    "cve_info": RiskLevel.L0_INFO,
    "cve_search": RiskLevel.L0_INFO,
    "cve_lookup": RiskLevel.L0_INFO,
    "cve_batch": RiskLevel.L0_INFO,
    "cvss_score": RiskLevel.L0_INFO,
    "cvss_calc": RiskLevel.L0_INFO,
    "cwe_info": RiskLevel.L0_INFO,
    "cwe_lookup": RiskLevel.L0_INFO,
    "cpe_search": RiskLevel.L0_INFO,
    "cpe_lookup": RiskLevel.L0_INFO,
    "cpe_match": RiskLevel.L0_INFO,
    "kev_check": RiskLevel.L0_INFO,
    "kev_latest": RiskLevel.L0_INFO,
    "epss_score": RiskLevel.L0_INFO,
    "exploit_search": RiskLevel.L0_INFO,
    "exploit_info": RiskLevel.L0_INFO,
    "threat_intel": RiskLevel.L0_INFO,
    "mitre_attack": RiskLevel.L0_INFO,
    "mitre_tactic": RiskLevel.L0_INFO,
    "cnvd_search": RiskLevel.L0_INFO,
    "cnvd_detail": RiskLevel.L0_INFO,
    "cnnvd_search": RiskLevel.L0_INFO,
    "cve_to_cnvd": RiskLevel.L0_INFO,
    "offline_mirror_status": RiskLevel.L0_INFO,
    "offline_mirror_query": RiskLevel.L0_INFO,
    "knowledge_graph": RiskLevel.L0_INFO,
    "graph_query": RiskLevel.L0_INFO,
    "neo4j_attack_paths": RiskLevel.L0_INFO,
    "neo4j_critical_assets": RiskLevel.L0_INFO,
    "verify_fix": RiskLevel.L0_INFO,
    "compliance_check": RiskLevel.L0_INFO,
    "correlate_assets": RiskLevel.L0_INFO,
    "report_generate": RiskLevel.L0_INFO,
    "audit_export": RiskLevel.L0_INFO,
    "project_list": RiskLevel.L0_INFO,
    "finding_list": RiskLevel.L0_INFO,
    "timeline_list": RiskLevel.L0_INFO,
    # ── L1: 网络信息收集 ──
    "dns_lookup": RiskLevel.L1_NET,
    "whois_lookup": RiskLevel.L1_NET,
    "ip_geolocation": RiskLevel.L1_NET,
    "check_http_headers": RiskLevel.L1_NET,
    "subdomain_enum": RiskLevel.L1_NET,
    "ssl_info": RiskLevel.L1_NET,
    # ── L2: 主动扫描 ──
    "scan_ports": RiskLevel.L2_SCAN,
    "service_detect": RiskLevel.L2_SCAN,
    "banner_grab": RiskLevel.L2_SCAN,
    "web_tech_detect": RiskLevel.L2_SCAN,
    "vulnerability_scan": RiskLevel.L2_SCAN,
    # ── L3: 漏洞测试 ──
    "search_exploit": RiskLevel.L3_EXPLOIT,
    "searchsploit": RiskLevel.L3_EXPLOIT,
    "generate_nuclei_cmd": RiskLevel.L3_EXPLOIT,
    "nuclei_scan": RiskLevel.L3_EXPLOIT,
    "msf_search": RiskLevel.L3_EXPLOIT,
    "msf_info": RiskLevel.L3_EXPLOIT,
    "poc_search": RiskLevel.L3_EXPLOIT,
    "run_exploit": RiskLevel.L3_EXPLOIT,
    # ── L4: 系统级 ──
    "exec_command": RiskLevel.L4_SYSTEM,
    "shell_exec": RiskLevel.L4_SYSTEM,
    "git_clone": RiskLevel.L4_SYSTEM,
    "file_read": RiskLevel.L4_SYSTEM,
    "config_edit": RiskLevel.L4_SYSTEM,
}

# 默认: 未映射的工具 → L3_EXPLOIT (保守)
DEFAULT_TOOL_RISK = RiskLevel.L3_EXPLOIT


@dataclass
class AccessDecision:
    """权限判定结果"""
    allowed: bool
    reason: str
    role: Role
    required_level: RiskLevel
    user_max_level: RiskLevel
    tool_name: str


@dataclass
class RBACConfig:
    """RBAC 配置"""
    default_role: Role = Role.OPERATOR
    enforce: bool = True                     # 是否强制执行
    auto_escalation: bool = False            # 是否允许自动提权
    escalation_approval_required: bool = True # 提权是否需要审批
    audit_access: bool = True                # 是否审计访问记录
    custom_tool_risk: dict[str, RiskLevel] = field(default_factory=dict)
    disabled_tools_for_role: dict[str, list[str]] = field(default_factory=dict)


class RBACManager:
    """RBAC 权限管理器"""

    def __init__(self, config: Optional[RBACConfig] = None):
        self.config = config or RBACConfig()
        self._tool_risk = dict(TOOL_RISK_MAP)
        self._tool_risk.update(self.config.custom_tool_risk)
        self._access_log: list[AccessDecision] = []
        self._current_role: Role = self.config.default_role
        self._role_confirmed: bool = False

    # ── 角色管理 ──

    @property
    def current_role(self) -> Role:
        return self._current_role

    def set_role(self, role: Role, confirmed: bool = False):
        """切换当前角色"""
        old = self._current_role
        self._current_role = role
        self._role_confirmed = confirmed
        logger.info(f"角色切换: {ROLE_LABELS[old]} → {ROLE_LABELS[role]} (已确认={confirmed})")

    def get_role_label(self) -> str:
        return ROLE_LABELS.get(self._current_role, "未知")

    def get_max_level(self, role: Optional[Role] = None) -> RiskLevel:
        r = role if role is not None else self._current_role
        return ROLE_MAX_LEVEL.get(r, RiskLevel.L0_INFO)

    # ── 工具风险 ──

    def get_tool_risk(self, tool_name: str) -> RiskLevel:
        """获取工具风险等级"""
        return self._tool_risk.get(tool_name, DEFAULT_TOOL_RISK)

    def get_tool_risk_label(self, tool_name: str) -> str:
        level = self.get_tool_risk(tool_name)
        return {
            RiskLevel.L0_INFO: "信息查询",
            RiskLevel.L1_NET: "网络收集",
            RiskLevel.L2_SCAN: "主动扫描",
            RiskLevel.L3_EXPLOIT: "漏洞测试",
            RiskLevel.L4_SYSTEM: "系统操作",
        }.get(level, "未知")

    def set_tool_risk(self, tool_name: str, level: RiskLevel):
        """自定义工具风险等级"""
        self._tool_risk[tool_name] = level
        logger.info(f"工具风险等级自定义: {tool_name} → {level.name}")

    # ── 权限检查 ──

    def check_access(self, tool_name: str, role: Optional[Role] = None) -> AccessDecision:
        """检查当前角色是否有权限调用工具"""
        r = role if role is not None else self._current_role
        required = self.get_tool_risk(tool_name)
        user_max = self.get_max_level(r)

        if not self.config.enforce:
            decision = AccessDecision(
                allowed=True,
                reason="RBAC 未启用",
                role=r,
                required_level=required,
                user_max_level=user_max,
                tool_name=tool_name,
            )
        elif required <= user_max:
            decision = AccessDecision(
                allowed=True,
                reason="权限允许",
                role=r,
                required_level=required,
                user_max_level=user_max,
                tool_name=tool_name,
            )
        else:
            decision = AccessDecision(
                allowed=False,
                reason=f"权限不足: {ROLE_LABELS[r]} 无法执行 {self.get_tool_risk_label(tool_name)} 操作 "
                       f"(需要 >= {required.name}, 当前最高 {user_max.name})",
                role=r,
                required_level=required,
                user_max_level=user_max,
                tool_name=tool_name,
            )

        # 审计
        if self.config.audit_access and not decision.allowed:
            self._access_log.append(decision)
            if len(self._access_log) > 1000:
                self._access_log = self._access_log[-500:]

        return decision

    # ── 角色特定禁用 ──

    def is_tool_disabled(self, tool_name: str, role: Optional[Role] = None) -> bool:
        """检查工具在指定角色下是否被禁用"""
        r = role if role is not None else self._current_role
        disabled = self.config.disabled_tools_for_role.get(r.name.lower(), [])
        return tool_name in disabled

    def disable_tool_for_role(self, tool_name: str, role: Role):
        """为指定角色禁用工具"""
        key = role.name.lower()
        if key not in self.config.disabled_tools_for_role:
            self.config.disabled_tools_for_role[key] = []
        if tool_name not in self.config.disabled_tools_for_role[key]:
            self.config.disabled_tools_for_role[key].append(tool_name)
            logger.info(f"已为 {ROLE_LABELS[role]} 禁用工具: {tool_name}")

    # ── 审计 ──

    def get_recent_denials(self, limit: int = 20) -> list[dict]:
        """获取最近的访问拒绝记录"""
        return [
            {"tool": d.tool_name, "role": d.role.name, "reason": d.reason}
            for d in self._access_log[-limit:] if not d.allowed
        ]

    def export_audit_log(self) -> list[dict]:
        return [
            {
                "tool": d.tool_name,
                "role": d.role.name,
                "allowed": d.allowed,
                "required_level": d.required_level.name,
                "user_max_level": d.user_max_level.name,
                "reason": d.reason,
            }
            for d in self._access_log
        ]

    # ── 摘要 ──

    def summary(self) -> dict:
        tools_by_risk = {}
        for tool, level in self._tool_risk.items():
            key = level.name
            if key not in tools_by_risk:
                tools_by_risk[key] = []
            tools_by_risk[key].append(tool)

        return {
            "current_role": self._current_role.name,
            "role_label": self.get_role_label(),
            "max_level": self.get_max_level().name,
            "total_tools": len(self._tool_risk),
            "tools_by_risk": {k: len(v) for k, v in tools_by_risk.items()},
            "denials_count": len([d for d in self._access_log if not d.allowed]),
            "enforce": self.config.enforce,
        }

    def to_config_dict(self) -> dict:
        return {
            "default_role": self.config.default_role.name,
            "enforce": self.config.enforce,
            "auto_escalation": self.config.auto_escalation,
            "audit_access": self.config.audit_access,
        }


# ============================================================
# 授权声明 — 启动时强制确认
# ============================================================

AUTHORIZATION_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║           ⚠️  授权声明 / Authorization Notice  ⚠️            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  本工具仅限在授权资产上进行安全测试。                           ║
║  未经授权扫描第三方资产属于违法行为。                           ║
║                                                              ║
║  使用本工具即表示您确认:                                       ║
║  1. 您拥有目标资产的合法测试授权                               ║
║  2. 您了解并遵守当地法律法规                                   ║
║  3. 您对使用本工具产生的后果承担全部责任                       ║
║                                                              ║
║  This tool is for authorized security testing only.          ║
║  Unauthorized scanning of third-party assets is illegal.     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


def check_authorization_confirmed() -> bool:
    """检查用户是否已确认授权声明"""
    env = os.environ.get("VULNRESEARCH_AUTHORIZED", "").lower()
    config_path = os.environ.get("VULNRESEARCH_CONFIG_PATH", "config.yaml")

    # 环境变量确认
    if env in ("1", "true", "yes"):
        return True

    # 配置文件确认标记
    try:
        if os.path.exists(config_path):
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            if cfg.get("authorization", {}).get("confirmed", False):
                return True
    except Exception:
        pass

    # 本地确认文件
    confirm_file = Path.home() / ".vulnresearch_authorized"
    if confirm_file.exists():
        return True

    return False


def confirm_authorization():
    """确认授权声明 — 创建确认标记文件"""
    confirm_file = Path.home() / ".vulnresearch_authorized"
    confirm_file.write_text(f"authorized_at={__import__('datetime').datetime.now().isoformat()}")
    logger.info("授权声明已确认")


# ============================================================
# 全局单例
# ============================================================

_rbac: Optional[RBACManager] = None


def get_rbac() -> RBACManager:
    global _rbac
    if _rbac is None:
        _rbac = RBACManager()
    return _rbac


def init_rbac(config: Optional[RBACConfig] = None) -> RBACManager:
    global _rbac
    _rbac = RBACManager(config)
    return _rbac
