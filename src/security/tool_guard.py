# src/security/tool_guard.py
"""工具权限控制 - RBAC 分级 + 工具哈希校验 + 调用频率限制"""

import hashlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("vuln-research-mcp.security")


class ToolRiskLevel(Enum):
    """工具风险等级"""
    READ_ONLY = "read_only"     # 只读情报查询（CVE 搜索、情报检索）
    NETWORK_INFO = "network_info"  # 网络信息收集（DNS 查询、WHOIS、HTTP 头）
    ACTIVE_SCAN = "active_scan"  # 主动扫描（端口扫描、子域名枚举）
    EXPLOIT = "exploit"         # 漏洞利用（Metasploit、Exploit-DB）
    SYSTEM = "system"           # 系统操作（git clone、文件读写）


# 工具风险等级映射表
TOOL_RISK_MAP: dict[str, ToolRiskLevel] = {
    # 只读情报
    "search_cve": ToolRiskLevel.READ_ONLY,
    "get_cve_details": ToolRiskLevel.READ_ONLY,
    "calculate_cvss": ToolRiskLevel.READ_ONLY,
    "query_cwe": ToolRiskLevel.READ_ONLY,
    "check_kev": ToolRiskLevel.READ_ONLY,
    "search_kev": ToolRiskLevel.READ_ONLY,
    "get_epss_score": ToolRiskLevel.READ_ONLY,
    "vulnerability_assess": ToolRiskLevel.READ_ONLY,
    "cross_source_search": ToolRiskLevel.READ_ONLY,
    "search_cpe": ToolRiskLevel.READ_ONLY,
    "query_knowledge_graph": ToolRiskLevel.READ_ONLY,
    "get_technique": ToolRiskLevel.READ_ONLY,

    # 网络信息
    "query_dns": ToolRiskLevel.NETWORK_INFO,
    "fetch_http_headers": ToolRiskLevel.NETWORK_INFO,
    "geolocate_ip": ToolRiskLevel.NETWORK_INFO,
    "reverse_dns": ToolRiskLevel.NETWORK_INFO,

    # 主动扫描
    "scan_ports": ToolRiskLevel.ACTIVE_SCAN,
    "enumerate_subdomains": ToolRiskLevel.ACTIVE_SCAN,
    "generate_nuclei_command": ToolRiskLevel.ACTIVE_SCAN,

    # 漏洞利用/EXP
    "search_exploit": ToolRiskLevel.EXPLOIT,
    "search_metasploit": ToolRiskLevel.EXPLOIT,
    "search_sploit": ToolRiskLevel.EXPLOIT,
    "find_nuclei_template": ToolRiskLevel.EXPLOIT,

    # 系统操作
    "search_poc_archive": ToolRiskLevel.SYSTEM,
    "clone_poc_archive": ToolRiskLevel.SYSTEM,
    "update_poc_archive": ToolRiskLevel.SYSTEM,
    "list_poc_archives": ToolRiskLevel.SYSTEM,

    # v4.0 工具
    "generate_pentest_report": ToolRiskLevel.READ_ONLY,
    "run_pipeline": ToolRiskLevel.ACTIVE_SCAN,
    "list_pipelines": ToolRiskLevel.READ_ONLY,
}


@dataclass
class RateLimitEntry:
    """频率限制条目"""
    count: int = 0
    window_start: float = field(default_factory=time.time)


class ToolGuard:
    """工具安全守卫

    职责：
    - 工具风险等级管理
    - 调用频率限制
    - 工具哈希校验（防篡改）
    - 按风险等级过滤可用工具
    """

    def __init__(self, max_risk_level: ToolRiskLevel = ToolRiskLevel.SYSTEM):
        self._max_risk_level = max_risk_level
        self._rate_limits: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._tool_hashes: dict[str, str] = {}

        # 频率限制配置
        self._rate_config: dict[ToolRiskLevel, tuple[int, int]] = {
            ToolRiskLevel.READ_ONLY: (100, 60),     # 100 次/分钟
            ToolRiskLevel.NETWORK_INFO: (30, 60),    # 30 次/分钟
            ToolRiskLevel.ACTIVE_SCAN: (5, 60),      # 5 次/分钟
            ToolRiskLevel.EXPLOIT: (3, 60),          # 3 次/分钟
            ToolRiskLevel.SYSTEM: (5, 60),           # 5 次/分钟
        }

    def get_risk_level(self, tool_name: str) -> ToolRiskLevel:
        """获取工具风险等级"""
        return TOOL_RISK_MAP.get(tool_name, ToolRiskLevel.READ_ONLY)

    def is_allowed(self, tool_name: str) -> tuple[bool, str]:
        """检查工具是否允许执行

        Returns:
            (is_allowed, reason)
        """
        risk = self.get_risk_level(tool_name)

        # 等级检查
        risk_order = [
            ToolRiskLevel.READ_ONLY,
            ToolRiskLevel.NETWORK_INFO,
            ToolRiskLevel.ACTIVE_SCAN,
            ToolRiskLevel.EXPLOIT,
            ToolRiskLevel.SYSTEM,
        ]
        max_idx = risk_order.index(self._max_risk_level)
        current_idx = risk_order.index(risk)

        if current_idx > max_idx:
            return False, f"工具 {tool_name} 风险等级 ({risk.value}) 超出当前允许 ({self._max_risk_level.value})"

        # 频率限制
        if not self._check_rate_limit(tool_name, risk):
            return False, f"工具 {tool_name} 调用频率超限"

        return True, "ok"

    def _check_rate_limit(self, tool_name: str, risk_level: ToolRiskLevel) -> bool:
        """检查频率限制"""
        now = time.time()
        entry = self._rate_limits[tool_name]
        max_count, window = self._rate_config.get(risk_level, (10, 60))

        if now - entry.window_start > window:
            # 新窗口
            entry.count = 0
            entry.window_start = now

        entry.count += 1
        if entry.count > max_count:
            logger.warning(f"工具 {tool_name} 调用频率超限: {entry.count}/{max_count} per {window}s")
            return False

        return True

    def _update_rate_limit(self, tool_name: str) -> None:
        """更新频率限制计数（调用 is_allowed 时已在 _check_rate_limit 中更新）"""
        pass

    def set_max_risk_level(self, level: ToolRiskLevel) -> None:
        """设置最大允许的风险等级"""
        self._max_risk_level = level
        logger.info(f"工具最大风险等级设置为: {level.value}")

    def compute_tool_hash(self, tool_name: str, tool_schema: dict) -> str:
        """计算工具定义哈希（用于防篡改校验）"""
        schema_str = json.dumps(tool_schema, sort_keys=True, ensure_ascii=False)
        hash_val = hashlib.sha256(schema_str.encode()).hexdigest()
        self._tool_hashes[tool_name] = hash_val
        return hash_val

    def verify_tool_hash(self, tool_name: str, tool_schema: dict) -> bool:
        """校验工具定义哈希"""
        stored = self._tool_hashes.get(tool_name)
        if stored is None:
            return True  # 无存储哈希，不校验
        current = hashlib.sha256(
            json.dumps(tool_schema, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        return stored == current

    def filter_tools(
        self, tools: list[dict], max_level: Optional[ToolRiskLevel] = None
    ) -> list[dict]:
        """按风险等级过滤工具列表"""
        level = max_level or self._max_risk_level
        risk_order = [
            ToolRiskLevel.READ_ONLY,
            ToolRiskLevel.NETWORK_INFO,
            ToolRiskLevel.ACTIVE_SCAN,
            ToolRiskLevel.EXPLOIT,
            ToolRiskLevel.SYSTEM,
        ]
        max_idx = risk_order.index(level)

        filtered = []
        for tool in tools:
            tool_name = tool.get("name", "")
            tool_risk = self.get_risk_level(tool_name)
            tool_idx = risk_order.index(tool_risk)
            if tool_idx <= max_idx:
                filtered.append(tool)

        return filtered

    def get_all_valid_scanners(self) -> list[str]:
        """获取所有允许的扫描工具名称"""
        return [
            name for name, risk in TOOL_RISK_MAP.items()
            if risk.value in ("active_scan", "exploit")
        ]


# 全局实例
_tool_guard: Optional[ToolGuard] = None


def create_tool_guard(max_risk_level: ToolRiskLevel = ToolRiskLevel.SYSTEM) -> ToolGuard:
    """创建或获取全局工具守卫"""
    global _tool_guard
    if _tool_guard is None:
        _tool_guard = ToolGuard(max_risk_level)
    return _tool_guard


def get_tool_guard() -> Optional[ToolGuard]:
    """获取当前工具守卫"""
    return _tool_guard
