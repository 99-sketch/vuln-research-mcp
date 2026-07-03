# src/security/target_policy.py
"""目标白名单与扫描策略控制 - 防止未授权扫描"""

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vuln-research-mcp.security")


@dataclass
class ScanLimitPolicy:
    """扫描限制策略"""
    # 速率限制
    max_concurrent_scans: int = 3      # 最大并发扫描数
    max_targets_per_scan: int = 50     # 单次扫描最大目标数
    max_ports_per_scan: int = 100      # 单次扫描最大端口数
    cooldown_seconds: int = 30         # 扫描冷却间隔

    # 范围限制
    scan_timeout_seconds: int = 300    # 单次扫描超时
    max_daily_scans: int = 100         # 每日最大扫描次数
    require_approval_batch: bool = True  # 批量扫描需审批

    # 网络限制
    allowed_networks: list[str] = field(default_factory=list)  # 允许扫描的网段
    deny_internet: bool = False        # 禁止扫描外网
    deny_private: bool = False         # 禁止扫描内网

    # 工具限制
    blocked_tools: list[str] = field(default_factory=list)  # 禁止执行的工具
    allowed_tools: list[str] = field(default_factory=list)   # 白名单工具（如果设置了）

    _scan_count_today: int = 0
    _last_scan_time: float = 0.0

    def can_scan(self) -> tuple[bool, str]:
        """检查是否可以发起扫描"""
        import time

        if self._scan_count_today >= self.max_daily_scans:
            return False, f"达到每日扫描上限 ({self.max_daily_scans})"

        if time.time() - self._last_scan_time < self.cooldown_seconds:
            remaining = int(self.cooldown_seconds - (time.time() - self._last_scan_time))
            return False, f"扫描冷却中，剩余 {remaining} 秒"

        return True, "ok"

    def record_scan(self) -> None:
        """记录一次扫描"""
        import time

        # 每日重置逻辑由外部控制，这里简单递增
        self._scan_count_today += 1
        self._last_scan_time = time.time()


@dataclass
class TargetPolicy:
    """目标策略 - 白名单/黑名单控制"""

    # 白名单模式（如果设置，只允许列表中的目标）
    whitelist_enabled: bool = False
    whitelist_targets: list[str] = field(default_factory=list)
    whitelist_networks: list[str] = field(default_factory=list)
    whitelist_domains: list[str] = field(default_factory=list)

    # 黑名单（明确禁止的目标）
    blacklist_targets: list[str] = field(default_factory=lambda: [
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
    ])
    blacklist_networks: list[str] = field(default_factory=lambda: [
        "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    ])
    blacklist_domains: list[str] = field(default_factory=list)

    # 内网策略
    allow_private_ips: bool = True     # 是否允许扫描内网
    allow_public_ips: bool = True      # 是否允许扫描外网

    # 域名后缀限制
    allowed_tlds: list[str] = field(default_factory=list)  # 允许的顶级域名
    blocked_tlds: list[str] = field(default_factory=list)   # 禁止的顶级域名

    def check_target(self, target: str) -> tuple[bool, str]:
        """检查目标是否允许扫描

        Returns:
            (is_allowed, reason)
        """
        if not target:
            return False, "目标不能为空"

        target = target.strip().lower()

        # 1. 黑名单精确匹配
        if target in self.blacklist_targets:
            return False, f"目标 {target} 在黑名单中"

        # 2. 黑名单域名
        for blocked in self.blacklist_domains:
            if target == blocked or target.endswith(f".{blocked}"):
                return False, f"目标域名 {target} 在域名黑名单中"

        # 3. 白名单检查（如果启用）
        if self.whitelist_enabled:
            if target not in self.whitelist_targets:
                # 检查 IP 白名单网段
                in_whitelist = False
                try:
                    addr = ipaddress.ip_address(target)
                    for net in self.whitelist_networks:
                        if addr in ipaddress.ip_network(net, strict=False):
                            in_whitelist = True
                            break
                except ValueError:
                    # 域名：检查后缀匹配
                    for domain in self.whitelist_domains:
                        if target == domain or target.endswith(f".{domain}"):
                            in_whitelist = True
                            break

                if not in_whitelist:
                    return False, f"目标 {target} 不在白名单中"

        # 4. IP 网段黑名单检查
        try:
            addr = ipaddress.ip_address(target)

            # 内网策略
            if addr.is_private and not self.allow_private_ips:
                return False, f"目标 {target} 是内网地址，不允许扫描"
            if not (addr.is_private or addr.is_loopback or addr.is_link_local) and not self.allow_public_ips:
                return False, f"目标 {target} 是公网地址，不允许扫描"

            # 黑名单网段
            for net_str in self.blacklist_networks:
                if addr in ipaddress.ip_network(net_str, strict=False):
                    return False, f"目标 {target} 在禁止网段 {net_str}"

        except ValueError:
            pass  # 不是 IP，跳过 IP 检查

        # 5. TLD 检查
        if self.allowed_tlds or self.blocked_tlds:
            # 提取 TLD
            parts = target.rsplit(".", 1)
            if len(parts) == 2:
                tld = parts[1]
                if self.allowed_tlds and tld not in self.allowed_tlds:
                    return False, f"顶级域名 .{tld} 不在允许列表中"
                if tld in self.blocked_tlds:
                    return False, f"顶级域名 .{tld} 在禁止列表中"

        return True, "ok"

    def add_to_whitelist(self, target: str) -> None:
        """添加目标到白名单"""
        target = target.strip().lower()
        if target not in self.whitelist_targets:
            self.whitelist_targets.append(target)
            logger.info(f"白名单添加目标: {target}")

    @classmethod
    def from_config_file(cls, path: str) -> "TargetPolicy":
        """从配置文件加载目标策略"""
        if not os.path.exists(path):
            logger.warning(f"目标策略文件不存在: {path}，使用默认策略")
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls(
            whitelist_enabled=data.get("whitelist_enabled", False),
            whitelist_targets=data.get("whitelist_targets", []),
            whitelist_networks=data.get("whitelist_networks", []),
            whitelist_domains=data.get("whitelist_domains", []),
            blacklist_targets=data.get("blacklist_targets", cls.blacklist_targets),
            blacklist_networks=data.get("blacklist_networks", cls.blacklist_networks),
            blacklist_domains=data.get("blacklist_domains", []),
            allow_private_ips=data.get("allow_private_ips", True),
            allow_public_ips=data.get("allow_public_ips", True),
            allowed_tlds=data.get("allowed_tlds", []),
            blocked_tlds=data.get("blocked_tlds", []),
        )


def create_default_policy() -> TargetPolicy:
    """创建默认安全策略（适合个人研究使用）

    允许内网/外网扫描，但禁止已知危险目标。
    """
    return TargetPolicy(
        whitelist_enabled=False,
        allow_private_ips=True,
        allow_public_ips=True,
    )


def create_enterprise_policy(allowed_nets: list[str] = None) -> TargetPolicy:
    """创建企业级策略（仅允许指定网段扫描）

    Args:
        allowed_nets: 允许扫描的网段列表，如 ["10.0.0.0/8", "192.168.1.0/24"]
    """
    policy = TargetPolicy(
        whitelist_enabled=True,
        allow_private_ips=True,
        allow_public_ips=False,
        whitelist_networks=allowed_nets or [],
    )
    return policy
