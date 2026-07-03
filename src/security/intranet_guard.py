# src/security/intranet_guard.py
"""内网防护模块 v5.1 — 全 RFC 1918 阻断 + 敏感端口告警 + 扫描范围强制限制

默认策略 (最高安全):
    - 阻断所有 RFC 1918 私有地址段 (10/8, 172.16/12, 192.168/16)
    - 阻断所有 CGNAT 地址段 (100.64/10)
    - 阻断所有特殊用途地址段 (127/8, 169.254/16, 224/4, 240/4)
    - 阻断云 metadata IP (169.254.169.254, 100.100.100.200)
    - 单次扫描: 最多 50 目标, 100 端口, 300s 超时
    - 每日扫描: 最多 100 次
    - 冷却间隔: 30s
    - 敏感端口需要审批 (22, 3389, 1433, 3306, 5432, 6379, 27017, 9200, 11211)

白名单模式:
    - 可以按 IP/CIDR/域名在配置中显式开放内网目标
    - 允许临时审批通过 (unlock_target 接口)
    - 所有审计日志自动写入
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time as _time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vuln-research-mcp.intranet_guard")

# ============================================================================
# 一、地址段定义 — 全部 RFC 标准私有/特殊用途地址
# ============================================================================

class NetworkCategory(Enum):
    """网络地址类别"""
    PRIVATE_IPV4 = auto()       # RFC 1918 私有地址
    CGNAT = auto()              # 运营商级 NAT
    LOOPBACK = auto()           # 回环
    LINK_LOCAL = auto()         # 链路本地
    MULTICAST = auto()           # 组播
    RESERVED = auto()            # 保留
    BENCHMARK = auto()           # 基准测试
    DOCUMENTATION = auto()       # 文档用途
    CLOUD_METADATA = auto()      # 云 metadata
    PUBLIC = auto()              # 公网

# RFC 1918 私有地址
PRIVATE_IPV4_RANGES: List[Tuple[str, str, str]] = [
    ("10.0.0.0/8", "RFC 1918 — Class A 私有地址", "PRIVATE"),
    ("172.16.0.0/12", "RFC 1918 — Class B 私有地址", "PRIVATE"),
    ("192.168.0.0/16", "RFC 1918 — Class C 私有地址", "PRIVATE"),
]

# CGNAT (运营商级 NAT)
CGNAT_RANGES: List[Tuple[str, str, str]] = [
    ("100.64.0.0/10", "RFC 6598 — CGNAT 共享地址空间", "CGNAT"),
]

# 回环地址
LOOPBACK_RANGES: List[Tuple[str, str, str]] = [
    ("127.0.0.0/8", "RFC 1122 — Loopback", "LOOPBACK"),
    ("::1/128", "IPv6 Loopback", "LOOPBACK"),
]

# 链路本地
LINK_LOCAL_RANGES: List[Tuple[str, str, str]] = [
    ("169.254.0.0/16", "RFC 3927 — 链路本地地址", "LINK_LOCAL"),
    ("fe80::/10", "IPv6 链路本地", "LINK_LOCAL"),
]

# 组播
MULTICAST_RANGES: List[Tuple[str, str, str]] = [
    ("224.0.0.0/4", "IPv4 组播", "MULTICAST"),
    ("ff00::/8", "IPv6 组播", "MULTICAST"),
]

# 保留/特殊用途
RESERVED_RANGES: List[Tuple[str, str, str]] = [
    ("0.0.0.0/8", "IANA — 本网络", "RESERVED"),
    ("240.0.0.0/4", "RFC 1112 — 保留", "RESERVED"),
    ("255.255.255.255/32", "全网广播", "RESERVED"),
]

# 文档/示例 (RFC 5737)
DOCUMENTATION_RANGES: List[Tuple[str, str, str]] = [
    ("192.0.2.0/24", "RFC 5737 — TEST-NET-1", "DOCUMENTATION"),
    ("198.51.100.0/24", "RFC 5737 — TEST-NET-2", "DOCUMENTATION"),
    ("203.0.113.0/24", "RFC 5737 — TEST-NET-3", "DOCUMENTATION"),
]

# 基准测试 (RFC 2544)
BENCHMARK_RANGES: List[Tuple[str, str, str]] = [
    ("198.18.0.0/15", "RFC 2544 — 基准测试", "BENCHMARK"),
]

# 云 metadata IP
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",       # AWS / GCP / Azure
    "100.100.100.200",       # Alibaba Cloud
    "100.64.0.1",            # 部分云环境
}

CLOUD_METADATA_HOSTS: Set[str] = {
    "metadata.google.internal",
    "metadata.tencentyun.com",
    "100.100.100.200",       # Alibaba Cloud metadata
}

# ============================================================================
# 二、敏感端口定义
# ============================================================================

# 敏感端口 — 扫描这些端口需要额外审批
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH — 远程管理",
    23: "Telnet — 明文远程管理",
    3389: "RDP — Windows 远程桌面",
    5900: "VNC — 远程桌面",
    1433: "MS-SQL — 数据库",
    1521: "Oracle DB — 数据库",
    3306: "MySQL — 数据库",
    5432: "PostgreSQL — 数据库",
    27017: "MongoDB — 数据库",
    6379: "Redis — 缓存/数据库",
    11211: "Memcached — 缓存",
    9200: "Elasticsearch — 搜索引擎",
    9300: "Elasticsearch — 集群通信",
    5601: "Kibana — 可视化",
    8080: "HTTP 代理/管理面板",
    8443: "HTTPS 管理面板",
    9090: "Prometheus — 监控",
    3000: "Grafana — 监控面板",
    5000: "Docker Registry",
    2375: "Docker API (无 TLS)",
    2376: "Docker API (TLS)",
    6443: "Kubernetes API",
    10250: "Kubelet API",
}

# ============================================================================
# 三、扫描范围限制策略
# ============================================================================

@dataclass
class ScanLimitPolicy:
    """扫描范围强制限制"""

    # 单次扫描限制
    max_targets_per_scan: int = 50        # 单次最多 50 个目标
    max_ports_per_scan: int = 1000        # 单次最多 1000 个端口
    max_port_range_span: int = 1000       # 端口范围跨度不超过 1000
    scan_timeout_seconds: int = 300       # 单次扫描超时 5 分钟

    # 速率限制
    max_concurrent_scans: int = 3         # 最大并发 3 个扫描
    cooldown_seconds: int = 30            # 扫描冷却 30 秒
    max_daily_scans: int = 100             # 每日最多 100 次
    max_hourly_scans: int = 20            # 每小时最多 20 次

    # 审批要求
    require_approval_batch: bool = True    # 批量扫描需要审批
    require_approval_sensitive_ports: bool = True  # 敏感端口需要审批
    require_approval_intranet: bool = True  # 内网扫描需要审批

    # 运行时计数器
    _scan_count_hour: int = 0
    _scan_count_day: int = 0
    _last_scan_time: float = 0.0
    _hour_start: float = 0.0
    _active_scans: int = 0
    _intranet_locks: Set[str] = field(default_factory=set)

    def can_scan(self, target_count: int = 1,
                 port_count: int = 1,
                 is_intranet: bool = False) -> Tuple[bool, str]:
        """检查是否可以发起扫描

        Returns:
            (allowed, reason)
        """
        now = _time.time()

        # 目标/端口数量限制
        if target_count > self.max_targets_per_scan:
            return False, f"目标数 {target_count} 超过上限 {self.max_targets_per_scan}"
        if port_count > self.max_ports_per_scan:
            return False, f"端口数 {port_count} 超过上限 {self.max_ports_per_scan}"

        # 并发限制
        if self._active_scans >= self.max_concurrent_scans:
            return False, f"并发扫描已达上限 ({self.max_concurrent_scans})"

        # 小时复位
        if now - self._hour_start > 3600:
            self._hour_start = now
            self._scan_count_hour = 0

        # 每日限制 (简单: 24h 窗口)
        if self._scan_count_day >= self.max_daily_scans:
            return False, f"每日扫描已达上限 ({self.max_daily_scans})"

        # 每小时限制
        if self._scan_count_hour >= self.max_hourly_scans:
            wait = 3600 - (now - self._hour_start)
            return False, f"每小时扫描已达上限 ({self.max_hourly_scans}), 需等待 {int(wait)}秒"

        # 冷却
        since_last = now - self._last_scan_time
        if since_last < self.cooldown_seconds:
            remaining = int(self.cooldown_seconds - since_last)
            return False, f"冷却中, 剩余 {remaining} 秒"

        return True, "ok"

    def record_scan(self, is_intranet: bool = False) -> None:
        """记录一次扫描"""
        now = _time.time()
        self._scan_count_hour += 1
        self._scan_count_day += 1
        self._last_scan_time = now
        self._active_scans += 1

        if is_intranet:
            logger.warning("内网扫描已记录 — 审计关键事件")

    def scan_complete(self) -> None:
        """扫描完成"""
        self._active_scans = max(0, self._active_scans - 1)

    def lock_intranet_target(self, target: str) -> None:
        """锁定内网目标 (已被审批放行)"""
        self._intranet_locks.add(target)
        logger.info(f"内网目标审批通过: {target}")

    def is_intranet_locked(self, target: str) -> bool:
        """检查内网目标是否已被审批放行"""
        return target in self._intranet_locks


# ============================================================================
# 四、目标策略 (增强版)
# ============================================================================

@dataclass
class IntranetGuardPolicy:
    """内网防护策略"""

    # 网络类别默认策略
    block_private_ipv4: bool = True         # 默认阻断 RFC 1918
    block_cgnat: bool = True                # 默认阻断 CGNAT
    block_loopback: bool = True             # 默认阻断回环
    block_link_local: bool = True           # 默认阻断链路本地
    block_multicast: bool = True            # 默认阻断组播
    block_reserved: bool = True             # 默认阻断保留地址
    block_benchmark: bool = True            # 默认阻断基准测试
    block_documentation: bool = True        # 默认阻断文档地址
    block_cloud_metadata: bool = True       # 默认阻断云 metadata

    # 白名单 — 显式放行的内网地址/CIDR/域名
    whitelist_enabled: bool = False
    whitelist_ips: Set[str] = field(default_factory=set)       # "10.0.1.5"
    whitelist_cidrs: List[str] = field(default_factory=list)   # "10.0.1.0/24"
    whitelist_domains: Set[str] = field(default_factory=set)   # "internal.corp.com"

    # 黑名单 (明确禁止, 即使在白名单中也不行)
    blacklist_ips: Set[str] = field(default_factory=lambda: {
        "127.0.0.1", "::1", "0.0.0.0", "[::1]",
    })
    blacklist_cidrs: List[str] = field(default_factory=list)
    blacklist_domains: Set[str] = field(default_factory=lambda: {
        "localhost", "metadata.google.internal",
    })

    # 域名策略
    allowed_tlds: Set[str] = field(default_factory=set)   # 允许的 TLD (空=全部)
    blocked_tlds: Set[str] = field(default_factory=set)   # 禁止的 TLD

    # 敏感端口策略
    block_sensitive_ports_without_approval: bool = True
    sensitive_port_whitelist: Set[int] = field(default_factory=set)  # 放行的敏感端口

    # 审批回调
    approval_callback: Optional[Callable[[str, str], bool]] = None

    def check_target(self, target: str,
                     ports: Optional[List[int]] = None,
                     require_approval: bool = False) -> Tuple[bool, str, str]:
        """检查目标是否允许扫描 (三级返回)

        Args:
            target: IP 地址、域名 或 CIDR
            ports: 端口列表
            require_approval: 是否需要审批

        Returns:
            (allowed, reason, category)
                category: "public", "intranet_blocked", "intranet_allowed",
                         "sensitive_port", "blacklisted", "approved"
        """
        if not target:
            return False, "目标不能为空", "blacklisted"

        target = target.strip().lower()
        if not target:
            return False, "目标为空白", "blacklisted"

        # 0. 黑名单检查 (最高优先级)
        if target in self.blacklist_ips:
            return False, f"目标 {target} 在 IP 黑名单中", "blacklisted"
        if target in self.blacklist_domains:
            return False, f"目标 {target} 在域名黑名单中", "blacklisted"
        for cidr in self.blacklist_cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ipaddress.ip_address(target) in net:
                    return False, f"目标 {target} 在 CIDR 黑名单 {cidr}", "blacklisted"
            except ValueError:
                pass

        # 1. IP 地址分类检查
        try:
            addr = ipaddress.ip_address(target)
            category = self._classify_ip(addr)

            if category == NetworkCategory.PUBLIC:
                # 公网 IP — 直接放行
                pass
            elif category == NetworkCategory.CLOUD_METADATA:
                return False, f"禁止扫描云 metadata 地址: {target}", "blacklisted"
            else:
                # 非公网地址 — 检查是否放行
                if not self._is_network_category_allowed(category):
                    return False, f"禁止 {category.name}: {target}", "intranet_blocked"

                # 检查白名单 (如果配置了)
                if self.whitelist_enabled:
                    if target not in self.whitelist_ips:
                        in_cidr = False
                        for cidr in self.whitelist_cidrs:
                            try:
                                if addr in ipaddress.ip_network(cidr, strict=False):
                                    in_cidr = True
                                    break
                            except ValueError:
                                pass
                        if not in_cidr:
                            return False, f"目标 {target} 不在内网白名单中", "intranet_blocked"

                # 审批要求
                if require_approval and self.whitelist_enabled:
                    if self.approval_callback:
                        if not self.approval_callback(target, "内网目标扫描"):
                            return False, f"内网目标 {target} 未通过审批", "intranet_blocked"
                    return True, "内网目标已审批通过", "approved"

                return True, "ok", "intranet_allowed"

        except ValueError:
            # 非 IP: 域名检查
            pass

        # 2. 域名检查
        if target in ("localhost",):
            return False, f"禁止扫描: {target}", "blacklisted"

        # TLD 检查
        if '.' in target:
            tld = target.rsplit('.', 1)[-1]
            if self.allowed_tlds and tld not in self.allowed_tlds:
                return False, f"TLD .{tld} 不在允许列表中", "blacklisted"
            if tld in self.blocked_tlds:
                return False, f"TLD .{tld} 在禁止列表中", "blacklisted"

        # 3. 端口检查
        if ports and self.block_sensitive_ports_without_approval:
            for port in ports:
                if port in SENSITIVE_PORTS and port not in self.sensitive_port_whitelist:
                    if require_approval:
                        return False, f"端口 {port} ({SENSITIVE_PORTS[port]}) 需要审批", "sensitive_port"
                    else:
                        return False, f"端口 {port} ({SENSITIVE_PORTS[port]}) 是敏感端口，默认禁止", "sensitive_port"

        return True, "ok", "public"

    @staticmethod
    def _classify_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> NetworkCategory:
        """分类 IP 地址"""
        if addr.is_private:
            return NetworkCategory.PRIVATE_IPV4
        if addr.is_loopback:
            return NetworkCategory.LOOPBACK
        if addr.is_link_local:
            return NetworkCategory.LINK_LOCAL
        if addr.is_multicast:
            return NetworkCategory.MULTICAST
        if addr.is_reserved:
            # 细化 reserved
            if addr in ipaddress.ip_network("0.0.0.0/8"):
                return NetworkCategory.RESERVED
            if addr in ipaddress.ip_network("240.0.0.0/4"):
                return NetworkCategory.RESERVED
            return NetworkCategory.RESERVED

        # CGNAT
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            return NetworkCategory.CGNAT

        # 基准测试
        if addr in ipaddress.ip_network("198.18.0.0/15"):
            return NetworkCategory.BENCHMARK

        # 文档
        if (addr in ipaddress.ip_network("192.0.2.0/24") or
            addr in ipaddress.ip_network("198.51.100.0/24") or
            addr in ipaddress.ip_network("203.0.113.0/24")):
            return NetworkCategory.DOCUMENTATION

        # 云 metadata
        if str(addr) in CLOUD_METADATA_IPS:
            return NetworkCategory.CLOUD_METADATA

        return NetworkCategory.PUBLIC

    def _is_network_category_allowed(self, category: NetworkCategory) -> bool:
        """检查网络类别是否允许"""
        category_map = {
            NetworkCategory.PRIVATE_IPV4: not self.block_private_ipv4,
            NetworkCategory.CGNAT: not self.block_cgnat,
            NetworkCategory.LOOPBACK: not self.block_loopback,
            NetworkCategory.LINK_LOCAL: not self.block_link_local,
            NetworkCategory.MULTICAST: not self.block_multicast,
            NetworkCategory.RESERVED: not self.block_reserved,
            NetworkCategory.BENCHMARK: not self.block_benchmark,
            NetworkCategory.DOCUMENTATION: not self.block_documentation,
            NetworkCategory.CLOUD_METADATA: not self.block_cloud_metadata,
            NetworkCategory.PUBLIC: True,
        }
        return category_map.get(category, True)

    def add_whitelist_ip(self, ip: str) -> None:
        """添加 IP 到白名单"""
        try:
            validated = str(ipaddress.ip_address(ip))
            self.whitelist_ips.add(validated)
            logger.info(f"IP 白名单添加: {validated}")
        except ValueError:
            raise ValueError(f"无效 IP 地址: {ip}")

    def add_whitelist_cidr(self, cidr: str) -> None:
        """添加 CIDR 网段到白名单"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            if cidr not in self.whitelist_cidrs:
                self.whitelist_cidrs.append(cidr)
                logger.info(f"CIDR 白名单添加: {cidr}")
        except ValueError:
            raise ValueError(f"无效 CIDR 格式: {cidr}")

    def to_dict(self) -> Dict[str, Any]:
        """导出配置为字典"""
        return {
            "block_private_ipv4": self.block_private_ipv4,
            "block_cgnat": self.block_cgnat,
            "block_loopback": self.block_loopback,
            "block_link_local": self.block_link_local,
            "block_multicast": self.block_multicast,
            "block_reserved": self.block_reserved,
            "block_benchmark": self.block_benchmark,
            "block_documentation": self.block_documentation,
            "block_cloud_metadata": self.block_cloud_metadata,
            "whitelist_enabled": self.whitelist_enabled,
            "whitelist_ips": sorted(self.whitelist_ips),
            "whitelist_cidrs": self.whitelist_cidrs,
            "whitelist_domains": sorted(self.whitelist_domains),
            "blacklist_ips": sorted(self.blacklist_ips),
            "blacklist_cidrs": self.blacklist_cidrs,
            "allowed_tlds": sorted(self.allowed_tlds),
            "blocked_tlds": sorted(self.blocked_tlds),
            "sensitive_ports": dict(SENSITIVE_PORTS),
            "block_sensitive_ports_without_approval": self.block_sensitive_ports_without_approval,
        }

    @classmethod
    def create_default(cls) -> "IntranetGuardPolicy":
        """创建默认策略 — 阻断所有内网/特殊地址, 仅允许公网"""
        return cls()

    @classmethod
    def create_permissive(cls) -> "IntranetGuardPolicy":
        """创建宽松策略 — 允许内网, 但保留基本防护"""
        return cls(
            block_private_ipv4=False,
            block_cgnat=False,
            block_loopback=True,       # 仍然阻断回环
            block_link_local=True,      # 仍然阻断链路本地
            block_multicast=True,        # 仍然阻断组播
            block_reserved=True,
            block_cloud_metadata=True,
        )

    @classmethod
    def create_enterprise(cls, allowed_cidrs: List[str],
                          allowed_domains: Optional[List[str]] = None) -> "IntranetGuardPolicy":
        """创建企业策略 — 仅允许指定网段和域名"""
        policy = cls(
            whitelist_enabled=True,
        )
        for cidr in allowed_cidrs:
            policy.add_whitelist_cidr(cidr)
        if allowed_domains:
            policy.whitelist_domains.update(allowed_domains)
        return policy

    @classmethod
    def from_config_file(cls, path: str) -> "IntranetGuardPolicy":
        """从 JSON 配置文件加载"""
        if not os.path.exists(path):
            logger.warning(f"内网防护配置不存在: {path}, 使用默认阻断策略")
            return cls.create_default()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        policy = cls(
            block_private_ipv4=data.get("block_private_ipv4", True),
            block_cgnat=data.get("block_cgnat", True),
            block_loopback=data.get("block_loopback", True),
            block_link_local=data.get("block_link_local", True),
            block_multicast=data.get("block_multicast", True),
            block_reserved=data.get("block_reserved", True),
            block_benchmark=data.get("block_benchmark", True),
            block_documentation=data.get("block_documentation", True),
            block_cloud_metadata=data.get("block_cloud_metadata", True),
            whitelist_enabled=data.get("whitelist_enabled", False),
            block_sensitive_ports_without_approval=data.get("block_sensitive_ports_without_approval", True),
        )

        for ip in data.get("whitelist_ips", []):
            policy.whitelist_ips.add(ip)
        policy.whitelist_cidrs = data.get("whitelist_cidrs", [])
        for dom in data.get("whitelist_domains", []):
            policy.whitelist_domains.add(dom)
        for ip in data.get("blacklist_ips", []):
            policy.blacklist_ips.add(ip)
        policy.blacklist_cidrs = data.get("blacklist_cidrs", [])
        policy.allowed_tlds = set(data.get("allowed_tlds", []))
        policy.blocked_tlds = set(data.get("blocked_tlds", []))

        return policy


# ============================================================================
# 五、便捷函数
# ============================================================================

def get_sensitive_port_names(ports: List[int]) -> List[str]:
    """获取端口列表中的敏感端口名称"""
    return [f"{p} ({SENSITIVE_PORTS[p]})" for p in ports if p in SENSITIVE_PORTS]


def is_intranet_ip(ip_str: str) -> bool:
    """快速判断是否为内网 IP"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_cloud_metadata_ip(ip_str: str) -> bool:
    """判断是否为云 metadata IP"""
    return ip_str in CLOUD_METADATA_IPS


# 全局单例
_global_intranet_guard: Optional[IntranetGuardPolicy] = None
_global_scan_limits: Optional[ScanLimitPolicy] = None


def get_intranet_guard() -> IntranetGuardPolicy:
    global _global_intranet_guard
    if _global_intranet_guard is None:
        _global_intranet_guard = IntranetGuardPolicy.create_default()
    return _global_intranet_guard


def get_scan_limits() -> ScanLimitPolicy:
    global _global_scan_limits
    if _global_scan_limits is None:
        _global_scan_limits = ScanLimitPolicy()
    return _global_scan_limits
