# src/security/target_authorization.py
"""合规 — 内置目标白名单 + 授权校验 + 审计日志

v5.3: 所有扫描/探测操作前强制校验目标是否在白名单内。

架构:
  白名单来源: config.yaml + 环境变量 + 动态运行时 API
  校验层:    IP/CIDR/域名精确匹配 + 通配符 + 自动解析
  阻断:      非授权目标 → AccessDenied + 审计日志 + 可选告警
  豁免:      情报查询 (CVE/KEV/CNVD) 无需白名单校验

配置示例 (config.yaml):
  target_authorization:
    enabled: true
    mode: strict          # strict=仅白名单, warn=告警但不阻断
    targets:
      - "10.0.0.0/8"     # 内网测试段
      - "*.example.com"   # 通配符域名
      - "192.168.1.100"   # 单个 IP
    auto_learn: false     # 是否自动学习新目标
"""

import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vuln-research-mcp.security.authz")


@dataclass
class AuthzDecision:
    """授权判定"""
    allowed: bool
    target: str
    reason: str
    matched_rule: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class AuthzConfig:
    """授权配置"""
    enabled: bool = True
    mode: str = "strict"          # "strict" | "warn" | "off"
    targets: list[str] = field(default_factory=list)
    default_deny: bool = True     # 不在白名单 → 拒绝
    auto_learn: bool = False
    auto_learn_max: int = 50
    max_targets: int = 500
    warn_on_deny: bool = True
    check_interval: int = 0       # 0=每次检查, >0=缓存秒数


class TargetAuthorizer:
    """目标授权管理器"""

    def __init__(self, config: Optional[AuthzConfig] = None):
        self.config = config or AuthzConfig()
        self._parsed_ips: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domain_patterns: list[re.Pattern] = []
        self._exact_domains: set[str] = set()
        self._exact_ips: set[str] = set()
        self._auto_learned: set[str] = set()
        self._decisions: list[AuthzDecision] = []
        self._decision_cache: dict[str, tuple[float, AuthzDecision]] = {}
        self._parse_rules()

    # ── 规则解析 ──

    def _parse_rules(self):
        """解析白名单规则到内存结构"""
        self._parsed_ips.clear()
        self._domain_patterns.clear()
        self._exact_domains.clear()
        self._exact_ips.clear()

        for target in self.config.targets:
            target = target.strip()
            if not target or target.startswith("#"):
                continue

            # CIDR / IP 网段
            if "/" in target and not "." in target.split("/")[0] if False else True:
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    self._parsed_ips.append(net)
                    logger.debug(f"白名单 CIDR: {target}")
                    continue
                except ValueError:
                    pass

            # 纯 IP
            try:
                ip = ipaddress.ip_address(target)
                self._exact_ips.add(str(ip))
                logger.debug(f"白名单 IP: {target}")
                continue
            except ValueError:
                pass

            # 通配符域名
            if "*" in target:
                pattern = re.escape(target).replace(r"\*", r"[a-zA-Z0-9\-_.]+")
                self._domain_patterns.append(re.compile(f"^{pattern}$", re.IGNORECASE))
                logger.debug(f"白名单域名模式: {target}")
            else:
                self._exact_domains.add(target.lower())
                logger.debug(f"白名单域名: {target}")

    # ── 目标标准化 ──

    @staticmethod
    def normalize_target(target: str) -> str:
        """标准化目标 — 去协议头、去路径"""
        t = target.strip().lower()
        t = re.sub(r'^https?://', '', t)
        t = re.sub(r':\d+$', '', t)
        t = t.split('/')[0]
        t = t.split('@')[-1]
        return t

    @staticmethod
    def is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    # ── 授权检查 ──

    def check(self, target: str) -> AuthzDecision:
        """检查目标是否授权"""
        if not self.config.enabled:
            return AuthzDecision(allowed=True, target=target, reason="白名单未启用")

        normalized = self.normalize_target(target)

        # 缓存检查
        if self.config.check_interval > 0:
            if normalized in self._decision_cache:
                ts, dec = self._decision_cache[normalized]
                if time.time() - ts < self.config.check_interval:
                    return dec

        # 智能默认: localhost 始终允许
        if normalized in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            dec = AuthzDecision(allowed=True, target=target, reason="localhost 默认允许", matched_rule="localhost")
        elif self._check_whitelist(normalized):
            dec = AuthzDecision(allowed=True, target=target, reason="匹配白名单", matched_rule=self._last_matched)
        elif self._auto_learned and normalized in self._auto_learned:
            dec = AuthzDecision(allowed=True, target=target, reason="自动学习目标", matched_rule="auto-learned")
        elif self.config.default_deny:
            reason = f"目标 '{target}' 不在授权白名单中"
            dec = AuthzDecision(allowed=False, target=target, reason=reason)
            if self.config.mode == "warn":
                logger.warning(f"[授权告警] {reason} — 模式=warn, 继续执行")
                dec = AuthzDecision(allowed=True, target=target, reason=f"{reason} (warn模式放行)")
        else:
            dec = AuthzDecision(allowed=True, target=target, reason="default_deny=false, 默认放行")

        # 审计
        if not dec.allowed:
            self._decisions.append(dec)
            if len(self._decisions) > 2000:
                self._decisions = self._decisions[-1000:]
            if self.config.warn_on_deny:
                logger.warning(f"[授权阻断] {dec.reason}")

        # 缓存
        if self.config.check_interval > 0:
            self._decision_cache[normalized] = (time.time(), dec)

        return dec

    _last_matched: str = ""

    def _check_whitelist(self, normalized: str) -> bool:
        """检查是否在白名单内"""
        # 精确 IP
        if normalized in self._exact_ips:
            self._last_matched = normalized
            return True

        # CIDR
        if self.is_ip(normalized):
            try:
                ip = ipaddress.ip_address(normalized)
                for net in self._parsed_ips:
                    if ip in net:
                        self._last_matched = str(net)
                        return True
            except ValueError:
                pass

        # 精确域名
        if normalized in self._exact_domains:
            self._last_matched = normalized
            return True

        # 通配符域名
        for p in self._domain_patterns:
            if p.match(normalized):
                self._last_matched = p.pattern
                return True

        return False

    # ── 批量检查 ──

    def check_batch(self, targets: list[str]) -> list[AuthzDecision]:
        return [self.check(t) for t in targets]

    def get_unauthorized(self, targets: list[str]) -> list[str]:
        """返回未授权目标列表"""
        return [t for t in targets if not self.check(t).allowed]

    # ── 动态管理 ──

    def add_target(self, target: str):
        """动态添加白名单目标"""
        if target not in self.config.targets:
            self.config.targets.append(target)
            self._parse_rules()
            logger.info(f"已添加白名单: {target}")

    def remove_target(self, target: str):
        if target in self.config.targets:
            self.config.targets.remove(target)
            self._parse_rules()
            logger.info(f"已移除白名单: {target}")

    def auto_learn(self, target: str):
        """自动学习合法目标"""
        if self.config.auto_learn and len(self._auto_learned) < self.config.auto_learn_max:
            normalized = self.normalize_target(target)
            if normalized not in self._auto_learned:
                self._auto_learned.add(normalized)
                logger.info(f"自动学习目标: {target}")

    # ── 导出 ──

    def export_audit_log(self) -> list[dict]:
        return [
            {"target": d.target, "allowed": d.allowed, "reason": d.reason, "rule": d.matched_rule}
            for d in self._decisions
        ]

    def summary(self) -> dict:
        return {
            "enabled": self.config.enabled,
            "mode": self.config.mode,
            "default_deny": self.config.default_deny,
            "whitelist_size": len(self.config.targets),
            "ip_rules": len(self._parsed_ips),
            "domain_rules": len(self._exact_domains) + len(self._domain_patterns),
            "auto_learned": len(self._auto_learned),
            "denials": len([d for d in self._decisions if not d.allowed]),
        }


# ============================================================
# 全局单例
# ============================================================

_authorizer: Optional[TargetAuthorizer] = None


def get_authorizer() -> TargetAuthorizer:
    global _authorizer
    if _authorizer is None:
        _authorizer = TargetAuthorizer()
    return _authorizer


def init_authorizer(config: Optional[AuthzConfig] = None) -> TargetAuthorizer:
    global _authorizer
    _authorizer = TargetAuthorizer(config)
    return _authorizer
