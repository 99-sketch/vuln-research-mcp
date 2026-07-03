# src/core/tool_namespace.py
"""MCP 工具命名空间隔离 — 防止多 MCP 服务工具名冲突

v5.3: 工具注册时自动添加 namespace 前缀，防止被其他 MCP 服务劫持。

工作原理:
  1. 内部注册名保持原名 (scan_ports)
  2. 对外暴露名添加 namespace 前缀 (vuln:scan_ports)
  3. call_tool 时自动去除 namespace 前缀查找 handler
  4. 跨 MCP 冲突检测 — 已知常见冲突列表

配置:
  namespace: "vuln"        # 命名空间前缀
  strict_mode: false        # true=强制命名空间, false=兼容裸名
  detect_conflicts: true    # 启动时检测已知冲突
"""

import logging
from typing import Optional

logger = logging.getLogger("vuln-research-mcp.core.namespace")

# 已知可能冲突的常用 MCP 工具名 (来自其他常见 MCP 服务)
KNOWN_CONFLICTING_NAMES: set[str] = {
    # 通用工具名 — 极易冲突
    "search", "query", "lookup", "fetch", "download", "upload",
    "list", "get", "scan", "check", "analyze", "report",
    # 安全相关常见名
    "nmap", "nuclei", "exploit", "vulnerability", "cve",
    "port_scan", "web_scan", "dns_lookup", "whois",
    # 文件系统
    "read_file", "write_file", "list_files", "delete_file",
    # 系统命令
    "exec", "run", "shell", "bash", "cmd",
}


class ToolNamespace:
    """工具命名空间管理器"""

    def __init__(self, namespace: str = "vuln", strict: bool = False):
        self.namespace = namespace
        self.strict = strict
        self._internal_to_external: dict[str, str] = {}  # 内部名 → 对外名
        self._external_to_internal: dict[str, str] = {}  # 对外名 → 内部名
        self._conflict_report: list[str] = []

    # ── 注册 ──

    def register(self, internal_name: str) -> tuple[str, Optional[str]]:
        """注册工具名，返回 (对外名, 冲突信息)"""
        external_name = f"{self.namespace}:{internal_name}"

        # 去重检查
        if external_name in self._external_to_internal:
            existing = self._external_to_internal[external_name]
            conflict = f"命名空间冲突: {external_name} -> {existing} (尝试注册 {internal_name})"
            self._conflict_report.append(conflict)
            return external_name, conflict

        self._internal_to_external[internal_name] = external_name
        self._external_to_internal[external_name] = internal_name

        # 已知冲突检测
        conflict = None
        if internal_name in KNOWN_CONFLICTING_NAMES:
            conflict = f"工具名 '{internal_name}' 可能与其它 MCP 服务冲突 → 对外名: '{external_name}'"
            self._conflict_report.append(conflict)

        return external_name, conflict

    def register_batch(self, names: list[str]) -> list[str]:
        """批量注册，返回对外名列表"""
        return [self.register(n)[0] for n in names]

    # ── 解析 ──

    def resolve(self, external_name: str) -> Optional[str]:
        """从对外名解析到内部名"""
        # 带命名空间前缀
        if external_name in self._external_to_internal:
            return self._external_to_internal[external_name]

        # 裸名（兼容模式）
        if not self.strict and external_name in self._internal_to_external:
            return external_name

        return None

    def to_external(self, internal_name: str) -> str:
        """内部名 → 对外名"""
        return self._internal_to_external.get(internal_name, internal_name)

    def to_internal(self, external_name: str) -> str:
        """对外名 → 内部名 (兼容模式也返回原名)"""
        return self._external_to_internal.get(external_name, external_name)

    # ── 列表 ──

    def list_external(self) -> list[str]:
        """列出所有对外暴露的工具名"""
        return list(self._external_to_internal.keys())

    def list_internal(self) -> list[str]:
        return list(self._internal_to_external.keys())

    def size(self) -> int:
        return len(self._internal_to_external)

    # ── 冲突报告 ──

    def get_conflict_report(self) -> list[str]:
        return list(self._conflict_report)

    def has_conflicts(self) -> bool:
        return len(self._conflict_report) > 0

    def summary(self) -> dict:
        return {
            "namespace": self.namespace,
            "strict_mode": self.strict,
            "tools_registered": self.size(),
            "conflicts_found": len(self._conflict_report),
        }


# ============================================================
# 全局单例
# ============================================================

_namespace: Optional[ToolNamespace] = None


def get_namespace() -> ToolNamespace:
    global _namespace
    if _namespace is None:
        _namespace = ToolNamespace()
    return _namespace


def init_namespace(namespace: str = "vuln", strict: bool = False) -> ToolNamespace:
    global _namespace
    _namespace = ToolNamespace(namespace, strict)
    return _namespace
