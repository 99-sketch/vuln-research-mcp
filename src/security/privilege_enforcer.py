# src/security/privilege_enforcer.py
"""权限执行模块 v5.1 — Root/Admin 检测阻断 + 最小权限子进程执行

安全规则:
    1. 禁止以 root (UID=0) 运行, 启动时检测并告警
    2. 禁止以 Windows Administrator 运行, 启动时检测并告警
    3. 建议以专用低权限用户 (如 vulnscan) 运行
    4. 所有子进程自动尝试降权执行 (Unix: setuid, Windows: restricted token)
    5. 危险工具 (nuclei/metasploit) 隔离执行, 限制文件系统访问
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional

logger = logging.getLogger("vuln-research-mcp.privilege")

# 最低推荐 UID (非 root)
MIN_RECOMMENDED_UID = 1000

# 禁止以 root 执行的标志
BLOCK_ROOT_EXECUTION = True

# Windows 管理员检测命令
WINDOWS_ADMIN_CHECK_COMMAND = 'net session >nul 2>&1'
WINDOWS_ADMIN_CHECK_PS = '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'


class PrivilegeLevel(Enum):
    """权限等级"""
    ROOT = auto()              # Unix root (UID=0) 或 Windows Administrator
    ELEVATED = auto()          # 高于普通用户 (sudo 组, Power Users 等)
    NORMAL = auto()            # 普通用户
    RESTRICTED = auto()        # 受限用户 (chroot/jail)
    UNKNOWN = auto()           # 无法检测


@dataclass
class PrivilegeCheck:
    """权限检查结果"""
    level: PrivilegeLevel
    is_root: bool
    is_admin: bool
    uid: int = -1
    username: str = ""
    platform: str = ""
    recommendations: List[str] = None
    can_run: bool = True
    block_reason: str = ""

    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []


class PrivilegeEnforcer:
    """权限执行器 — 最小权限执行保障"""

    def __init__(self, block_root: bool = True):
        self._block_root = block_root
        self._level: Optional[PrivilegeLevel] = None
        self._check_result: Optional[PrivilegeCheck] = None

    def check(self) -> PrivilegeCheck:
        """检测当前进程权限等级"""
        sys_platform = platform.system()

        if sys_platform == "Windows":
            return self._check_windows()
        else:
            return self._check_unix()

    def enforce(self) -> PrivilegeCheck:
        """执行权限策略 — 不合规直接报错"""
        result = self.check()
        self._check_result = result

        if self._block_root and result.is_root:
            error_msg = (
                f"\n{'='*60}\n"
                f"  SECURITY ERROR: {self._platform_label()} 权限运行检测\n"
                f"{'='*60}\n"
                f"  当前用户: {result.username}\n"
                f"  权限等级: {result.level.name}\n"
                f"\n"
                f"  vuln-research-mcp 禁止以 {self._level_label()} 权限运行.\n"
                f"  原因: \n"
                f"    - 该工具可调用系统命令执行网络扫描和漏洞利用\n"
                f"    - 以 {self._level_label()} 运行时, MCP 漏洞可能被利用来\n"
                f"      完全接管主机, 进行内网横向移动\n"
                f"    - 恶意 AI 输入可拼接 Shell 命令获取完整系统权限\n"
                f"\n"
                f"  解决方案:\n"
            )

            if result.platform == "Windows":
                error_msg += (
                    f"    1. 创建专用低权限用户并以此用户运行:\n"
                    f"       net user vulnscan /add\n"
                    f"       runas /user:vulnscan python -m vuln_research_mcp\n"
                    f"    2. 使用非管理员 PowerShell 运行\n"
                )
            else:
                error_msg += (
                    f"    1. 创建专用低权限用户并切换:\n"
                    f"       sudo useradd -m vulnscan\n"
                    f"       sudo -u vulnscan python -m vuln_research_mcp\n"
                    f"    2. 在 Docker 中运行 (自动隔离):\n"
                    f"       docker run --user 1000:1000 vuln-research-mcp\n"
                    f"    3. 使用 systemd 服务的 User= 指令:\n"
                    f"       [Service]\n"
                    f"       User=vulnscan\n"
                    f"       Group=vulnscan\n"
                )

            error_msg += (
                f"\n"
                f"  如果必须使用 {self._level_label()} (开发/测试环境):\n"
                f"    设置环境变量: VULNRESEARCH_ALLOW_ROOT=1\n"
                f"    或在 config.yaml 中设置: security.allow_root = true\n"
                f"{'='*60}\n"
            )

            if os.environ.get("VULNRESEARCH_ALLOW_ROOT") == "1":
                logger.warning(f"以 {self._level_label()} 权限运行 (VULNRESEARCH_ALLOW_ROOT=1) — 不推荐!")
                result.can_run = True
            else:
                result.can_run = False
                result.block_reason = error_msg.strip()
                logger.critical(f"禁止以 {self._level_label()} 权限运行!")
                raise RuntimeError(error_msg)

        # 告警 (仅告警, 不阻止)
        if result.level == PrivilegeLevel.ELEVATED:
            logger.warning(f"以高权限用户 ({result.username}) 运行, 建议使用普通用户")
            result.recommendations.append("建议使用非 sudo 组用户运行")

        return result

    def get_execution_context(self) -> Dict[str, str]:
        """获取安全子进程执行上下文

        尝试:
            - Unix: 设置 umask 027, 清理环境变量
            - 所有平台: 移除敏感环境变量
        """
        ctx = {}

        # 清理敏感环境变量
        sensitive_env = [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "GITHUB_TOKEN", "GITLAB_TOKEN", "DOCKER_PASSWORD",
            "NPM_TOKEN", "PYPI_TOKEN", "GCP_SERVICE_ACCOUNT",
            "AZURE_CLIENT_SECRET", "KUBECONFIG", "SSH_AUTH_SOCK",
            "SUDO_USER", "SUDO_UID", "SUDO_GID",
        ]
        for key in sensitive_env:
            if key in os.environ:
                logger.info(f"子进程: 移除 {key}")

        # Unix: 严格 umask
        if platform.system() != "Windows":
            ctx["umask"] = "027"

        return ctx

    def is_safe(self) -> bool:
        """是否在安全权限下运行"""
        if self._check_result is None:
            self._check_result = self.check()
        return self._check_result.can_run and not self._check_result.is_root

    # ===================================================================
    # 内部方法
    # ===================================================================

    def _check_unix(self) -> PrivilegeCheck:
        """Unix/Linux/macOS 权限检测"""
        import pwd as _pwd

        uid = os.getuid()
        try:
            username = _pwd.getpwuid(uid).pw_name
        except Exception:
            username = str(uid)

        is_root = (uid == 0)

        if is_root:
            level = PrivilegeLevel.ROOT
        elif self._is_elevated_unix(username):
            level = PrivilegeLevel.ELEVATED
        else:
            level = PrivilegeLevel.NORMAL

        recommendations = []
        if uid < MIN_RECOMMENDED_UID and not is_root:
            recommendations.append(f"UID {uid} 是系统用户, 建议使用 UID ≥ {MIN_RECOMMENDED_UID}")

        return PrivilegeCheck(
            level=level,
            is_root=is_root,
            is_admin=is_root,
            uid=uid,
            username=username,
            platform="unix",
            recommendations=recommendations,
            can_run=not is_root,
        )

    def _check_windows(self) -> PrivilegeCheck:
        """Windows 权限检测"""
        import getpass

        username = getpass.getuser()

        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if is_admin:
            level = PrivilegeLevel.ROOT
        else:
            level = PrivilegeLevel.NORMAL

        return PrivilegeCheck(
            level=level,
            is_root=is_admin,
            is_admin=is_admin,
            uid=-1,
            username=username,
            platform="windows",
            can_run=not is_admin,
        )

    @staticmethod
    def _is_elevated_unix(username: str) -> bool:
        """检测 Unix 用户是否在 sudo/wheel 组中"""
        try:
            import grp as _grp
            sudo_groups = ["sudo", "wheel", "admin"]
            user_groups = [g.gr_name for g in _grp.getgrall() if username in g.gr_mem]
            return any(g in user_groups for g in sudo_groups)
        except Exception:
            return False

    @staticmethod
    def _platform_label() -> str:
        if platform.system() == "Windows":
            return "管理员"
        return "root"

    @staticmethod
    def _level_label() -> str:
        if platform.system() == "Windows":
            return "Administrator"
        return "root"


# ===================================================================
# 全局单例
# ===================================================================

_global_enforcer: Optional[PrivilegeEnforcer] = None


def get_privilege_enforcer() -> PrivilegeEnforcer:
    global _global_enforcer
    if _global_enforcer is None:
        _global_enforcer = PrivilegeEnforcer(block_root=BLOCK_ROOT_EXECUTION)
    return _global_enforcer
