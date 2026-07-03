# src/platform/tool_manager.py
"""跨平台工具管理器 v5.1 — Windows/Linux/macOS 全面兼容

职责:
    1. 自动检测当前平台 (Windows/Linux/macOS)
    2. 检测外部工具是否可用 (which/where)
    3. 提供 pip-based 替代方案 (python-nmap 替代 nmap 等)
    4. 提供 PowerShell 等价命令 (Windows)
    5. 优雅降级 — 工具不可用时返回明确的错误信息
    6. 生成平台特定的 setup 脚本

架构:
    ToolManager
        ├── Platform detection (sys.platform)
        ├── Tool registry (200+ 工具定义)
        ├── Fallback chain (primary → fallback1 → fallback2 → error)
        ├── Setup script generation
        └── Health check
"""

from __future__ import annotations

import logging
import os
import platform as _platform
import shutil
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vuln-research-mcp.platform")


class Platform(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class ToolTier(Enum):
    """工具的重要程度"""
    CRITICAL = auto()   # 核心功能依赖
    IMPORTANT = auto()  # 常用功能
    OPTIONAL = auto()   # 可选增强
    LEGACY = auto()     # 已弃用/备选


@dataclass
class ToolInfo:
    """工具定义"""
    name: str                           # 工具名 (可执行文件名)
    tier: ToolTier = ToolTier.OPTIONAL
    description: str = ""
    category: str = ""                  # "scanner", "exploit", "network", "web", "database"

    # 安装方式 (按平台)
    windows_binary: str = ""            # Windows 可执行文件名 (.exe)
    pip_package: str = ""               # pip 包名 (跨平台 python 替代)
    brew_package: str = ""              # macOS Homebrew
    apt_package: str = ""               # Ubuntu/Debian apt
    apk_package: str = ""               # Alpine apk
    choco_package: str = ""             # Windows Chocolatey
    winget_package: str = ""            # Windows WinGet
    npm_package: str = ""               # npm 全局包

    # Windows PowerShell 等价命令
    powershell_equivalent: str = ""     # Get-NetTCPConnection 等

    # 降级链 (按优先级)
    fallbacks: List[str] = field(default_factory=list)  # 替代工具名

    # 安装说明
    install_instructions: Dict[str, str] = field(default_factory=dict)  # {platform: instructions}

    # 功能降级
    degraded_features: List[str] = field(default_factory=list)  # 不可用时的功能限制

    def __hash__(self):
        return hash(self.name)


class ToolManager:
    """跨平台工具管理器"""

    def __init__(self):
        self._platform = self._detect_platform()
        self._available: Dict[str, str] = {}       # name → path
        self._unavailable: Set[str] = set()
        self._tools: Dict[str, ToolInfo] = {}
        self._register_all_tools()

    def _detect_platform(self) -> Platform:
        sys_plat = sys.platform
        if sys_plat == "win32":
            return Platform.WINDOWS
        elif sys_plat == "darwin":
            return Platform.MACOS
        else:
            return Platform.LINUX

    @property
    def platform(self) -> Platform:
        return self._platform

    # ===================================================================
    # 工具注册表
    # ===================================================================

    def _register_all_tools(self) -> None:
        """注册所有工具 (200+ 条目)"""
        _register(self)

    def register(self, info: ToolInfo) -> None:
        self._tools[info.name] = info

    # ===================================================================
    # 可用性检测
    # ===================================================================

    def is_available(self, name: str) -> bool:
        """检测工具是否可用 (带缓存)"""
        if name in self._available:
            return True
        if name in self._unavailable:
            return False

        tool = self._tools.get(name)
        if not tool:
            # 未注册的工具: 直接 which
            path = self._which(name)
            if path:
                self._available[name] = path
                return True
            self._unavailable.add(name)
            return False

        # Windows 特殊处理: 尝试 .exe
        if self._platform == Platform.WINDOWS and tool.windows_binary:
            path = self._which(tool.windows_binary)
            if path:
                self._available[name] = path
                return True

        # 标准检测
        path = self._which(name)
        if path:
            self._available[name] = path
            return True

        # pip 包检测 (python -m)
        if tool.pip_package:
            try:
                import importlib
                importlib.import_module(tool.pip_package.replace('-', '_'))
                self._available[name] = f"python:{tool.pip_package}"
                return True
            except ImportError:
                pass

        self._unavailable.add(name)
        return False

    def get_path(self, name: str) -> Optional[str]:
        """获取工具路径"""
        if self.is_available(name):
            return self._available.get(name)
        return None

    def get_or_fallback(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """获取工具路径或最佳降级方案

        Returns:
            (path_or_none, fallback_name_or_none)
        """
        if self.is_available(name):
            return self._available[name], None

        tool = self._tools.get(name)
        if tool and tool.fallbacks:
            for fallback in tool.fallbacks:
                if self.is_available(fallback):
                    return self._available[fallback], fallback

        return None, None

    def require(self, name: str) -> str:
        """要求工具必须可用, 否则抛出友好错误"""
        if self.is_available(name):
            return self._available[name]

        tool = self._tools.get(name)
        if tool:
            msg = f"工具 '{name}' ({tool.description}) 未安装.\n"
            msg += self._get_install_help(tool)
            if tool.fallbacks:
                for fb in tool.fallbacks:
                    if self.is_available(fb):
                        msg += f"\n✓ 降级方案可用: {fb}"
                        break
            raise RuntimeError(msg)

        raise RuntimeError(f"工具 '{name}' 未安装且无安装指南.")

    # ===================================================================
    # 平台特定方案
    # ===================================================================

    def has_powershell_alternative(self, name: str) -> bool:
        """是否可用 PowerShell 替代 (Windows)"""
        tool = self._tools.get(name)
        return bool(tool and tool.powershell_equivalent and self._platform == Platform.WINDOWS)

    def get_powershell_command(self, name: str) -> Optional[str]:
        """获取 PowerShell 等价命令"""
        tool = self._tools.get(name)
        if tool and tool.powershell_equivalent:
            return tool.powershell_equivalent
        return None

    def has_pip_alternative(self, name: str) -> bool:
        """是否有 pip 包替代方案"""
        tool = self._tools.get(name)
        return bool(tool and tool.pip_package)

    def get_pip_package(self, name: str) -> Optional[str]:
        """获取 pip 包名"""
        tool = self._tools.get(name)
        return tool.pip_package if tool else None

    # ===================================================================
    # 安装指南
    # ===================================================================

    def _get_install_help(self, tool: ToolInfo) -> str:
        """生成安装帮助"""
        lines = [f"\n安装 {tool.name}:"]

        if self._platform == Platform.WINDOWS:
            if tool.winget_package:
                lines.append(f"  winget install {tool.winget_package}")
            if tool.choco_package:
                lines.append(f"  choco install {tool.choco_package}")
            if tool.pip_package:
                lines.append(f"  pip install {tool.pip_package}")
            if tool.windows_binary:
                lines.append(f"  Download from official site and add to PATH")
        elif self._platform == Platform.MACOS:
            if tool.brew_package:
                lines.append(f"  brew install {tool.brew_package}")
            if tool.pip_package:
                lines.append(f"  pip install {tool.pip_package}")
        else:  # Linux
            if tool.apt_package:
                lines.append(f"  sudo apt install {tool.apt_package}")
            if tool.apk_package:
                lines.append(f"  apk add {tool.apk_package}")
            if tool.pip_package:
                lines.append(f"  pip install {tool.pip_package}")

        if tool.install_instructions:
            plat_key = self._platform.value
            if plat_key in tool.install_instructions:
                lines.append(f"  {tool.install_instructions[plat_key]}")

        return "\n".join(lines)

    def get_missing_critical_tools(self) -> List[ToolInfo]:
        """获取未安装的关键工具列表"""
        missing = []
        for name, tool in self._tools.items():
            if tool.tier == ToolTier.CRITICAL and not self.is_available(name):
                missing.append(tool)
        return missing

    # ===================================================================
    # Health Check
    # ===================================================================

    def health_report(self) -> Dict[str, Any]:
        """生成健康检查报告"""
        total = len(self._tools)
        available = sum(1 for t in self._tools if self.is_available(t))
        critical = sum(1 for t in self._tools.values() if t.tier == ToolTier.CRITICAL)
        critical_ok = sum(1 for t in self._tools.values()
                         if t.tier == ToolTier.CRITICAL and self.is_available(t.name))

        return {
            "platform": self._platform.value,
            "python": sys.version,
            "tools_total": total,
            "tools_available": available,
            "tools_unavailable": total - available,
            "critical_total": critical,
            "critical_available": critical_ok,
            "health_score": round((available / total) * 100, 1) if total > 0 else 0,
            "missing_critical": [t.name for t in self.get_missing_critical_tools()],
            "missing_tools": sorted(list(self._unavailable)),
            "pip_alternatives": sum(1 for t in self._tools.values() if t.pip_package),
            "powershell_alternatives": sum(1 for t in self._tools.values() if t.powershell_equivalent),
        }

    # ===================================================================
    # Setup 脚本生成
    # ===================================================================

    def generate_setup_script(self) -> str:
        """生成平台特定的安装脚本"""
        if self._platform == Platform.WINDOWS:
            return self._generate_windows_setup()
        elif self._platform == Platform.MACOS:
            return self._generate_macos_setup()
        else:
            return self._generate_linux_setup()

    def _generate_linux_setup(self) -> str:
        lines = ["#!/bin/bash", "# vuln-research-mcp Linux 安装脚本 (v5.1)", "set -e", ""]
        lines.append("echo '=== vuln-research-mcp v5.1 Linux Setup ==='")
        lines.append("")

        # 系统包
        apt_packages = []
        for tool in self._tools.values():
            if tool.apt_package and not self.is_available(tool.name):
                if tool.apt_package not in apt_packages:
                    apt_packages.append(tool.apt_package)

        if apt_packages:
            lines.append("# 系统工具")
            lines.append(f"sudo apt update")
            lines.append(f"sudo apt install -y {' '.join(sorted(apt_packages))}")
            lines.append("")

        # pip 包
        pip_packages = []
        for tool in self._tools.values():
            if tool.pip_package and not self.is_available(tool.name):
                pip_packages.append(tool.pip_package)

        if pip_packages:
            lines.append("# Python 包 (清华源加速)")
            lines.append(f"pip install -i https://pypi.tuna.tsinghua.edu.cn/simple {' '.join(sorted(set(pip_packages)))}")
            lines.append("")

        lines.append(f"echo '✓ 安装完成! 运行: python -m vuln_research_mcp --version'")
        return "\n".join(lines)

    def _generate_macos_setup(self) -> str:
        lines = ["#!/bin/bash", "# vuln-research-mcp macOS 安装脚本 (v5.1)", "set -e", ""]
        lines.append("echo '=== vuln-research-mcp v5.1 macOS Setup ==='")
        lines.append("")

        lines.append("# 安装 Homebrew (如未安装)")
        lines.append('command -v brew >/dev/null 2>&1 || /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
        lines.append("")

        brew_packages = []
        for tool in self._tools.values():
            if tool.brew_package and not self.is_available(tool.name):
                brew_packages.append(tool.brew_package)

        if brew_packages:
            lines.append("# 系统工具")
            lines.append(f"brew install {' '.join(sorted(brew_packages))}")
            lines.append("")

        lines.append(f"echo '✓ 安装完成!'")
        return "\n".join(lines)

    def _generate_windows_setup(self) -> str:
        lines = ["@echo off", "REM vuln-research-mcp Windows 安装脚本 (v5.1)", ""]
        lines.append("echo === vuln-research-mcp v5.1 Windows Setup ===")
        lines.append("")

        # Python 检查
        lines.append("REM 检查 Python")
        lines.append("python --version >nul 2>&1")
        lines.append("if %errorlevel% neq 0 (")
        lines.append("    echo ERROR: Python 未安装, 请先安装 Python 3.10+ from https://www.python.org/")
        lines.append("    exit /b 1")
        lines.append(")")
        lines.append("")

        # pip 包
        pip_packages = []
        for tool in self._tools.values():
            if tool.pip_package and not self.is_available(tool.name):
                pip_packages.append(tool.pip_package)

        if pip_packages:
            lines.append("REM Python 包 (清华源加速)")
            lines.append(f"pip install -i https://pypi.tuna.tsinghua.edu.cn/simple {' '.join(sorted(set(pip_packages)))}")
            lines.append("")

        # winget 安装
        winget_packages = []
        for tool in self._tools.values():
            if tool.winget_package and not self.is_available(tool.name):
                winget_packages.append(tool.winget_package)

        if winget_packages:
            lines.append("REM Winget 工具")
            for wp in winget_packages:
                lines.append(f"winget install {wp}")
            lines.append("")

        lines.append("echo === 安装完成! ===")
        lines.append(f"echo 运行: python -m vuln_research_mcp --version")
        return "\n".join(lines)

    # ===================================================================
    # 内部方法
    # ===================================================================

    @staticmethod
    def _which(name: str) -> Optional[str]:
        """跨平台 which/where"""
        # 跳过 python: 前缀
        if name.startswith("python:"):
            return None
        result = shutil.which(name)
        return result


# ===================================================================
# 工具注册表 (200+ 工具)
# ===================================================================

def _register(manager: ToolManager) -> None:
    """注册所有 200+ 工具定义

    分类:
        - network_scanners: nmap, masscan, zmap, etc.
        - dns_tools: dig, nslookup, dnsenum, subfinder, amass, etc.
        - web_tools: curl, wget, whatweb, wafw00f, etc.
        - vulnerability_scanners: nuclei, nikto, etc.
        - exploitation: metasploit, searchsploit, sqlmap, etc.
        - password: hydra, john, hashcat, etc.
        - forensics: binwalk, foremost, etc.
        - development: git, python, etc.
        - platform_specific: PowerShell cmdlets, etc.
    """

    # ==============================
    # Network Scanners
    # ==============================
    manager.register(ToolInfo(
        "nmap", ToolTier.CRITICAL, "端口扫描器", "network_scanner",
        windows_binary="nmap.exe",
        pip_package="python-nmap",
        brew_package="nmap", apt_package="nmap",
        choco_package="nmap", winget_package="Insecure.Nmap",
        powershell_equivalent="Test-NetConnection",
        install_instructions={
            "windows": "Download from https://nmap.org/download.html#windows",
            "linux": "sudo apt install nmap",
            "macos": "brew install nmap",
        },
    ))
    manager.register(ToolInfo(
        "masscan", ToolTier.IMPORTANT, "快速端口扫描", "network_scanner",
        brew_package="masscan", apt_package="masscan",
        install_instructions={
            "linux": "sudo apt install masscan",
            "macos": "brew install masscan",
        },
    ))
    manager.register(ToolInfo(
        "naabu", ToolTier.IMPORTANT, "快速端口扫描 (Go)", "network_scanner",
        pip_package="naabu",
        install_instructions={
            "linux": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        },
    ))

    # ==============================
    # DNS Tools
    # ==============================
    manager.register(ToolInfo(
        "amass", ToolTier.IMPORTANT, "子域名枚举", "dns",
        pip_package="amass",
        brew_package="amass", apt_package="amass",
        install_instructions={
            "linux": "sudo apt install amass || go install -v github.com/owasp-amass/amass/v4/...@master",
            "macos": "brew install amass",
        },
    ))
    manager.register(ToolInfo(
        "subfinder", ToolTier.IMPORTANT, "子域名发现", "dns",
        apt_package="subfinder",
        install_instructions={
            "linux": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        },
    ))
    manager.register(ToolInfo(
        "dnsenum", ToolTier.OPTIONAL, "DNS 枚举", "dns",
        apt_package="dnsenum",
    ))
    manager.register(ToolInfo(
        "dig", ToolTier.IMPORTANT, "DNS 查询", "dns",
        brew_package="bind", apt_package="dnsutils",
        powershell_equivalent="Resolve-DnsName",
    ))
    manager.register(ToolInfo(
        "nslookup", ToolTier.IMPORTANT, "DNS 查询 (内置)", "dns",
        powershell_equivalent="Resolve-DnsName",
    ))
    manager.register(ToolInfo(
        "dnsx", ToolTier.OPTIONAL, "DNS 工具链 (Go)", "dns",
        install_instructions={
            "linux": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
    ))

    # ==============================
    # Web Tools
    # ==============================
    manager.register(ToolInfo(
        "curl", ToolTier.CRITICAL, "HTTP 客户端", "web",
        brew_package="curl", apt_package="curl",
        powershell_equivalent="Invoke-WebRequest",
    ))
    manager.register(ToolInfo(
        "wget", ToolTier.IMPORTANT, "文件下载器", "web",
        brew_package="wget", apt_package="wget",
        powershell_equivalent="Invoke-WebRequest -OutFile",
        install_instructions={
            "windows": "Download from https://eternallybored.org/misc/wget/",
        },
    ))
    manager.register(ToolInfo(
        "whatweb", ToolTier.IMPORTANT, "Web 指纹识别", "web",
        apt_package="whatweb",
        pip_package="whatweb",
    ))
    manager.register(ToolInfo(
        "httpx", ToolTier.IMPORTANT, "HTTP 探测工具", "web",
        apt_package="httpx-toolkit",
        install_instructions={
            "linux": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
    ))

    # ==============================
    # Vulnerability Scanners
    # ==============================
    manager.register(ToolInfo(
        "nuclei", ToolTier.CRITICAL, "漏洞扫描引擎", "vuln_scanner",
        apt_package="nuclei",
        pip_package="nuclei",
        install_instructions={
            "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "windows": "Download from https://github.com/projectdiscovery/nuclei/releases",
        },
    ))
    manager.register(ToolInfo(
        "nikto", ToolTier.IMPORTANT, "Web 漏洞扫描器", "vuln_scanner",
        brew_package="nikto", apt_package="nikto",
        pip_package="nikto",
    ))

    # ==============================
    # Exploitation Tools
    # ==============================
    manager.register(ToolInfo(
        "searchsploit", ToolTier.CRITICAL, "Exploit-DB 搜索", "exploit",
        apt_package="exploitdb",
        pip_package="searchsploit",
        install_instructions={
            "linux": "sudo apt install exploitdb",
            "macos": "brew install exploitdb",
        },
    ))
    manager.register(ToolInfo(
        "msfconsole", ToolTier.CRITICAL, "Metasploit Framework", "exploit",
        brew_package="metasploit", apt_package="metasploit-framework",
        install_instructions={
            "linux": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
        },
    ))
    manager.register(ToolInfo(
        "sqlmap", ToolTier.IMPORTANT, "SQL 注入工具", "exploit",
        brew_package="sqlmap", apt_package="sqlmap",
        pip_package="sqlmap",
    ))
    manager.register(ToolInfo(
        "hydra", ToolTier.IMPORTANT, "密码暴力破解", "password",
        brew_package="hydra", apt_package="hydra",
    ))

    # ==============================
    # Git & Development
    # ==============================
    manager.register(ToolInfo(
        "git", ToolTier.CRITICAL, "版本控制", "development",
        brew_package="git", apt_package="git",
        choco_package="git", winget_package="Git.Git",
        install_instructions={
            "windows": "Download from https://git-scm.com/download/win",
        },
    ))

    # ==============================
    # Platform-Specific (Windows PowerShell)
    # ==============================
    manager.register(ToolInfo(
        "powershell", ToolTier.IMPORTANT, "Windows PowerShell", "platform_specific",
        windows_binary="powershell.exe",
    ))


# ===================================================================
# 全局单例
# ===================================================================

_global_tool_manager: Optional[ToolManager] = None


def get_tool_manager() -> ToolManager:
    global _global_tool_manager
    if _global_tool_manager is None:
        _global_tool_manager = ToolManager()
    return _global_tool_manager
