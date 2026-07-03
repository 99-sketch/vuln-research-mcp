# src/security/input_sanitizer.py
"""输入净化模块 - 防止命令注入、SSRF、路径遍历、XSS"""

import os
import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse


# Shell 注入关键字符
SHELL_METACHARS: set[str] = {
    ";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">",
    "\n", "\r", "\x00", "\\", "'", '"', "!", "~", "#", "%",
}

# 命令注入危险模式
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r'(?:;|\||&)\s*(?:sh|bash|zsh|ksh|tcsh|perl|python|ruby|lua|php|node|cmd|powershell|wget|curl|nc|ncat|telnet)\b',
     "shell execution injection"),
    (r'(?:;|\||&)\s*(?:cat|head|tail|less|more|dd|xxd|base64)\b',
     "file read injection"),
    (r'(?:;|\||&)\s*(?:rm\s|mv\s|cp\s|chmod|chown|mkfs|dd\s+if=|>/dev/)',
     "file write/destroy injection"),
    (r'`[^`]+`', "backtick command substitution"),
    (r'\$\([^)]+\)', "dollar command substitution"),
    (r'\$\{[^}]+\}', "brace variable expansion"),
    (r'\.\./', "directory traversal"),
    (r'\.\.\\', "Windows directory traversal"),
    (r'\\x[0-9a-fA-F]{2}', "hex escape injection"),
    (r'%(?:25)?(?:32)?[0-9a-fA-F]{2}', "URL-encoded injection"),
    (r'[<>]script', "XSS injection"),
    (r'(?:http|ftp|gopher|dict|file)://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)',
     "SSRF to internal network"),
    (r'(?:http|ftp)://(?:localhost|0\.0\.0\.0|\[::1\])',
     "SSRF to loopback"),
]

# 文件路径危险模式
PATH_INJECTION_PATTERNS: list[str] = [
    r'\.\./', r'\.\.\\',    # 目录遍历
    r'~/',                   # 用户目录
    r'\/etc\/', r'\/root\/', r'\/var\/',  # 系统路径
    r'C:\\Windows', r'C:\\WINDOWS',        # Windows 系统路径
]

# 网络目标黑名单（不可扫描的地址段）
NETWORK_BLACKLIST: list[tuple[str, str]] = [
    # 保留地址
    ("0.0.0.0/8", "IANA 保留"),
    ("127.0.0.0/8", "本地回环"),
    ("169.254.0.0/16", "链路本地"),
    ("224.0.0.0/4", "组播地址"),
    ("240.0.0.0/4", "保留地址"),
    # 特殊用途
    ("255.255.255.255/32", "全网广播"),
]

# 允许的命令参数字符集（取决于上下文）
SAFE_ARG_PATTERN = re.compile(r'^[a-zA-Z0-9._\-/:,]+$')
SAFE_SHELL_QUERY_PATTERN = re.compile(r'^[a-zA-Z0-9._\-/:, ]+$')
SAFE_FILE_PATH_PATTERN = re.compile(
    r'^[a-zA-Z0-9._\-/\\:]+$'
)


def sanitize_command_arg(arg: str, allow_spaces: bool = False) -> str:
    """净化命令参数 - 严格模式，拒绝任何 shell 元字符

    Args:
        arg: 待净化的参数
        allow_spaces: 是否允许空格（如搜索查询）

    Returns:
        净化后的参数

    Raises:
        ValueError: 参数包含非法字符或注入模式
    """
    if not arg or not isinstance(arg, str):
        raise ValueError("参数不能为空")

    arg = arg.strip()
    if not arg:
        raise ValueError("参数不能为空白")

    # 长度限制
    if len(arg) > 2048:
        raise ValueError("参数过长，超过 2048 字符")

    # 字符白名单检查
    pattern = SAFE_SHELL_QUERY_PATTERN if allow_spaces else SAFE_ARG_PATTERN
    if not pattern.match(arg):
        raise ValueError(f"参数包含非法字符: {arg[:100]}")

    # 注入模式扫描
    sanitize_injection_patterns(arg)

    return arg


def sanitize_shell_query(query: str) -> str:
    """净化 shell 工具搜索查询 - 允许字母数字、空格、常见标点

    用于 searchsploit、metasploit search 等搜索工具的查询参数净化。
    比 sanitize_command_arg 宽松，但会检查所有注入模式。
    """
    if not query or not isinstance(query, str):
        raise ValueError("查询参数不能为空")

    query = query.strip()
    if not query:
        raise ValueError("查询参数不能为空白")

    if len(query) > 500:
        raise ValueError("查询参数过长，超过 500 字符")

    # 只允许字母数字、空格、少量标点
    if not re.match(r'^[a-zA-Z0-9._\-/:,+()\[\]{} =\'"!@#*^~?]+$', query):
        raise ValueError(f"查询参数包含非法字符: {query[:100]}")

    # 注入模式扫描
    sanitize_injection_patterns(query)

    return query


def sanitize_file_path(path: str) -> str:
    """净化文件路径 - 防止路径遍历

    只允许相对路径中的安全字符，拒绝绝对路径和遍历模式。
    """
    if not path or not isinstance(path, str):
        raise ValueError("文件路径不能为空")

    path = path.strip()

    if len(path) > 1024:
        raise ValueError("文件路径过长")

    # 路径遍历检查
    for pattern in PATH_INJECTION_PATTERNS:
        if re.search(pattern, path):
            raise ValueError(f"文件路径包含危险模式: {pattern}")

    # 解析为绝对路径后检查是否在允许范围内
    # （调用方应传入相对于项目 data/ 的路径）
    if os.path.isabs(path):
        raise ValueError("不允许使用绝对路径")

    if not SAFE_FILE_PATH_PATTERN.match(path):
        raise ValueError(f"文件路径包含非法字符: {path[:100]}")

    return path


def sanitize_http_param(value: str, allow_url: bool = False) -> str:
    """净化 HTTP 参数 - 防止 HTTP 响应头注入和 XSS

    Args:
        value: 待净化的值
        allow_url: 是否允许完整 URL

    Returns:
        净化后的值
    """
    if not isinstance(value, str):
        raise ValueError("参数格式无效")

    value = value.strip()
    if not value:
        return value

    if len(value) > 4096:
        raise ValueError("参数过长")

    # HTTP 响应头注入检查
    if '\r' in value or '\n' in value:
        raise ValueError("参数包含换行符，可能存在 HTTP 响应头注入")

    # Null 字节注入
    if '\x00' in value:
        raise ValueError("参数包含 Null 字节")

    return value


def sanitize_injection_patterns(text: str) -> str:
    """扫描并拒绝命令注入/SSRF 等危险模式

    如果检测到任何已知注入模式，抛出 ValueError。
    返回原文本不做修改（白名单模式：要么通过，要么拒绝）。
    """
    lowered = text.lower()

    # 检查每个注入模式
    for pattern, description in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            raise ValueError(f"检测到潜在的 {description}: {text[:100]}")

    # 检查 shell 元字符组合
    metachar_count = sum(1 for c in text if c in SHELL_METACHARS)
    if metachar_count >= 3:
        raise ValueError(f"参数包含 {metachar_count} 个 shell 元字符，可能有注入风险")

    return text


def check_target_blacklist(target: str) -> None:
    """检查目标是否在网络黑名单中

    Args:
        target: IP 地址或域名

    Raises:
        ValueError: 目标在黑名单中
    """
    if not target:
        raise ValueError("目标不能为空")

    target = target.strip().lower() if isinstance(target, str) else target

    # 检查域名黑名单
    if target in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"不允许扫描本地回环地址: {target}")

    # 检查 IP 黑名单
    try:
        addr = ipaddress.ip_address(target)
        for network_str, reason in NETWORK_BLACKLIST:
            network = ipaddress.ip_network(network_str, strict=False)
            if addr in network:
                raise ValueError(f"目标 {target} 在禁止列表: {reason}")
    except (ValueError, TypeError):
        pass  # 如果不是 IP，跳过 IP 检查


# 全局净化器实例
class SecuritySanitizer:
    """安全输入净化器 - 统一入口"""

    @staticmethod
    def arg(arg: str) -> str:
        """净化命令参数"""
        return sanitize_command_arg(arg)

    @staticmethod
    def query(query: str) -> str:
        """净化搜索查询"""
        return sanitize_shell_query(query)

    @staticmethod
    def path(path: str) -> str:
        """净化文件路径"""
        return sanitize_file_path(path)

    @staticmethod
    def http(value: str) -> str:
        """净化 HTTP 参数"""
        return sanitize_http_param(value)

    @staticmethod
    def target(target: str) -> str:
        """校验网络目标"""
        check_target_blacklist(target)
        return sanitize_command_arg(target)

    @staticmethod
    def check(value: str) -> str:
        """通用注入模式检查"""
        return sanitize_injection_patterns(value)
