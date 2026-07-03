# src/security/enhanced_sanitizer.py
"""极致输入防御模块 v5.1 — AST 级 Shell 注入检测 + 多层白名单校验

设计原则 (Zero-Trust Input):
    1. AST 级 Shell 命令解析 — 用 shlex 解析后逐 token 白名单校验
    2. Unicode 混淆检测 — RLO/LRO/ZWJ/同形异义/双编码攻击
    3. 编码嵌套检测 — URL编码%252f → %2f → / 多层解码检测
    4. 递归参数验证 — 所有 list/dict 嵌套结构深度遍历清洗
    5. 白名单模式 — 未知 = 拒绝, 仅显式允许的才通过
    6. 零 shell=True — 所有子进程调用使用参数数组, 永不拼接字符串
"""

from __future__ import annotations

import itertools
import math
import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote


# ============================================================================
# 一、Unicode 混淆攻击检测
# ============================================================================

# 危险 Unicode 控制字符
DANGEROUS_UNICODE: Set[int] = {
    0x202A,  # LEFT-TO-RIGHT EMBEDDING (LRE)
    0x202B,  # RIGHT-TO-LEFT EMBEDDING (RLE)
    0x202C,  # POP DIRECTIONAL FORMATTING (PDF)
    0x202D,  # LEFT-TO-RIGHT OVERRIDE (LRO)
    0x202E,  # RIGHT-TO-LEFT OVERRIDE (RLO) — 文件名欺骗
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
    0x00AD,  # SOFT HYPHEN
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x034F,  # COMBINING GRAPHEME JOINER
    0x061C,  # ARABIC LETTER MARK
    0x2060,  # WORD JOINER
    0x2061,  # FUNCTION APPLICATION
    0x2062,  # INVISIBLE TIMES
    0x2063,  # INVISIBLE SEPARATOR
    0x2064,  # INVISIBLE PLUS
    0x0000,  # NULL byte injection
}

# 同形异义字符映射 (Homoglyph Attack — 拉丁字母 → 西里尔/希腊字母等)
HOMOGLYPH_MAP: Dict[int, int] = {
    # 拉丁 a → Cyrillic а (U+0430)
    0x0430: 0x0061,  # а → a
    # 拉丁 c → Cyrillic с (U+0441)
    0x0441: 0x0063,  # с → c
    # 拉丁 e → Cyrillic е (U+0435)
    0x0435: 0x0065,  # е → e
    # 拉丁 o → Cyrillic о (U+043E)
    0x043E: 0x006F,  # о → o
    # 拉丁 p → Cyrillic р (U+0440)
    0x0440: 0x0070,  # р → p
    # 拉丁 x → Cyrillic х (U+0445)
    0x0445: 0x0078,  # х → x
    # 拉丁 y → Cyrillic у (U+0443)
    0x0443: 0x0079,  # у → y
    # 拉丁 A → Cyrillic А (U+0410)
    0x0410: 0x0041,  # А → A
    # 拉丁 B → Cyrillic В (U+0412)
    0x0412: 0x0042,  # В → B
    # 拉丁 E → Cyrillic Е (U+0415)
    0x0415: 0x0045,  # Е → E
    # 拉丁 H → Cyrillic Н (U+041D)
    0x041D: 0x0048,  # Н → H
    # 拉丁 K → Cyrillic К (U+041A)
    0x041A: 0x004B,  # К → K
    # 拉丁 M → Cyrillic М (U+041C)
    0x041C: 0x004D,  # М → M
    # 拉丁 O → Cyrillic О (U+041E)
    0x041E: 0x004F,  # О → O
    # 拉丁 P → Cyrillic Р (U+0420)
    0x0420: 0x0050,  # Р → P
    # 拉丁 T → Cyrillic Т (U+0422)
    0x0422: 0x0054,  # Т → T
    # 拉丁 X → Cyrillic Х (U+0425)
    0x0425: 0x0058,  # Х → X
    # 拉丁 Y → Cyrillic Ү (U+04AE)
    0x04AE: 0x0059,  # Ү → Y
    # 数字 0 → Cyrillic О (U+041E)
    0x039F: 0x004F,  # Ο (Greek Omicron) → O
    # 拉丁 i → Greek ⅰ (U+2170)
    0x0456: 0x0069,  # і (Cyrillic) → i
    # 拉丁 I → Greek Ι (U+0399)
    0x0399: 0x0049,  # Ι → I
    # 拉丁 l → 数字 1 / Cyrillic
    0x217C: 0x006C,  # ⅼ → l
    # 全角转半角映射
    0xFF01: 0x0021,  # ！→ !
    0xFF02: 0x0022,  # ＂→ "
    0xFF03: 0x0023,  # ＃→ #
    0xFF04: 0x0024,  # ＄→ $
    0xFF05: 0x0025,  # ％→ %
    0xFF06: 0x0026,  # ＆→ &
    0xFF07: 0x0027,  # ＇→ '
    0xFF08: 0x0028,  # （→ (
    0xFF09: 0x0029,  # ）→ )
    0xFF0A: 0x002A,  # ＊→ *
    0xFF0B: 0x002B,  # ＋→ +
    0xFF0C: 0x002C,  # ，→ ,
    0xFF0D: 0x002D,  # －→ -
    0xFF0E: 0x002E,  # ．→ .
    0xFF0F: 0x002F,  # ／→ /
    0xFF1A: 0x003A,  # ：→ :
    0xFF1B: 0x003B,  # ；→ ;
    0xFF1C: 0x003C,  # ＜→ <
    0xFF1D: 0x003D,  # ＝→ =
    0xFF1E: 0x003E,  # ＞→ >
    0xFF1F: 0x003F,  # ？→ ?
    0xFF20: 0x0040,  # ＠→ @
    0xFF3B: 0x005B,  # ［→ [
    0xFF3C: 0x005C,  # ＼→ \
    0xFF3D: 0x005D,  # ］→ ]
    0xFF3E: 0x005E,  # ＾→ ^
    0xFF40: 0x0060,  # ｀→ `
    0xFF5B: 0x007B,  # ｛→ {
    0xFF5C: 0x007C,  # ｜→ |
    0xFF5D: 0x007D,  # ｝→ }
    0xFF5E: 0x007E,  # ～→ ~
}

# ============================================================================
# 二、Shell AST 级注入检测
# ============================================================================

# Shell 关键字 (不允许在任何参数中出现)
SHELL_KEYWORDS: Set[str] = {
    "if", "then", "else", "elif", "fi", "case", "esac",
    "for", "while", "until", "do", "done", "in", "select",
    "function", "time", "coproc", "declare", "typeset",
    "local", "export", "readonly", "alias", "unalias",
}

# 危险 Shell 内置命令 (绝不允许通过)
DANGEROUS_BUILTINS: Set[str] = {
    "eval", "exec", "source", ".", "trap", "builtin",
    "command", "enable", "disown", "set", "unset",
    "shift", "getopts", "mapfile", "readarray",
}

# 危险系统命令 (绝不允许通过)
DANGEROUS_COMMANDS: Set[str] = {
    # Shell 解释器
    "sh", "bash", "zsh", "ksh", "tcsh", "dash", "fish",
    "csh", "ash", "busybox",
    # 脚本语言解释器
    "perl", "python", "python3", "python2", "ruby", "lua",
    "php", "node", "nodejs", "deno", "bun",
    # 系统工具 - 文件操作
    "rm", "mv", "cp", "dd", "chmod", "chown", "chgrp",
    "mkfs", "mkswap", "fdisk", "parted",
    # 系统工具 - 进程
    "kill", "killall", "pkill", "reboot", "shutdown",
    "halt", "poweroff", "init", "systemctl", "service",
    # 系统工具 - 用户
    "useradd", "userdel", "usermod", "passwd", "chpasswd",
    "groupadd", "groupdel", "su", "sudo", "doas",
    # 网络危险
    "nc", "ncat", "netcat", "socat", "telnet",
    "wget", "curl", "ftp", "tftp", "rsync", "scp", "ssh",
    # 数据泄露
    "cat", "head", "tail", "less", "more", "tac",
    "xxd", "hexdump", "od", "base64", "base32",
    "gzip", "bzip2", "xz", "tar", "zip", "unzip",
    # 编译
    "gcc", "g++", "make", "cmake", "nasm", "yasm",
    # PowerShell / CMD (Windows)
    "cmd", "cmd.exe", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "cscript", "wscript",
    "mshta", "regsvr32", "rundll32", "msiexec",
    # 注册表 (Windows)
    "reg", "reg.exe", "regedit", "regedt32",
    # 计划任务
    "schtasks", "at", "cron", "crontab",
    # 下载执行的一行命令
    "certutil", "bitsadmin",
}

# 管道/重定向/控制操作符 (任何非零出现量都需审查)
SHELL_CONTROL_OPS: Set[str] = {
    ";", "|", "&", "&&", "||", "`", "$(", "${", "$",
    ">", ">>", "<", "<<", "<<<", "<>", ">&",
    "\\", "'", '"', "#", "!", "~",
    "\n", "\r", "\x00", "\t",
}


@dataclass
class SanitizationVerdict:
    """净化判决结果"""
    passed: bool
    cleaned_value: str
    reason: str = ""
    blocked_tokens: List[str] = field(default_factory=list)
    unicode_attacks: List[str] = field(default_factory=list)
    injection_attempts: List[str] = field(default_factory=list)
    risk_level: str = "none"  # none, low, medium, high, critical


class ExtremeSanitizer:
    """极致输入净化器 — 多层纵深防御

    净化管道 (pipeline):
        1. 长度/类型检查
        2. Unicode 混淆清洗
        3. 多层 URL 解码攻击检测
        4. Shell token 化 + AST 审查
        5. 危险命令/关键字白名单反查
        6. 注入模式特征匹配
        7. 嵌套结构递归检查
    """

    # 允许的参数字符白名单 (per-context)
    WHITELIST_ARG = re.compile(r'^[a-zA-Z0-9._\-/:, @*#^?\[\]{}()<>+=!%\'\"]+$')
    WHITELIST_HOST = re.compile(r'^[a-zA-Z0-9._\-]+$')
    WHITELIST_IP = re.compile(r'^[0-9.]+$')
    WHITELIST_CVE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    WHITELIST_PORT = re.compile(r'^[0-9,\- ]+$')

    # 入参最大长度
    MAX_ARG_LEN = 2048
    MAX_QUERY_LEN = 500
    MAX_PATH_LEN = 1024
    MAX_URL_LEN = 8192
    MAX_JSON_LEN = 1048576  # 1MB

    def sanitize_command_arg(self, arg: Any, allow_spaces: bool = False,
                             allow_special: bool = False) -> SanitizationVerdict:
        """命令参数净化 (严格模式)

        白名单规则:
            - 字母数字 + ._-/:, 组合
            - allow_spaces=True 时额外允许空格
            - allow_special=True 时额外允许 @*#^?[]{}()<>+=!%'"  (搜索查询)
        """
        if not isinstance(arg, str) or not arg:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason="参数为空或类型无效",
                risk_level="high"
            )

        arg = arg.strip()
        if not arg:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason="参数为空白字符串",
                risk_level="high"
            )

        if len(arg) > self.MAX_ARG_LEN:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"参数过长 ({len(arg)} > {self.MAX_ARG_LEN})",
                risk_level="high"
            )

        # 1. Unicode 混淆清洗
        arg, unicode_attacks = self._clean_unicode_confusion(arg)

        # 2. 多层编码攻击检测
        encoding_attacks = self._detect_encoding_nesting(arg)
        if encoding_attacks:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"检测到编码嵌套攻击: {encoding_attacks}",
                unicode_attacks=unicode_attacks,
                injection_attempts=encoding_attacks,
                risk_level="critical"
            )

        # 3. 注入模式扫描
        injection_hits = self._scan_injection_patterns(arg)
        if injection_hits:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"检测到注入模式: {injection_hits}",
                injection_attempts=injection_hits,
                risk_level="critical"
            )

        # 4. Shell token 化检查
        shell_tokens = self._detect_shell_ast_injection(arg)
        if shell_tokens:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"检测到 Shell 注入 token: {shell_tokens}",
                blocked_tokens=shell_tokens,
                risk_level="critical"
            )

        # 5. 白名单字符集检查
        if not allow_special and not self.WHITELIST_ARG.match(arg):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"参数包含白名单外字符: {arg[:100]}",
                risk_level="high"
            )

        return SanitizationVerdict(
            passed=True, cleaned_value=arg,
            unicode_attacks=unicode_attacks,
            risk_level="none" if not unicode_attacks else "low"
        )

    def sanitize_target(self, target: Any) -> SanitizationVerdict:
        """网络目标净化 (IP/域名/URL)

        检查:
            - IP 格式 + 私有地址阻止
            - 域名格式 + TLD 验证
            - URL SSRF 检查
        """
        if not isinstance(target, str) or not target:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason="目标不能为空",
                risk_level="high"
            )

        target = target.strip().lower()
        if len(target) > 2048:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="目标过长", risk_level="high")

        # Unicode 清洗
        target, unicode_attacks = self._clean_unicode_confusion(target)

        # URL 尝试
        if target.startswith(('http://', 'https://', 'ftp://')):
            return self._check_ssrf_url(target, unicode_attacks)

        # IP 检查
        import ipaddress
        try:
            addr = ipaddress.ip_address(target)
            if addr.is_private:
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"禁止扫描内网地址: {target}",
                    risk_level="high"
                )
            if addr.is_loopback:
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"禁止扫描回环地址: {target}",
                    risk_level="critical"
                )
            if addr.is_multicast or addr.is_reserved:
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"禁止扫描保留/组播地址: {target}",
                    risk_level="critical"
                )
            return SanitizationVerdict(
                passed=True, cleaned_value=target,
                unicode_attacks=unicode_attacks,
                risk_level="low" if addr.is_private else "none"
            )
        except ValueError:
            pass

        # 域名检查
        if self.WHITELIST_HOST.match(target):
            # 阻止裸 localhost/loopback 域名
            if target in ('localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]'):
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"禁止扫描回环: {target}",
                    risk_level="critical"
                )
            return SanitizationVerdict(
                passed=True, cleaned_value=target,
                unicode_attacks=unicode_attacks,
                risk_level="none"
            )

        return SanitizationVerdict(
            passed=False, cleaned_value="",
            reason=f"无效目标格式: {target}",
            risk_level="high"
        )

    def sanitize_port_list(self, ports: Any) -> SanitizationVerdict:
        """端口列表净化 — 只允许数字、逗号、连字符、空格"""
        if not isinstance(ports, str):
            # 也允许整数
            if isinstance(ports, int) and 1 <= ports <= 65535:
                return SanitizationVerdict(
                    passed=True, cleaned_value=str(ports), risk_level="none"
                )
            return SanitizationVerdict(
                passed=False, cleaned_value="", reason="无效端口格式", risk_level="high"
            )

        ports = ports.strip()
        if len(ports) > 500:
            return SanitizationVerdict(
                passed=False, cleaned_value="", reason="端口列表过长", risk_level="high"
            )

        # 格式: "80,443,8000-8100, 22"
        # 只允许 0-9 , - 空格
        if not re.match(r'^[0-9,\- ]+$', ports):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason="端口列表包含非法字符",
                risk_level="high"
            )

        # 解析并验证所有端口
        for part in re.split(r'[, ]+', ports):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = part.split('-', 1)
                if not start.isdigit() or not end.isdigit():
                    return SanitizationVerdict(
                        passed=False, cleaned_value="",
                        reason=f"无效端口范围: {part}",
                        risk_level="high"
                    )
                s, e = int(start), int(end)
                if s < 1 or e > 65535 or s > e:
                    return SanitizationVerdict(
                        passed=False, cleaned_value="",
                        reason=f"端口范围越界: {s}-{e}",
                        risk_level="high"
                    )
                if e - s > 1000:
                    return SanitizationVerdict(
                        passed=False, cleaned_value="",
                        reason=f"单次扫描端口过多: {e - s + 1} > 1000",
                        risk_level="high"
                    )
            else:
                if not part.isdigit() or int(part) < 1 or int(part) > 65535:
                    return SanitizationVerdict(
                        passed=False, cleaned_value="",
                        reason=f"无效端口: {part}",
                        risk_level="high"
                    )

        return SanitizationVerdict(passed=True, cleaned_value=ports, risk_level="none")

    def sanitize_cve_id(self, cve: Any) -> SanitizationVerdict:
        """CVE ID 净化 — 仅允许 CVE-YYYY-NNNN+ 格式"""
        if not isinstance(cve, str):
            return SanitizationVerdict(passed=False, cleaned_value="", reason="CVE ID 格式无效", risk_level="high")

        cve = cve.strip().upper()
        if self.WHITELIST_CVE.match(cve):
            return SanitizationVerdict(passed=True, cleaned_value=cve, risk_level="none")

        return SanitizationVerdict(
            passed=False, cleaned_value="",
            reason=f"无效 CVE 格式: {cve}",
            risk_level="high"
        )

    def sanitize_http_url(self, url: Any) -> SanitizationVerdict:
        """HTTP URL 净化 — SSRF 防护"""
        if not isinstance(url, str) or not url:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="URL 不能为空", risk_level="high")

        url = url.strip()
        if len(url) > self.MAX_URL_LEN:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="URL 过长", risk_level="high")

        # Unicode 清洗
        url, unicode_attacks = self._clean_unicode_confusion(url)

        # 编码嵌套检测
        encoding_attacks = self._detect_encoding_nesting(url)
        if encoding_attacks:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"URL 编码攻击: {encoding_attacks}",
                risk_level="critical"
            )

        return self._check_ssrf_url(url, unicode_attacks)

    def sanitize_domain(self, domain: Any) -> SanitizationVerdict:
        """域名净化"""
        if not isinstance(domain, str) or not domain:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="域名不能为空", risk_level="high")

        domain = domain.strip().lower()

        # Unicode 清洗
        domain, unicode_attacks = self._clean_unicode_confusion(domain)

        # 阻止 localhost
        if domain in ('localhost',):
            return SanitizationVerdict(passed=False, cleaned_value="", reason="不允许 localhost", risk_level="critical")

        # 域名格式: alphanum + . + hyphen
        if re.match(r'^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$', domain):
            return SanitizationVerdict(passed=True, cleaned_value=domain, risk_level="none")

        return SanitizationVerdict(
            passed=False, cleaned_value="",
            reason=f"无效域名格式: {domain}",
            risk_level="high"
        )

    def sanitize_search_query(self, query: Any) -> SanitizationVerdict:
        """搜索查询净化 — 允许字母数字 + 常用标点"""
        if not isinstance(query, str) or not query:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="查询不能为空", risk_level="high")

        query = query.strip()
        if len(query) > self.MAX_QUERY_LEN:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="查询过长", risk_level="high")

        # Unicode 清洗
        query, unicode_attacks = self._clean_unicode_confusion(query)

        # 注入扫描
        injection_hits = self._scan_injection_patterns(query)
        if injection_hits:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"查询包含注入模式: {injection_hits}",
                risk_level="critical"
            )

        # 允许: 字母数字 + 空格 + _-.:/,+()[]{}@*#^~?!$%&'"
        if not re.match(r"^[a-zA-Z0-9._\-/:,+()\[\]{}@*#^~?!$%&'\" =]+$", query):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"查询包含非法字符: {query[:100]}",
                risk_level="high"
            )

        return SanitizationVerdict(passed=True, cleaned_value=query, risk_level="none")

    def sanitize_file_path(self, path: Any) -> SanitizationVerdict:
        """文件路径净化 — 防止路径遍历"""
        if not isinstance(path, str) or not path:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="路径不能为空", risk_level="high")

        path = path.strip()
        if len(path) > self.MAX_PATH_LEN:
            return SanitizationVerdict(passed=False, cleaned_value="", reason="路径过长", risk_level="high")

        # 路径遍历检测
        traversal_patterns = [
            (r'\.\./+', "Unix 目录遍历"),
            (r'\.\.\\+', "Windows 目录遍历"),
            (r'~/', "用户目录访问"),
            (r'\x00', "NULL 字节注入"),
            (r'%00', "URL NULL 字节"),
        ]
        for pattern, desc in traversal_patterns:
            if re.search(pattern, path):
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"路径遍历 ({desc}): {path[:100]}",
                    risk_level="critical"
                )

        # 绝对路径检查
        import os
        if os.path.isabs(path):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason="不允许绝对路径",
                risk_level="high"
            )

        # 危险系统路径
        dangerous_starts = ['/etc/', '/root/', '/var/', '/boot/', '/proc/', '/sys/',
                            'C:\\Windows\\', 'C:\\WINDOWS\\', 'C:\\Program Files\\',
                            '/System/', '/Library/']
        for ds in dangerous_starts:
            if path.lower().startswith(ds.lower()):
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"禁止访问系统路径: {path}",
                    risk_level="critical"
                )

        # 允许安全字符
        if not re.match(r'^[a-zA-Z0-9._\-/\\: @]+$', path):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"路径包含非法字符: {path[:100]}",
                risk_level="high"
            )

        return SanitizationVerdict(passed=True, cleaned_value=path, risk_level="none")

    def sanitize_recursive(self, data: Any) -> Any:
        """递归清洗嵌套结构 (dict/list/str)"""
        if isinstance(data, str):
            verdict = self.sanitize_command_arg(data, allow_spaces=True, allow_special=True)
            return verdict.cleaned_value if verdict.passed else ""
        elif isinstance(data, dict):
            return {self.sanitize_recursive(k): self.sanitize_recursive(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_recursive(item) for item in data]
        elif isinstance(data, (int, float, bool, type(None))):
            return data
        else:
            return str(data)

    # ===================================================================
    # 内部方法
    # ===================================================================

    def _clean_unicode_confusion(self, text: str) -> Tuple[str, List[str]]:
        """检测并清洗 Unicode 混淆攻击

        Returns:
            (cleaned_text, list_of_detected_attacks)
        """
        attacks = []
        cleaned_chars = []

        for ch in text:
            cp = ord(ch)

            if cp in DANGEROUS_UNICODE:
                attacks.append(f"危险控制字符 U+{cp:04X} ({unicodedata.name(ch, 'UNKNOWN')})")
                continue  # 移除危险字符

            if cp in HOMOGLYPH_MAP:
                attacks.append(f"同形异义字符 U+{cp:04X} ({unicodedata.name(ch, 'UNKNOWN')}) → U+{HOMOGLYPH_MAP[cp]:04X}")
                cleaned_chars.append(chr(HOMOGLYPH_MAP[cp]))
                continue

            # 全角转半角 (FF01-FF5E)
            if 0xFF01 <= cp <= 0xFF5E:
                attacks.append(f"全角字符 U+{cp:04X} 转半角")
                cleaned_chars.append(chr(cp - 0xFEE0))
                continue

            # Unicode 规范化 (NFKC)
            normalized = unicodedata.normalize('NFKC', ch)
            if normalized != ch:
                attacks.append(f"NFKC 规范化: {ch} → {normalized}")
                cleaned_chars.append(normalized)
                continue

            cleaned_chars.append(ch)

        return ''.join(cleaned_chars), attacks

    @staticmethod
    def _detect_encoding_nesting(text: str) -> List[str]:
        """检测多层 URL 编码攻击

        攻击示例:
            %252f → 一次解码得 %2f → 二次解码得 /  (路径遍历)
            %25%32%66 = %2f → /
        """
        attacks = []

        # 检测 URL 编码的 URL 编码 (%25 = % 本身)
        # 例如 %252f, %253c, %253e
        nested_encodings = re.findall(r'%25[0-9a-fA-F]{2}', text)
        if nested_encodings:
            attacks.append(f"双层 URL 编码: {nested_encodings}")

        # 尝试两层解码
        try:
            once = unquote(text)
            if once != text:
                twice = unquote(once)
                if twice != once:
                    # 检查解码后是否泄露危险字符
                    dangerous_after_decode = []
                    for ch in twice:
                        if ch in ('/', '\\', ';', '|', '&', '>', '<', '\x00'):
                            dangerous_after_decode.append(f"0x{ord(ch):02X}")
                    if dangerous_after_decode:
                        attacks.append(f"解码后泄露危险字符: {dangerous_after_decode}")
        except Exception:
            attacks.append("URL 解码异常")

        return attacks

    def _detect_shell_ast_injection(self, text: str) -> List[str]:
        """Shell AST 级注入检测

        用 shlex 尝试解析 token, 检查:
            1. 是否有 Shell 控制操作符
            2. 是否有危险命令名
            3. 是否有危险内置命令
            4. 是否有命令替换 $() 或 backtick
            5. 是否有管道/重定向
        """
        blocked = []

        # 尝试 shlex 分词
        try:
            tokens = list(shlex.shlex(text, posix=True))
        except ValueError:
            # shlex 解析失败通常意味着有未闭合引号等注入尝试
            return ["shell token 解析失败 (可能存在注入)"]

        for token in tokens:
            token_lower = token.lower() if isinstance(token, str) else ""

            # 控制操作符检查
            if token in SHELL_CONTROL_OPS:
                blocked.append(f"Shell 控制操作符: '{token}'")
                continue

            # 命令替换语法
            if token.startswith('$(') or token.startswith('`') or '`' in token:
                blocked.append(f"命令替换语法: '{token}'")
                continue

            # 变量展开
            if token.startswith('${'):
                blocked.append(f"变量展开语法: '{token}'")
                continue

            # 危险命令
            if token_lower in DANGEROUS_COMMANDS:
                blocked.append(f"危险命令: '{token}'")
                continue

            # 危险内置
            if token_lower in DANGEROUS_BUILTINS:
                blocked.append(f"危险内置: '{token}'")
                continue

            # 关键字 (作为独立 token)
            if token_lower in SHELL_KEYWORDS:
                blocked.append(f"Shell 关键字: '{token}'")
                continue

            # 通配符展开攻击 (如 $(echo rm) 这种)
            if token.startswith('$') and not token.startswith('$('):
                blocked.append(f"变量引用: '{token}'")
                continue

        # 检查裸管道符号和裸分号 (shlex 可能不把它们当 token)
        if '|' in text and not any('|' in t for t in tokens if isinstance(t, str)):
            blocked.append("裸管道符号 '|'")
        if ';' in text and not any(';' in t for t in tokens if isinstance(t, str)):
            blocked.append("裸分号 ';'")

        return blocked

    @staticmethod
    def _scan_injection_patterns(text: str) -> List[str]:
        """增强注入模式扫描 — 覆盖更多攻击向量"""
        lowered = text.lower()
        hits = []

        patterns: List[Tuple[str, str, str]] = [
            # Shell 执行注入
            (r'(?:;|\||&|\n)\s*(?:sh|bash|zsh|ksh|tcsh|dash|fish)($|\s)', "shell 执行", "critical"),
            (r'(?:;|\||&|\n)\s*(?:perl|python|ruby|lua|php|node)($|\s|\d)', "解释器执行", "critical"),
            (r'(?:;|\||&)\s*(?:wget|curl|fetch)\s+\S+', "远程下载执行", "critical"),
            (r'(?:;|\||&)\s*(?:nc|ncat|socat)\s', "反向 Shell", "critical"),

            # 命令替换
            (r'`[^`]{1,200}`', "backtick 命令替换", "critical"),
            (r'\$\([^)]{1,200}\)', "dollar 命令替换", "critical"),
            (r'\$\{[^}]{1,200}\}', "变量展开替换", "critical"),

            # 文件操作
            (r'(?:;|\||&)\s*(?:rm\s+-|dd\s+if=)', "文件破坏", "critical"),
            (r'>/dev/[a-z]+\s', "设备写入", "critical"),
            (r'>/etc/(?:passwd|shadow|hosts|sudoers)', "系统文件覆写", "critical"),

            # 路径遍历
            (r'\.\.(?:/|\\)\.\.(?:/|\\)', "多层目录遍历", "high"),
            (r'(?:/|\\|\.)etc(?:/|\\)passwd', "passwd 文件读取", "critical"),
            (r'(?:/|\\)proc(?:/|\\)self', "proc 文件系统访问", "high"),

            # SSRF 进阶
            (r'(?:http|ftp|gopher|dict|tftp|file|netdoc)://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)', "SSRF 内网", "critical"),
            (r'(?:http|ftp)://(?:localhost|0\.0\.0\.0|\[::1\]|\[::\]|metadata\.google\.internal)', "SSRF 特殊地址", "critical"),
            (r'(?:http|ftp)://169\.254\.169\.254', "AWS metadata SSRF", "critical"),
            (r'file:///(?:etc|root|var|proc|sys|boot)', "file:// SSRF", "critical"),

            # SQL 注入尝试
            (r"(\s|')(?:union\s+select|select\s+.*\s+from\s|insert\s+into\s|drop\s+table|alter\s+table)", "SQL 注入", "high"),
            (r"'|\s*--\s*", "SQL 注释注入", "high"),

            # LDAP 注入
            (r'[*(][|&!]=.*[)]', "LDAP 注入", "high"),

            # XPath 注入
            (r"(\||&)\s*(?://|count\(|string\(|name\()", "XPath 注入", "high"),

            # XSS
            (r'<script[^>]*>', "XSS<script>", "high"),
            (r'javascript\s*:', "javascript: XSS", "high"),
            (r'onerror\s*=', "onerror XSS", "high"),
            (r'onload\s*=', "onload XSS", "high"),

            # SSTI
            (r'\{\{.*\}\}', "SSTI {{}}", "high"),
            (r'\$\{.*\}', "SSTI ${}", "high"),
            (r'<%=.*%>', "SSTI EJS/ERB", "high"),
            (r'#{.*}', "SSTI Pug/Jade", "high"),

            # CRLF 注入
            (r'%0[dD]%0[aA]', "CRLF 注入 (URL)", "high"),
            (r'%0[dD]', "CR 注入 (URL)", "high"),
            (r'%0[aA]', "LF 注入 (URL)", "high"),

            # NULL byte
            (r'(?:%00|\\x00|\\0)', "NULL byte 注入", "critical"),

            # 编码混淆
            (r'\\u[0-9a-fA-F]{4}', "Unicode escape 混淆", "low"),
            (r'\\x[0-9a-fA-F]{2}', "Hex escape 混淆", "medium"),
            (r'\\[0-7]{3}', "Octal escape 混淆", "medium"),
        ]

        for pattern, desc, level in patterns:
            if re.search(pattern, lowered):
                hits.append(f"[{level}] {desc}")

        return hits

    def _check_ssrf_url(self, url: str, unicode_attacks: List[str]) -> SanitizationVerdict:
        """SSRF URL 安全检查"""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
        except Exception:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"URL 解析失败: {url[:100]}",
                risk_level="high"
            )

        # 阻止危险 scheme
        dangerous_schemes = {'file', 'gopher', 'dict', 'tftp', 'netdoc', 'jar', 'php', 'ftp'}
        if parsed.scheme in dangerous_schemes:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"禁止危险 URL scheme: {parsed.scheme}",
                risk_level="critical"
            )

        # 阻止仅限 HTTP/HTTPS
        if parsed.scheme not in ('http', 'https'):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"仅允许 HTTP/HTTPS scheme, 收到: {parsed.scheme}",
                risk_level="high"
            )

        hostname = (parsed.hostname or '').lower()

        # 阻止内网地址
        import ipaddress
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"SSRF 阻止: 内网/回环地址 {hostname}",
                    risk_level="critical"
                )
            if addr.is_multicast or addr.is_reserved:
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason=f"SSRF 阻止: 保留地址 {hostname}",
                    risk_level="critical"
                )
            # 检查 0.0.0.0
            if addr == ipaddress.IPv4Address('0.0.0.0'):
                return SanitizationVerdict(
                    passed=False, cleaned_value="",
                    reason="SSRF 阻止: 0.0.0.0",
                    risk_level="critical"
                )
        except ValueError:
            pass

        # 阻止 localhost 变体
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]'):
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"SSRF 阻止: {hostname}",
                risk_level="critical"
            )

        # 阻止云 metadata 端点
        cloud_metadata_hosts = {
            '169.254.169.254',  # AWS / GCP / Azure
            'metadata.google.internal',
            'metadata.tencentyun.com',
            '100.100.100.200',  # Alibaba Cloud
        }
        if hostname in cloud_metadata_hosts:
            return SanitizationVerdict(
                passed=False, cleaned_value="",
                reason=f"SSRF 阻止: 云 metadata {hostname}",
                risk_level="critical"
            )

        return SanitizationVerdict(
            passed=True, cleaned_value=url,
            unicode_attacks=unicode_attacks,
            risk_level="none"
        )


# ============================================================================
# 三、参数化命令执行器 (零 shell=True)
# ============================================================================

@dataclass
class SafeCommand:
    """安全命令描述 — 参数数组模式"""
    program: str
    args: List[str] = field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None
    timeout: int = 300
    stdin_data: Optional[str] = None
    capture_output: bool = True

    def to_args_list(self) -> List[str]:
        """转为 subprocess 参数数组"""
        return [self.program] + self.args


def execute_safe_command(cmd: SafeCommand) -> Tuple[int, str, str]:
    """安全执行命令 — 永远不调用 shell

    Args:
        cmd: 安全命令描述 (参数数组模式)

    Returns:
        (return_code, stdout, stderr)

    Raises:
        OSError: 命令不存在或无法执行
        subprocess.TimeoutExpired: 超时
    """
    import subprocess
    import os as _os

    # 安全断言: 拒绝任何包含 shell 元字符的 program 名
    if any(c in cmd.program for c in (';', '|', '&', '$', '`', '>', '<', '\n', '\r')):
        raise ValueError(f"Illegal program name: {cmd.program}")

    # 检查 program 是否存在
    if '/' in cmd.program or '\\' in cmd.program:
        # 绝对/相对路径: 检查文件存在
        if not _os.path.isfile(cmd.program):
            raise FileNotFoundError(f"Program not found: {cmd.program}")
    else:
        # PATH 查找
        import shutil as _shutil
        resolved = _shutil.which(cmd.program)
        if not resolved:
            raise FileNotFoundError(f"Program not in PATH: {cmd.program}")

    try:
        proc = subprocess.run(
            cmd.to_args_list(),
            capture_output=cmd.capture_output,
            text=True,
            timeout=cmd.timeout,
            cwd=cmd.cwd,
            env=cmd.env,
            input=cmd.stdin_data,
            shell=False,  # CRITICAL: never shell=True
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        raise
    except Exception as e:
        return -1, "", str(e)


# ============================================================================
# 全局单例 & 便捷函数
# ============================================================================

_global_sanitizer: Optional[ExtremeSanitizer] = None


def get_extreme_sanitizer() -> ExtremeSanitizer:
    global _global_sanitizer
    if _global_sanitizer is None:
        _global_sanitizer = ExtremeSanitizer()
    return _global_sanitizer


def extreme_sanitize(arg: Any, context: str = "arg") -> str:
    """极致净化入口 — 失败抛异常"""
    s = get_extreme_sanitizer()

    if context == "arg":
        verdict = s.sanitize_command_arg(arg)
    elif context == "query":
        verdict = s.sanitize_search_query(arg)
    elif context == "target":
        verdict = s.sanitize_target(arg)
    elif context == "path":
        verdict = s.sanitize_file_path(arg)
    elif context == "url":
        verdict = s.sanitize_http_url(arg)
    elif context == "domain":
        verdict = s.sanitize_domain(arg)
    elif context == "cve":
        verdict = s.sanitize_cve_id(arg)
    elif context == "ports":
        verdict = s.sanitize_port_list(arg)
    else:
        verdict = s.sanitize_command_arg(arg, allow_spaces=True, allow_special=True)

    if not verdict.passed:
        raise ValueError(f"[{verdict.risk_level}] {verdict.reason}")

    return verdict.cleaned_value
